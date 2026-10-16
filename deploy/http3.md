# QUIC on UDP 443

`ftwcloudd` serves QUIC on UDP 443 beside TCP 443, with the same
certificate:

- HTTP/3 (`h3`) for the routes that are plain HTTPS: `/v1/app/once`,
  `/v1/now`, `/healthz` and `/source`. TCP responses carry
  `Alt-Svc: h3=":443"; ma=86400`, except a WebSocket upgrade's.
- The uplink (`ftw-cloud-box/1`) and the app session (`ftw-cloud-app/1`),
  with the WebSockets' handlers and messages (srcfl/ftw
  `docs/protocol-cloud.md`, "QUIC"). Boxes and phones race QUIC against the
  WebSocket and fall back to it on their own, so shutting UDP never cuts
  anyone off; it only makes them slower.

What it buys, measured by `scripts/netem-once.sh` (a watch's one-shot read,
40 ms round trip): a read on a new connection takes two round trips instead
of three. The pull request that added it has the table.

## Order

Open the port before the image that listens on it runs, and shut it after
the image stops saying so. A client that heard `Alt-Svc` races QUIC against
TCP for up to a day; with UDP shut it loses the race every time and gains
nothing.

### 1. Open UDP 443 in the security group (once)

In a terminal signed in to the FTW Cloud account (976075258475):

```bash
aws ec2 authorize-security-group-ingress --region eu-north-1 --group-id sg-098992ad382ecf94a \
  --ip-permissions 'IpProtocol=udp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0,Description=HTTP/3}]' \
  --tag-specifications 'ResourceType=security-group-rule,Tags=[{Key=Project,Value=ftw-cloud}]'
```

If the TCP rule also has `::/0`, add `Ipv6Ranges=[{CidrIpv6=::/0,Description=HTTP/3}]`
to match it. Check that the group now lets in 443/tcp and 443/udp and
nothing else:

```bash
aws ec2 describe-security-group-rules --region eu-north-1 \
  --filters Name=group-id,Values=sg-098992ad382ecf94a \
  --query 'SecurityGroupRules[?!IsEgress].[IpProtocol,FromPort,ToPort,CidrIpv4,CidrIpv6]' --output table
```

### 2. Run bootstrap.sh again (once per host)

It now raises the socket buffer ceiling to 7.5 MB, which quic-go asks for
(`net.core.rmem_max` and `net.core.wmem_max`). Without it HTTP/3 still works
and quic-go logs once that its buffers are small. Run it as under "Bringing
it up" in [README.md](README.md).

### 3. Deploy

Deploy the image built from the commit that added HTTP/3, or any later one,
as under "Updating" in [README.md](README.md). Its `compose.yml` maps
`443:443/udp`. No flag is needed: HTTP/3 is on by default.

### 4. Check it

From any machine with Go and a checkout of this repository:

```bash
go run ./cmd/ftwcloudd health https://cloud.ftw.energy/healthz
```

It prints `HTTP/1.1 ok` and `HTTP/3.0 ok`, each with its time, and fails if
either fails. A failing HTTP/3 line from outside, with a healthy container,
means the security group or a network in between drops UDP. `curl --http3`
does the same where curl was built with HTTP/3 (macOS's own curl is not).

The container checks itself the same way every minute, against its own
port, and `docker compose ps` on the host shows `healthy` or `unhealthy`.
Nothing restarts on it; it is there to look at after a deploy.

## Turning it off

Without a release: on the host, add `FTW_CLOUD_H3=false`,
`FTW_CLOUD_QUIC_SESSIONS=false` or both to `/etc/ftw-cloud/compose.env` and
run `systemctl restart ftw-cloud.service`. `ftw-cloud-deploy` keeps those
lines. With both off the service stops listening on UDP and stops sending
`Alt-Svc`. Wait a day, the `ma` in `Alt-Svc`, before you shut UDP 443 in
the security group:

```bash
aws ec2 revoke-security-group-ingress --region eu-north-1 --group-id sg-098992ad382ecf94a \
  --ip-permissions 'IpProtocol=udp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0}]'
```

## Notes

- **TLS still ends in `ftwcloudd`.** Over HTTP/3, `r.TLS` is the service's
  own TLS 1.3 session with the client, and its exporter is the client's
  (`TestTheExporterOverHTTP3IsTheClientsOwn`). A UDP load balancer that
  forwards packets is fine; anything that ends QUIC is not.
- **Restarts.** When the process goes away, a TCP client hears from the
  kernel, but a QUIC client hears nothing. So `ftwcloudd` keeps a stateless
  reset key in `quic-reset.key` in the state directory, and the next
  process answers an old connection's next packet with a reset: the client
  knows at once, not after its idle timeout
  (`TestARestartResetsTheOldProcesssConnections`). Keep the file with the
  rest of `/state`; a new key only costs one idle timeout per client.
  On SIGTERM the door stops taking connections, and on the way out it ends
  each live session with 1001, going away
  (`TestCloseEndsEachSessionWithGoingAway`). The drain, which closes them
  first with 4503 and a spread, goes between the two.
- **Floods.** Past 200 new connections a second the door asks each to prove
  its address with a Retry, which costs a real client one round trip and a
  spoofed one everything. A handshake gets 5 s, and the door holds at most
  a set number of handshakes and connections at once. A UDP port that will
  not bind turns QUIC off and leaves TCP serving.
- **0-RTT.** The sessions take early data under the protocol's rules: a
  box's target may get its `challenge` before the handshake ends, and a
  phone's session waits for the handshake, so a replayed flight changes
  nothing. A ticket allows early data for a day. HTTP/3 requests in early
  data wait for the handshake. A restart draws new ticket keys.
- **A UDP load balancer** in front would have to keep each QUIC connection
  on one host by its connection id; with one host there is none.
- **No DNS record for HTTP/3.** An `HTTPS` record with `alpn=h3` would tell
  every client, the sockets' too, to try QUIC on the first connection.
  `Alt-Svc` reaches only clients of the plain routes.
- **Apple's URLSession** speaks HTTP/3 to this service. With
  `assumesHTTP3Capable` it tries HTTP/3 on the first request, and with UDP
  refused it fell back to TCP in the same time as without the flag (macOS,
  loopback; a network that drops UDP silently is not measured). A
  WebSocket in a session that already holds an HTTP/3 connection still
  opened over HTTP/1.1. On a port other than 443 URLSession did not move to
  HTTP/3 from `Alt-Svc` alone. So the watch's direct path should set
  `assumesHTTP3Capable` and keep one URLSession for its requests.
- **Logs.** Neither quic-go nor its HTTP/3 server logs anything here; both
  would name the peer's address.
