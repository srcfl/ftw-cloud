# The energy reports' gateway key and relay

A box sends one anonymous energy report a day, sealed with Oblivious HTTP
(RFC 9458) to this service's gateway key and posted to a relay that someone
other than Sourceful runs. The relay forwards it to `POST /v1/ohttp`. The
relay sees the box's address but not the report; this service sees the
report but not the address. Without the key, `/v1/ohttp` answers 501 and the
public totals still answer.

The private key lives like the Noise key ([noise.md](noise.md)): made on a
machine signed in to the account, put straight into Parameter Store, and
read into tmpfs at every boot. It is never in the repository, the image, the
volume or a log. A Core release pins the public half, so boxes never ask
this service for a key.

## 1. Make the key (once)

From a checkout of this repository:

```bash
go run ./cmd/ftwcloudd keygen -ohttp -out /tmp/ftw-cloud-ohttp.key
```

It writes the private key and prints the key configuration, base64url, 55
characters. Keep it: it is the pin for Core in step 5, and the relay
operator may ask for it.

## 2. Put it in Parameter Store (once)

In a terminal signed in to the FTW Cloud account (976075258475):

```bash
aws ssm put-parameter --region eu-north-1 --name /ftw-cloud/ohttp-key --type SecureString --value file:///tmp/ftw-cloud-ohttp.key
rm /tmp/ftw-cloud-ohttp.key
```

## 3. Give it to the host (once per host)

`deploy/ohttp.sh` installs `ftw-cloud-ohttp.service`, which reads the
parameter into `/run/ftw-cloud/ohttp/` before Docker starts. `compose.yml`
mounts that directory read-only. Run it through SSM, then redeploy:

```bash
aws ssm send-command --region eu-north-1 --instance-ids i-0ecac4cbc6b5f8adc \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["bash /opt/ftw-cloud/deploy/ohttp.sh","/usr/local/sbin/ftw-cloud-deploy"]'
```

The start line, `ftwcloudd listening … ohttp_keys=…`, shows the
configuration from step 1. From anywhere:

```bash
curl -s https://cloud.ftw.energy/.well-known/ohttp-gateway | base64
curl -s -o /dev/null -w '%{http_code}\n' -H 'Content-Type: message/ohttp-req' \
  --data-binary 'not a report' https://cloud.ftw.energy/v1/ohttp
```

The first prints the configuration with a two-byte length in front. The
second prints 400, because the bytes do not open under the key; without the
key it prints 501.

## 4. Ask a relay operator (once)

The relay must be run by someone other than Sourceful. Two that sell one:

- **Cloudflare OHTTP Relay** (formerly Privacy Gateway). Enterprise only, in
  closed beta: ask through https://www.cloudflare.com/lp/privacy-edge/.
  Sourceful already uses Cloudflare, so this is the shorter path.
- **Fastly OHTTP Relay**, through Fastly sales.

Send them:

- **Gateway URL:** `https://cloud.ftw.energy/v1/ohttp`
- **Key configuration:** `https://cloud.ftw.energy/.well-known/ohttp-gateway`
  (`application/ohttp-keys`), or the string from step 1. The suite is
  DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM.
- **Traffic:** `POST` with `message/ohttp-req`, always 375 bytes; answers
  are `message/ohttp-res`, always 48 bytes. One request per box per day,
  spread over the 12 hours after 00:00 UTC.

Ask them to confirm, in writing:

- they pass the gateway no client address or other client header
  (`Forwarded`, `X-Forwarded-For`, `CF-Connecting-IP`, `True-Client-IP`,
  `User-Agent`), only the body and its content type;
- what they log about the client and for how long. Cloudflare's published
  terms keep the address, the time and request metadata for about 124 days;
- that they keep no request body.

They hand back the **relay URL** the boxes post to. Cloudflare's form is
`https://privacy-relay.cloudflare.com/<name>`.

## 5. Pin both in Core

In srcfl/ftw, `go/internal/energyreport/energyreport.go`: `RelayURL` takes the
relay URL from step 4 and `GatewayKey` the string from step 1. Boxes on the
release that carries both start sending; older releases send nothing.

## Rotating

Make a new key with step 1 into a new file, and put both PEM blocks, old
then new, in the one parameter. ftwcloudd loads both and refuses two keys
under one id; then make the new one again. Ship a Core release that pins
the new configuration. Once boxes have moved to it, drop the old block.

## Access

The host role needs nothing new, as for the Noise key: see
[apns.md](apns.md), "Access".
