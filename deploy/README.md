# Running FTW Cloud

FTW Cloud runs on one `t4g.small` in AWS eu-north-1 (Stockholm) and answers
at `https://cloud.ftw.energy`. No box sends to it yet: release builds of Core
name no service, and a home can turn FTW Cloud on only from a Core built with
the uplink (srcfl/ftw#1595), after its owner decides to.

## The host

| What | Value |
|---|---|
| Account | `976075258475`, shared with other Sourceful work. FTW Cloud moves to an account of its own when it has real users (ADR 0008). |
| Region | eu-north-1, zone eu-north-1a, default VPC |
| Instance | `i-0ecac4cbc6b5f8adc`, `t4g.small`, Amazon Linux 2023 arm64, IMDSv2 required, no key pair |
| Disk | `vol-0760cad0e8551e5e4`, 20 GB gp3, encrypted with `aws/ebs` |
| Elastic IP | `13.50.84.149` (`eipalloc-0085f3e68b6f36da4`) |
| Security group | `sg-098992ad382ecf94a` `ftw-cloud`: 443/tcp from anywhere, nothing else in |
| Instance role | `ftw-cloud-host`, with `AmazonSSMManagedInstanceCore` and the inline policy `ftw-cloud-service-key` ([`host-policy.json`](host-policy.json)): read one secret, nothing else |
| Secret | `ftw-cloud/service-key` in Secrets Manager, eu-north-1, encrypted with `aws/secretsmanager` |
| DNS | `cloud.ftw.energy` A `13.50.84.149` in the Cloudflare zone `ftw.energy`, grey cloud (record `22d28943eea9f6b8584214e1a8256ef1`) |
| Image | `ghcr.io/srcfl/ftw-cloud`, public, run by digest; `/etc/ftw-cloud/compose.env` names the running one |
| Service public key | `BG6EvBxFzSHPVsQOES6PYaKFo5vHQmte9lJ6D5OBIT9JgcBrJAOxAucdqKXxS76pToQ7orI1Ivsno0OtxbMuliQ` |

Every AWS resource carries the tag `Project=ftw-cloud`.

## Shape

- One instance, one container (`compose.yml`), no standby. A rebuilt host
  starts empty and boxes fill it again when they reconnect.
- `ftwcloudd` ends TLS 1.3 itself and gets its certificate from Let's Encrypt
  by TLS-ALPN-01 on 443, so port 80 stays shut. **No TLS-terminating proxy in
  front**: box and service bind the handshake to the TLS session, so Caddy,
  an ALB or an orange Cloudflare cloud would break every box's connection, on
  purpose. An NLB in TCP mode is fine. That is also why the DNS record is
  grey.
- CI builds the image. The `Image` workflow
  ([`image.yml`](../.github/workflows/image.yml)) builds `linux/arm64` from
  every commit on `main`, pushes it to `ghcr.io/srcfl/ftw-cloud` tagged with
  the commit, and records its provenance in GitHub's attestation store. The
  host builds nothing and needs no credential to pull.
- The host runs one image, named by its digest, never by a tag.
  `/opt/ftw-cloud` is checked out at the commit that image was built from and
  supplies `compose.yml`.
- The Docker volume `ftw-cloud_ftw-cloud-state` holds the SQLite registry
  (home ids, box keys, signed rosters, tombstones) and the ACME cache, on the
  encrypted root disk. No readings. No backup.

## The service key

The key lives in Secrets Manager as `ftw-cloud/service-key`, in PEM. At boot,
before Docker starts, `ftw-cloud-key.service` runs
`/usr/local/sbin/ftw-cloud-key`, which fetches it into
`/run/ftw-cloud/service.key` (tmpfs, owned by the container's user, mode
`0400`), and `compose.yml` mounts that file. The key is never on disk and
never in the image. `ftw-cloud-deploy` fetches it again, so a new version
takes effect on the next deploy or reboot.

The role may read this one secret and write nothing. A rebuilt host reads the
same key, so Core needs no new release for it. The public half, above, goes
into Core's `cloudlink.ServiceKeys`.

To rotate, ship a Core release that carries both public keys first (Core
carries up to two), then put the new key into the secret. Writing the secret
needs `secretsmanager:PutSecretValue`, which the role lacks: grant it for the
change and take it away after. The key moved from the host's disk to the
secret the same way.

## Host rules

- Swap off (`swapoff -a`, no swap in fstab) and core dumps off: the kernel
  pipes cores to `/bin/false`, systemd-coredump stores nothing, `compose.yml`
  sets `ulimits: core: 0`, and `ftwcloudd` marks itself not dumpable.
  Household readings exist only in this process's memory.
- Nothing comes in but 443. There is no SSH and no key pair; administration
  is through SSM. Session logs to a separate account are not set up yet.
- Outbound is open. The host now needs only GitHub and `ghcr.io` (the image
  and `compose.yml`), AWS endpoints (SSM, Secrets Manager), Let's Encrypt
  and, from C4, APNs. Narrowing it is still to do.
- The running build's source is at `https://cloud.ftw.energy/source`, with
  its commit in `X-Source-Revision` and the image digest in `X-Source-Image`.

## Bringing it up

The secret and the role's policy come first; they outlive the host:

```bash
aws secretsmanager create-secret --region eu-north-1 --name ftw-cloud/service-key \
  --description 'FTW Cloud service key, PEM' --tags Key=Project,Value=ftw-cloud
aws iam put-role-policy --role-name ftw-cloud-host --policy-name ftw-cloud-service-key \
  --policy-document file://deploy/host-policy.json
```

A secret without a value needs a key in it before the host can start (see
the service key, above).

`bootstrap.sh` is the rest of the host. It is idempotent: it turns off swap
and core dumps, installs Docker and Compose, clones this repository to
`/opt/ftw-cloud`, and installs `ftw-cloud-key`, the two systemd units and
`/usr/local/sbin/ftw-cloud-deploy`. On a host that already runs an image from
CI, it runs that image again with the new tooling. A new host waits for
`ftw-cloud-deploy` with a digest.

```bash
aws ssm send-command --region eu-north-1 --instance-ids i-0ecac4cbc6b5f8adc \
  --document-name AWS-RunShellScript \
  --parameters "$(jq -n --rawfile s deploy/bootstrap.sh '{commands: [$s]}')"
```

The DNS record must exist before the first TLS connection, since that is when
`ftwcloudd` asks Let's Encrypt for a certificate.

## Updating

Every commit on `main` gets an image. Take its digest from the summary of the
`Image` workflow's run, or from the `Digest:` line of:

```bash
docker buildx imagetools inspect ghcr.io/srcfl/ftw-cloud:<commit>
```

To check that the digest came from this repository's CI:

```bash
gh attestation verify oci://ghcr.io/srcfl/ftw-cloud@sha256:<digest> -R srcfl/ftw-cloud
```

Then run it:

```bash
aws ssm send-command --region eu-north-1 --instance-ids i-0ecac4cbc6b5f8adc \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["/usr/local/sbin/ftw-cloud-deploy sha256:<digest>"]'
```

or, in a session (`aws ssm start-session --region eu-north-1 --target
i-0ecac4cbc6b5f8adc`), `sudo ftw-cloud-deploy sha256:<digest>`. It pulls the
image, refuses one whose commit is not on `main`, checks out that commit in
`/opt/ftw-cloud`, fetches the key, starts a new container and deletes the old
image. The old container drains first; see [Deploys](#deploys). To go back,
run it with the earlier digest.

It always makes a new container, even when only a mounted file changed. The
relay ran into this: a file mounted on its own, like the service key, keeps
the copy the container started with after the file changes on the host.

## Deploys

A deploy stops the one process that carries every box's uplink and every
phone's session, so for each home commands wait until its box is back. The
service makes that short and spreads the return:

1. `docker compose down` sends SIGTERM and waits up to 15 s
   (`stop_grace_period`).
2. The old process stops accepting connections. It closes every box and
   phone with 4503 and a spread: the sockets it holds at 500 a second
   (`-restart-rate`), at least 5 s (`-restart-spread-min`, about how long the
   next container takes to start) and at most 60 s. 4,000 boxes get 8 s.
3. It closes the boxes side by side, so a stuck socket holds up none of
   the others, waits up to 2 s for the phones' closes to go out, and up to
   3 s for queued alerts. An alert still queued or waiting to go again is
   lost, and the log says how many. A box closed this way starts no
   `box.unreachable`.
4. It exits, in about 0.1 s in the load test.
5. The new container reads every signed roster back and checks the
   signatures on all cores before it listens: 0.35 s for 10,000 homes on
   two M5 cores (`BenchmarkRestore10k`), about 1.2 s on the host by the
   estimate under [Load](#load). Phones are admitted at once; readings come
   back with the boxes.
6. A box with srcfl/ftw#1645 redials at a random moment within the spread,
   and so does a phone once the apps honour 4503. Older clients redial on
   their own backoff, within 0.5 s, and those that come before the new
   container is up back off further.

The log shows `drained for a restart` with the counts and the spread, then
`rosters restored from the registry` with how long that took.

**Blue/green, when an NLB is worth it.** One host cannot run two containers
on 443 with the port mapping in `compose.yml`. With a TCP NLB in front (it
keeps the TLS binding), start the new instance on a second host with the same
keys and registry file, register it with the target group, deregister the old
one, then send the old one SIGTERM. Its sockets come back through the NLB to
the new instance within the spread, and no client meets a closed port. Copy
the registry first with `ftwcloudd move` (see [Shards](#shards)).

## Watching it

- **`/metrics`** answers on `127.0.0.1:9464` inside the container, in
  Prometheus text: sockets by kind, homes, homes with a connected box, tun
  messages and bytes each way, drops by reason, push queue depths, Apple's
  answers, handshake and forward latency histograms, the Go heap and
  goroutines. Nothing in it names a home or an address. Read it with
  `docker exec ftw-cloud-ftwcloudd-1 ftwcloudd metrics`.
- **One line a minute** goes to stdout in CloudWatch's embedded metric
  format: each counter's rise over the minute, each gauge, and p50, p95 and
  p99 of each latency in milliseconds. Once the container logs to CloudWatch
  Logs (the `awslogs` log driver, and `logs:CreateLogStream` and
  `logs:PutLogEvents` for the instance role, which the owner adds), each
  field is a metric in the `FTWCloud` namespace, by shard.
- What to watch: `forward_seconds_*_p99` (time inside the service),
  `drops_*` (any rise), `push_queued_alert`, `homes_connected`,
  `go_memory_bytes`.

## Load

`cmd/ftwload` starts a local `ftwcloudd`, connects N boxes and M phones per
box, and measures. Each box sends a signed `live` every second with the
readable copy on. Each phone looks at its home and sends a 64-byte `tun`
every second, which its box sends straight back. The service ran with
`GOMAXPROCS=2`, as on the host's two vCPUs, on an Apple M5 laptop, in a Linux
container unless marked macOS. Runs lasted under two minutes.

| Run | Service CPU (100 = one core) | Service RSS | Inside the service, p99 | Phone to box and back, p50 / p99 |
|---|---|---|---|---|
| 4,000 boxes, no phones | 34 % | 289 MiB | — | — |
| 3,000 homes, a phone each | 35 % | 518 MiB | — | 1.6 / 32 ms |
| 8,000 homes, a phone each (16,000 sockets) | 84 % | 1.43 GiB | envelope ≤ 2.5 ms, tun ≤ 0.25 ms | 6 / 160 ms |
| 2,000 homes, a phone each, macOS | 33 % | 377 MiB | envelope ≤ 1 ms, tun ≤ 0.1 ms | 0.8 / 27 ms |
| Storm: 4,000 boxes redial at once | peak 155 % | | | all back in 0.9 s |
| SIGTERM with 3,000 homes and phones | | | | 6,000 of 6,000 got 4503 with 12 s; exit in 0.11 s |

- **Per 1,000 boxes:** 8.4 % of a core and 69 MiB. The live heap is 22 MiB;
  goroutine stacks and the collector's headroom make up the rest. Below
  about 45 MiB the collector runs without pause, so that is the floor.
- **Per 1,000 phones on top**, each sending a command a second: about 3 % of
  a core and 100 to 110 MiB. On macOS a phone cost more CPU.
- **Where box CPU goes,** in a macOS profile: reading the socket, about two
  thirds; checking each message's signature, a quarter (17 µs each).
- **Handshakes:** about 4,400 box handshakes a second on two cores,
  rosters written to SQLite included.
- **The service is not where latency comes from** at these loads: inside it a
  message waits at most a few milliseconds at the 99th percentile. The tail
  end to end is the harness and the laptop, which ran other work.

**On a t4g.small.** These runs were not on the host. A Graviton2 core does
this work at roughly a third of an M5 core's speed, an estimate from public
single-core benchmarks, so take 3.5 times the CPU and the same memory, and
check against `/metrics` once real boxes connect:

| | Per 1,000 boxes at one message a second |
|---|---|
| CPU | about 30 % of a vCPU |
| Memory | about 70 MiB |
| Handshakes the next instance takes | about 1,250 a second; `-restart-rate` is 500 |

The first limit is CPU, not memory:

- **About 1,300 boxes** fit in the burst baseline (20 % of each of the two
  vCPUs). Past that the instance spends CPU credits, which unlimited mode
  bills.
- **About 4,500 boxes** keep both vCPUs under 70 %.
- **About 20,000 boxes**, or about 8,000 homes with a phone connected each,
  fit in `GOMEMLIMIT` (1,400 MiB).

A box that sends every 5 s, as an unwatched box does today, costs a fraction
of this.

**When to add a shard.** Add one when any of these holds over a busy day:

- the instance averages more than 60 % of its two vCPUs;
- more than 4,000 homes have a box connected (`homes_connected`);
- the runtime holds more than 1.2 GiB (`go_memory_bytes`);
- a forward p99 inside the service passes 50 ms.

Between about 1,300 and 4,000 boxes, a non-burstable instance with two vCPUs
is the cheaper first step; it needs no shard.

## Shards

With no `-shards` file one instance holds every home and nothing below
applies. Each shard is one instance with its own host
(`s2.cloud.ftw.energy`), volume and registry, and the same service key and
Noise key as the others, because boxes and phones carry those. Each holds the
same directory file apart from `self`:

```json
{
  "self": "s1",
  "shards": {"s1": "cloud.ftw.energy", "s2": "s2.cloud.ftw.energy"},
  "default": "s1",
  "buckets": {"s2": ["128-255"]},
  "homes": {}
}
```

Homes fall into 256 buckets by a hash of their id. `homes` moves single
homes and wins over `buckets`. An instance answers a home it does not hold
with that shard's host (protocol: "Shards and restarts"); clients follow once
and keep the host. A second shard holds homes only once their boxes list
`shard` in `hello.caps` (`boxes_following_shards`) and the apps follow 4421.

**Moving homes**, here buckets 128-255 from s1 to s2:

1. On s1, copy their rows while s1 still holds them:
   `ftwcloudd move -registry /state/registry.db -to /state/to-s2.db -shards <new file> -shard s2`.
2. Take `to-s2.db` to s2's volume and merge it into s2's registry, before
   s2 starts: `ftwcloudd move -registry to-s2.db -to /state/registry.db -shards <s2's file> -shard s2`.
3. Start s2 with its file, and point `s2.cloud.ftw.energy` at it.
4. Within ten minutes of step 3, deploy s1 with the new file. It drains,
   and from then on its boxes and phones of those homes hear 4421 and go to
   s2. (s2 starts the wait for `box.unreachable` for each moved home with
   alert registrations; a box that has not arrived in ten minutes would
   raise a false alarm. s1 starts none for the homes it no longer holds.)
5. On s1, run step 1 again with `-drop`, so what changed between step 1 and
   step 4 follows and s1 forgets the homes. Merge that file into s2 as in
   step 2, then deploy s2 again so it reads the merged suspensions.

A merge never makes a row older: a roster is taken only with a higher
`rosterSeq`, other rows only where they are missing, and a tombstone deletes
its home. It adds and never deletes, so a row s1 deleted between steps 1
and 4 stays on s2. A box's roster at its first connect to s2 prunes the
tokens and push registrations it no longer allows, and a withdrawn copy
prunes every token again; what is left is a token dropped by a suspension
in that window and a push token a phone unregistered in it. Keep steps 1
to 4 short. Extension tokens keep working, because their hashes move with
the rows and each token names its home; tokens from before this change
named none, and no app read them.

## Checking it

```bash
curl -s https://cloud.ftw.energy/healthz
curl -sI https://cloud.ftw.energy/source
```

`ok` means DNS, the certificate and the service all work. `/source` returns
the source archive, and its headers name the commit (`X-Source-Revision`) and
the image digest (`X-Source-Image`), which should match what CI built.
`/v1/app` answers 501 on a host without the Noise key, and `/v1/now` answers
401 to a request without a valid token.

## Cost

eu-north-1 on-demand prices, October 2026:

| Item | Price | Per month |
|---|---|---|
| `t4g.small` | $0.0172 an hour | $12.56 |
| 20 GB gp3 | $0.0836 a GB-month | $1.67 |
| Public IPv4 (the Elastic IP) | $0.005 an hour | $3.65 |
| Secrets Manager, one secret | $0.40 a month | $0.40 |
| **Total** | | **about $18** |

Traffic from boxes comes in, which AWS does not charge for. Traffic out to
phones (C3) is free for the first 100 GB a month across the account. SSM costs
nothing, and reading the secret at each boot and deploy costs next to
nothing. The public image on `ghcr.io` is free. CPU credits run unlimited, which costs extra only if the CPU averages
more than 20% over a day.

## Tearing it down

```bash
cf dns records delete 22d28943eea9f6b8584214e1a8256ef1 -z ftw.energy
aws ec2 terminate-instances --region eu-north-1 --instance-ids i-0ecac4cbc6b5f8adc
aws ec2 wait instance-terminated --region eu-north-1 --instance-ids i-0ecac4cbc6b5f8adc
aws ec2 release-address --region eu-north-1 --allocation-id eipalloc-0085f3e68b6f36da4
aws ec2 delete-security-group --region eu-north-1 --group-id sg-098992ad382ecf94a
aws iam remove-role-from-instance-profile --instance-profile-name ftw-cloud-host --role-name ftw-cloud-host
aws iam delete-instance-profile --instance-profile-name ftw-cloud-host
aws iam delete-role-policy --role-name ftw-cloud-host --policy-name ftw-cloud-service-key
aws iam detach-role-policy --role-name ftw-cloud-host \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
aws iam delete-role --role-name ftw-cloud-host
aws secretsmanager delete-secret --region eu-north-1 --secret-id ftw-cloud/service-key
```

The disk goes with the instance, and with it the registry. Secrets Manager
keeps the service key for 30 days after `delete-secret`, so a mistaken
teardown can still be undone, and then deletes it. Nothing else holds FTW
Cloud data; the images on `ghcr.io` hold only code.

## Not here yet

The APNs key ([apns.md](apns.md)) and the Noise key phones dial
([noise.md](noise.md)) come from Parameter Store. Widget tokens need no
secret: the registry holds their hashes. Statistics (C7–C8) add secrets,
egress and storage when they land. The erase test, canary homes
and the external heartbeat that pages Sourceful belong with the first homes.
