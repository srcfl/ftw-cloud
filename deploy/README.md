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
| Instance role | `ftw-cloud-host`, with `AmazonSSMManagedInstanceCore` and nothing else |
| DNS | `cloud.ftw.energy` A `13.50.84.149` in the Cloudflare zone `ftw.energy`, grey cloud (record `22d28943eea9f6b8584214e1a8256ef1`) |
| Branch | `main`, checked out in `/opt/ftw-cloud` |
| Service public key | `BG6EvBxFzSHPVsQOES6PYaKFo5vHQmte9lJ6D5OBIT9JgcBrJAOxAucdqKXxS76pToQ7orI1Ivsno0OtxbMuliQ` |

Every resource carries the tag `Project=ftw-cloud`.

## Shape

- One instance, one container (`compose.yml`), no standby. A rebuilt host
  starts empty and boxes fill it again when they reconnect.
- `ftwcloudd` ends TLS 1.3 itself and gets its certificate from Let's Encrypt
  by TLS-ALPN-01 on 443, so port 80 stays shut. **No TLS-terminating proxy in
  front**: box and service bind the handshake to the TLS session, so Caddy,
  an ALB or an orange Cloudflare cloud would break every box's connection, on
  purpose. An NLB in TCP mode is fine. That is also why the DNS record is
  grey.
- The host builds the image from its checkout and tags it with the commit
  (`ftw-cloud:<12 hex>`); `/etc/ftw-cloud/compose.env` names it for
  `compose.yml`. Images built in CI and deployed by digest come later.
- The Docker volume `ftw-cloud_ftw-cloud-state` holds the SQLite registry
  (home ids, box keys, signed rosters, tombstones) and the ACME cache, on the
  encrypted root disk. No readings. No backup.

## The service key

`ftw-cloud-deploy` makes the key on the host the first time it runs
(`ftwcloudd keygen`) and keeps it at `/var/lib/ftw-cloud/service.key`, root
only, on the encrypted disk. At boot, `ftw-cloud-key.service` copies it to
`/run/ftw-cloud/service.key` (tmpfs) before Docker starts, and `compose.yml`
mounts that copy.

The key never leaves the host, and nothing backs it up. Its public half,
above, goes into Core's `cloudlink.ServiceKeys`. A new host makes a new key,
and Core then needs a release that carries it; Core carries up to two keys so
it can rotate across a release.

ADR 0008 keeps the key in Secrets Manager. That needs a role that may read a
secret, and this host's role may only talk to SSM. Move the key to Secrets
Manager before a Core release carries its public half.

## Host rules

- Swap off (`swapoff -a`, no swap in fstab) and core dumps off: the kernel
  pipes cores to `/bin/false`, systemd-coredump stores nothing, `compose.yml`
  sets `ulimits: core: 0`, and `ftwcloudd` marks itself not dumpable.
  Household readings exist only in this process's memory.
- Nothing comes in but 443. There is no SSH and no key pair; administration
  is through SSM. Session logs to a separate account are not set up yet.
- Outbound is open, because the host builds its own image (Docker Hub,
  gcr.io, the Go module proxy, GitHub). Narrow it to AWS endpoints, Let's
  Encrypt and, from C4, APNs once images come from CI.
- The running build's source is at `https://cloud.ftw.energy/source`.

## Bringing it up

`bootstrap.sh` is the whole host. It is idempotent: it turns off swap and
core dumps, installs Docker, Compose and buildx as the relay host does,
clones this repository to `/opt/ftw-cloud`, installs the two systemd units and
`/usr/local/sbin/ftw-cloud-deploy`, and runs that.

```bash
aws ssm send-command --region eu-north-1 --instance-ids i-0ecac4cbc6b5f8adc \
  --document-name AWS-RunShellScript \
  --parameters "$(jq -n --rawfile s deploy/bootstrap.sh '{commands: [$s]}')"
```

The DNS record must exist before the first TLS connection, since that is when
`ftwcloudd` asks Let's Encrypt for a certificate.

## Updating

```bash
aws ssm send-command --region eu-north-1 --instance-ids i-0ecac4cbc6b5f8adc \
  --document-name AWS-RunShellScript \
  --parameters 'commands=["/usr/local/sbin/ftw-cloud-deploy"]'
```

or, in a session (`aws ssm start-session --region eu-north-1 --target
i-0ecac4cbc6b5f8adc`), `sudo ftw-cloud-deploy`. It pulls the checked-out branch,
builds, and starts a new container. Every box reconnects within seconds.

It always makes a new container, even when only a mounted file changed. The
relay ran into this: a file mounted on its own, like the service key, keeps
the copy the container started with after the file changes on the host.

## Checking it

```bash
curl -s https://cloud.ftw.energy/healthz
```

`ok` means DNS, the certificate and the service all work.
`https://cloud.ftw.energy/source` returns the source archive.
`/v1/app` and `/v1/now` answer 501 until C3 and C5.

## Cost

eu-north-1 on-demand prices, October 2026:

| Item | Price | Per month |
|---|---|---|
| `t4g.small` | $0.0172 an hour | $12.56 |
| 20 GB gp3 | $0.0836 a GB-month | $1.67 |
| Public IPv4 (the Elastic IP) | $0.005 an hour | $3.65 |
| **Total** | | **about $18** |

Traffic from boxes comes in, which AWS does not charge for. Traffic out to
phones (C3) is free for the first 100 GB a month across the account. SSM costs
nothing. CPU credits run unlimited, which costs extra only if the CPU averages
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
aws iam detach-role-policy --role-name ftw-cloud-host \
  --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
aws iam delete-role --role-name ftw-cloud-host
```

The disk goes with the instance, and with it the registry and the service
key. Nothing else holds FTW Cloud data.

## Not here yet

APNs (C4), the app session (C3), widget tokens (C5) and statistics (C7–C8)
add secrets, egress and storage when they land. The erase test, canary homes
and the external heartbeat that pages Sourceful belong with the first homes.
