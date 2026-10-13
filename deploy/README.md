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
image. Every box reconnects within seconds. To go back, run it with the
earlier digest.

It always makes a new container, even when only a mounted file changed. The
relay ran into this: a file mounted on its own, like the service key, keeps
the copy the container started with after the file changes on the host.

## Checking it

```bash
curl -s https://cloud.ftw.energy/healthz
curl -sI https://cloud.ftw.energy/source
```

`ok` means DNS, the certificate and the service all work. `/source` returns
the source archive, and its headers name the commit (`X-Source-Revision`) and
the image digest (`X-Source-Image`), which should match what CI built.
`/v1/app` and `/v1/now` answer 501 until C3 and C5.

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

APNs (C4), the app session (C3), widget tokens (C5) and statistics (C7–C8)
add secrets, egress and storage when they land. The erase test, canary homes
and the external heartbeat that pages Sourceful belong with the first homes.
