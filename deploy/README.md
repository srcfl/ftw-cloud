# Running FTW Cloud

Proposed, not deployed. ADR 0008 in `srcfl/ftw` chose one `t4g.small` in AWS
eu-north-1 (Stockholm), in an AWS account of its own, apart from the relay and
escrow. The account is not decided yet; nothing here creates anything.

## Shape

- One instance, one container (`compose.yml`), no standby. A rebuilt host
  starts empty and boxes fill it again when they reconnect.
- `ftwcloudd` ends TLS 1.3 itself and gets its certificate by ACME
  (TLS-ALPN-01 on 443). **No TLS-terminating proxy in front**: box and service
  bind the handshake to the TLS session, so Caddy, an ALB or an orange
  Cloudflare cloud would break every box's connection, on purpose. An NLB in
  TCP mode is fine. DNS for `cloud.ftw.energy` is a grey-cloud A record.
- The service key comes from Secrets Manager into `/run/ftw-cloud/service.key`
  (tmpfs) at boot. Its public half is compiled into Core
  (`cloudlink.ServiceKeys`); Core carries up to two, so it can rotate across a
  release.
- The volume holds the SQLite registry (home ids, box keys, signed rosters,
  tombstones) and the ACME cache. No readings. Use an encrypted EBS volume.

## Host rules

- Swap off (`swapoff -a`, no swap in fstab) and core dumps off (the compose
  file sets `ulimits: core: 0`; `ftwcloudd` also marks itself not dumpable).
  Household readings exist only in this process's memory.
- Security group: 443 from anywhere. Nothing else; administration is through
  SSM, with every session logged to a separate account.
- Outbound only to AWS endpoints, Let's Encrypt and, from C4, APNs.
- Deploy by image digest, built in CI from a reviewed commit. The running
  build's source is at `https://cloud.ftw.energy/source`.

## Not here yet

APNs (C4), the app session (C3), widget tokens (C5) and statistics (C7–C8)
add secrets, egress and storage when they land. The erase test, canary homes
and the external heartbeat that pages Sourceful belong with the first
deployment.
