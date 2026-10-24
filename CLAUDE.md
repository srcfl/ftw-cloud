# FTW Cloud guide

`ftwcloudd` is the one door between a home's phones and its box: it carries
each phone's own Noise session with the box, and keeps a signed, readable
copy of each home whose owner turned that on. Read [README.md](README.md) first,
then the normative
[FTW Cloud protocol](https://github.com/srcfl/ftw/blob/master/docs/protocol-cloud.md)
and [ADR 0008](https://github.com/srcfl/ftw/blob/master/docs/adr/0008-ftw-cloud.md)
in `srcfl/ftw`. Fredrik owns FTW's direction; Sourceful develops and
maintains it.

## Invariants

- **FTW Cloud forwards ciphertext it cannot read. It acts on a home only as
  an agent its owner approved, within limits the box enforces.** It sends a
  box only `challenge`, `hello_ok`, `watch`, `resync`, `purged`, `tun` and
  `x` (`internal/uplink/downlink.go`). Commands go from the app to the box
  inside the phone's own Noise session, which rides here as `tun` under the
  device id the service's own handshake proved, never one a phone names. A
  watch's commands go inside its exchange with the box, which rides as `x`
  the same way. An agent's requests ride the agent's own Noise session the
  same way, and the box admits it only while its signed roster lists the
  agent's key.
- **Agent keys live only in `ftwkeysd`** (`internal/keys`, `cmd/ftwkeysd`). It
  answers on a local unix socket, seals keys at rest under KMS, unseals a key
  only to open one session, and logs no key. `ftwcloudd` never holds an
  agent's static key or session keys. Keep it small: nothing else goes in.
- **One way to a home:** `store.For(principal)`. No listing, no second lookup,
  no principal for staff. A new route needs a row in `server.Routes` and must
  pass `TestNoRouteReadsAHome`. The one other way in is `store.Seed`, called
  once at start: it puts back the rosters the registry holds, each checked
  against its home's key, and reads nothing out.
- **The home id comes from the key that signed hello** on this connection,
  never from a body field. Every later box message but `tun` and `x` must
  verify with that key. Both are unsigned: a `tun`'s `d` is a phone's
  ciphertext, which the service routes by `dev` and `sid` and never reads,
  and an `x`'s a watch's, routed by `dev` and `id`.
- **Live readings stay in memory.** The versioned project statistics
  scope covers rounded closed-hour energy and configured capacities on
  disk for 48 hours. Only group cells pass `/v1/stats`; no staff route reads
  a home. Withdrawal and home purge delete its unpublished statistics.
  Memory holds live readings, and only while the roster's
  grant serves a copy; SQLite holds only the home id, the box key, the signed
  roster, owners' suspensions, tombstones, APNs registrations, the hashes of
  extension tokens when each away box's alert is due, browser notice sent markers,
  anonymous daily fleet and energy totals, and the service's own hourly counts. Browser endpoints and box-encrypted offline
  notices live only in the signed roster. Nothing logs
  addresses.
- **A phone can only narrow, or talk to its own box.** On `/v1/app` it can
  say whether it is looking, an owner can suspend a roster device, and a
  device the roster lists with `tun` can send its box session as `tun`. On
  `/v1/app/once` a watch can read, ask for its token, register for push and,
  if the roster lists it as a watch with `tun`, send its exchange with the
  box as `x`,
  and nothing else. The service admits a phone or a watch by the key its
  Noise handshake proved, and only if the box's roster lists it, or once for
  a pairing code the roster lists by its hash.
- **TLS ends in `ftwcloudd`.** The handshake is bound to the TLS session; a
  terminating proxy breaks it on purpose. A TCP load balancer is fine.
- **Forward the box's bytes unchanged.** The service cannot sign for a box,
  so it cannot make data look fresher; keep it that way.
- **Import only `go/protocol` from `srcfl/ftw`.** `scripts/check-imports.sh`
  fails on anything else.
- **A home lives on one shard** (`internal/shard`). An instance that does not
  hold a home names the host that does (4421, or 421 with `Ftw-Shard`)
  before it reads message 1 or touches the registry. Nothing about a home
  crosses between instances: no shared pub/sub, no shared storage. With no
  `-shards` file one instance holds every home. `/mcp` and `/oauth` stay on
  `cloud.ftw.energy` and forward to the home's shard once there is a second
  one, because other parties' clients follow no redirect.
- **Counts name nobody.** `/metrics` listens on loopback only, and it and
  the minute's log line sum over all homes: no home id, device or address.
  The registry keeps the same sums an hour at a time for 90 days, and
  `/v1/ops` serves them, with the closed fleet and energy day totals, only to
  the stats Worker's key. A label is a word fixed in the code
  (`TestCountsNameNobody`); never add one that could hold a home.
- **A deploy drains.** On SIGTERM every socket, handshakes included, hears
  4503 with a spread before the process exits, and no drained box starts
  `box.unreachable`. A part that holds sockets is a `drainer` in
  `cmd/ftwcloudd`. Every close the service sends waits for the client's
  answer (`internal/wsclose`), so the client reads the code, not a reset.

## Work

- Check open PRs on the files you touch; an open PR has right of way.
- A wire change is a pair: `srcfl/ftw` (`go/protocol` and its golden vectors)
  first, then this repository, moving the pin in `go.mod`. Say so in both PRs.
- Keep the service small. The old budget was about 3,000 lines of Go in all,
  and the service is over it. The one-door plan gives each part a budget of
  its own, and the numbers are Fredrik's call. Until he sets them, a PR that
  grows a part says by how much. Lines of Go without tests, at
  srcfl/ftw-cloud#17 (#15 in brackets):

  | Part | Lines |
  |---|---|
  | `internal/appsession` (app session, one-shot read) | 1,116 (1,020) |
  | `internal/push` | 1,029 (542) |
  | `internal/uplink` | 938 (719) |
  | `internal/store` | 854 (807) |
  | `internal/registry` | 809 (694) |
  | `cmd/ftwcloudd` | 701 (553) |
  | `internal/metrics` | 448 (new) |
  | `internal/apns` | 299 (299) |
  | `internal/token` | 214 (170) |
  | `internal/server` | 199 (205) |
  | `internal/shard` | 188 (new) |
  | `internal/wsclose` | 109 (new) |
  | All | 6,904 (5,009) |

  `cmd/ftwload`, the load harness, is a tool and not the service (1,938).
- Nothing is deployed from here without the owner. `deploy/` describes the
  running host; it does not run itself.
- Keep task breakdowns and agent notes out of the repository.

## Check

```bash
go vet ./... && go test -race ./...
go test -tags ftwclouddev ./...
bash scripts/check-imports.sh
```
