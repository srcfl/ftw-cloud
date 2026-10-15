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

- **FTW Cloud forwards ciphertext it cannot read, and never chooses an
  action.** It sends a box only `challenge`, `hello_ok`, `watch`, `resync`,
  `purged` and `tun` (`internal/uplink/downlink.go`). Commands go from the app
  to the box inside the phone's own Noise session, which rides here as `tun`
  under the device id the service's own handshake proved, never one a phone
  names.
- **One way to a home:** `store.For(principal)`. No listing, no second lookup,
  no principal for staff. A new route needs a row in `server.Routes` and must
  pass `TestNoRouteReadsAHome`. The one other way in is `store.Seed`, called
  once at start: it puts back the rosters the registry holds, each checked
  against its home's key, and reads nothing out.
- **The home id comes from the key that signed hello** on this connection,
  never from a body field. Every later box message but `tun` must verify
  with that key. `tun` is unsigned: its `d` is a phone's ciphertext, which
  the service routes by `dev` and `sid` and never reads.
- **No readings on disk.** Memory holds readings, and only while the roster's
  grant serves a copy; SQLite holds only the home id, the box key, the signed
  roster, owners' suspensions, tombstones, APNs registrations, the hashes of
  extension tokens and when each away box's alert is due. Nothing logs
  addresses.
- **A phone can only narrow, or talk to its own box.** On `/v1/app` it can
  say whether it is looking, an owner can suspend a roster device, and a
  device the roster lists with `tun` can send its box session as `tun`. On
  `/v1/app/once` a watch can read, ask for its token and register for push,
  and nothing else. The service admits a phone or a watch by the key its
  Noise handshake proved, and only if the box's roster lists it, or once for
  a pairing code the roster lists by its hash.
- **TLS ends in `ftwcloudd`.** The handshake is bound to the TLS session; a
  terminating proxy breaks it on purpose. A TCP load balancer is fine.
- **Forward the box's bytes unchanged.** The service cannot sign for a box,
  so it cannot make data look fresher; keep it that way.
- **Import only `go/protocol` from `srcfl/ftw`.** `scripts/check-imports.sh`
  fails on anything else.

## Work

- Check open PRs on the files you touch; an open PR has right of way.
- A wire change is a pair: `srcfl/ftw` (`go/protocol` and its golden vectors)
  first, then this repository, moving the pin in `go.mod`. Say so in both PRs.
- Keep the service small. The old budget was about 3,000 lines of Go in all,
  and the service is over it. The one-door plan gives each part a budget of
  its own, and the numbers are Fredrik's call. Until he sets them, a PR that
  grows a part says by how much. Lines of Go without tests, at
  srcfl/ftw-cloud#15:

  | Part | Lines |
  |---|---|
  | `internal/appsession` (app session, one-shot read) | 1,020 |
  | `internal/store` | 807 |
  | `internal/uplink` | 719 |
  | `internal/registry` | 694 |
  | `cmd/ftwcloudd` | 553 |
  | `internal/push` | 542 |
  | `internal/apns` | 299 |
  | `internal/server` | 205 |
  | `internal/token` | 170 |
  | All | 5,009 |
- Nothing is deployed from here without the owner. `deploy/` describes the
  running host; it does not run itself.
- Keep task breakdowns and agent notes out of the repository.

## Check

```bash
go vet ./... && go test -race ./...
go test -tags ftwclouddev ./...
bash scripts/check-imports.sh
```
