# FTW Cloud guide

`ftwcloudd` keeps a signed, readable copy of each home that turned FTW Cloud
on, and serves it to that home's phones. Read [README.md](README.md) first,
then the normative
[FTW Cloud protocol](https://github.com/srcfl/ftw/blob/master/docs/protocol-cloud.md)
and [ADR 0008](https://github.com/srcfl/ftw/blob/master/docs/adr/0008-ftw-cloud.md)
in `srcfl/ftw`. Fredrik owns FTW's direction; Sourceful develops and
maintains it.

## Invariants

- **FTW Cloud reads and never controls.** It sends a box only `challenge`,
  `hello_ok`, `watch`, `resync` and `purged` (`internal/uplink/downlink.go`).
  Commands go from the app to the box over Noise, never through here.
- **One way to a home:** `store.For(principal)`. No listing, no second lookup,
  no principal for staff. A new route needs a row in `server.Routes` and must
  pass `TestNoRouteReadsAHome`.
- **The home id comes from the key that signed hello** on this connection,
  never from a body field. Every later box message must verify with that key.
- **No readings on disk.** Memory holds readings; SQLite holds only the home
  id, the box key, the signed roster, owners' suspensions, tombstones, APNs
  registrations and the hashes of extension tokens. Nothing logs addresses.
- **A phone can only narrow.** On `/v1/app` it can say whether it is looking,
  and an owner can suspend a roster device. The service admits a phone by the
  key its Noise handshake proved, and only if the box's roster lists it.
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
- Keep the service small. The budget is about 3,000 lines of Go; tiles go
  first if it is overrun.
- Nothing is deployed from here without the owner. `deploy/` describes the
  running host; it does not run itself.
- Keep task breakdowns and agent notes out of the repository.

## Check

```bash
go vet ./... && go test -race ./...
go test -tags ftwclouddev ./...
bash scripts/check-imports.sh
```
