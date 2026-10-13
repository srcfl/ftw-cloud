# FTW Cloud

FTW Cloud keeps a signed, readable copy of each home that turns it on, and
serves it to that home's phones. It reads and never controls. The box opens
the connection, picks and signs every message, and can revoke at any time.

This is `ftwcloudd`, the service. The decision is
[ADR 0008](https://github.com/srcfl/ftw/blob/master/docs/adr/0008-ftw-cloud.md)
and the wire format is the normative
[FTW Cloud protocol](https://github.com/srcfl/ftw/blob/master/docs/protocol-cloud.md),
both in `srcfl/ftw`. Both are proposed; nothing here is deployed.

## What works today (C2)

- A box with FTW Cloud on keeps one WebSocket at `/v1/box`. The service
  checks that the box signed `hello` over this TLS session's exporter value,
  answers with a `hello_ok` signed by the service key, and then accepts only
  messages signed by that box's key.
- Each home's newest message of each class lives in memory, as the exact bytes
  the box sent. Readings are dropped an hour after the box goes quiet and are
  never written to disk.
- The registry (SQLite) holds the home id, the box key and the signed roster.
  A box that turns FTW Cloud off gets its home deleted and a signed receipt.
- `/source` serves the source of the running build, as AGPL-3.0 asks.

Not built yet, with a marked place in the code:

| Step | What | Where |
|---|---|---|
| C3 | The app's Noise session, `/v1/app` | `internal/server`, `store.For` with a `Device` principal |
| C4 | Alerts over APNs, `box.unreachable` | not started |
| C5 | Widget token reads, `/v1/now`, tiles | `internal/server` |
| C7–C8 | Statistics | not started |

## How it holds a home

```
box ──wss, TLS 1.3, signed frames──▶ /v1/box ──▶ store (memory) ◀── store.For(principal)
                                         └────▶ registry (SQLite: key, roster, tombstones)
```

- **The home id is a hash of the box's key.** It comes from the key that
  signed `hello`, never from a field anyone sends. A second box cannot claim
  a home that is not its own.
- **One way in.** `store.For(principal)` is the only access to a home: a
  `Box` principal may write its own home, and a `Device` principal (C3) may
  read the classes its role and the owner's grant both allow. There is no
  listing and no principal for staff; `TestNoRouteReadsAHome` checks every
  route.
- **The service sends five things.** `challenge`, `hello_ok`, `watch`,
  `resync` and `purged` are the whole downlink, and none asks the box to act.
  The box closes the uplink on anything else.
- **No TLS terminator in front.** Box and service bind the handshake to the
  TLS session, so `ftwcloudd` ends TLS itself. A TCP load balancer is fine.
- **Root on the host can read memory.** The privacy notice says so.

## Run it locally

```bash
go build -tags ftwclouddev -o ftwcloudd ./cmd/ftwcloudd
./ftwcloudd keygen -out service.key        # prints the public key
./ftwcloudd -listen 127.0.0.1:18443 -state ./state -service-key service.key \
  -tls-cert leaf.pem -tls-key leaf.key
```

Build Core from `srcfl/ftw` against it. A release build names no service, so
a local build sets the endpoint, the service's public key and a root for the
local certificate at link time:

```bash
go build -ldflags "\
 -X github.com/srcfl/ftw/go/internal/cloudlink.Endpoint=wss://127.0.0.1:18443/v1/box \
 -X github.com/srcfl/ftw/go/internal/cloudlink.ServiceKeys=<public key> \
 -X github.com/srcfl/ftw/go/internal/cloudlink.DevRootCA=$PWD/ca.pem" ./cmd/ftw
```

Then turn FTW Cloud on from the box itself:

```bash
curl -X POST http://127.0.0.1:8080/api/cloud/grant \
  -d '{"scopes":["ftw.live.read"],"policy":"local-test"}'
curl http://127.0.0.1:8080/api/cloud/preview
```

`-tags ftwclouddev` adds `/dev/held?home=<id>` on loopback, which shows what
the service holds so a test can compare it with the preview. Release builds
do not have it.

## Develop

```bash
go vet ./... && go test -race ./...
go test -run XXX -fuzz FuzzBoxMessage -fuzztime 30s ./internal/uplink
bash scripts/check-imports.sh
```

The wire types come from `github.com/srcfl/ftw/go/protocol`, Apache-2.0,
pinned to a commit in `go.mod`. A wire change is a pair of pull requests:
first in `srcfl/ftw` (`go/protocol` and its golden vectors), then here, moving
the pin. The service may import nothing else from `srcfl/ftw`; CI checks that
with `go list -deps`, so no control code can reach this build.

## License

`ftwcloudd` is licensed under the GNU Affero General Public License, version 3
only (AGPL-3.0-only). See [LICENSE](LICENSE) and
[CONTRIBUTING.md](CONTRIBUTING.md).
