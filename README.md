# FTW Cloud

FTW Cloud keeps a signed, readable copy of each home that turns it on, and
serves it to that home's phones. On that path it reads and never controls:
the box opens the connection, picks and signs every message, and can revoke
at any time. A second path on the same server carries remote commands. Those
frames are end-to-end Noise between the app and the box; this service
forwards the bytes and cannot open them, and it does not originate a
command. [ADR 0008](https://github.com/srcfl/ftw/blob/master/docs/adr/0008-ftw-cloud.md)
said commands stay on the Frankfurt relay. That stance is being revised.
The ADR text lives in `srcfl/ftw` and is not changed here.

This is `ftwcloudd`, the service. The decision is
[ADR 0008](https://github.com/srcfl/ftw/blob/master/docs/adr/0008-ftw-cloud.md)
and the wire format is the normative
[FTW Cloud protocol](https://github.com/srcfl/ftw/blob/master/docs/protocol-cloud.md),
both in `srcfl/ftw`. Both are proposed. The service runs at
`cloud.ftw.energy` ([deploy/README.md](deploy/README.md)), but no box sends
to it yet.

## What works today

- A box with FTW Cloud on keeps one WebSocket at `/v1/box`. The service
  checks that the box signed `hello` over this TLS session's exporter value,
  answers with a `hello_ok` signed by the service key, and then accepts only
  messages signed by that box's key.
- Each home's newest message of each class lives in memory, as the exact bytes
  the box sent. Readings are dropped an hour after the box goes quiet and are
  never written to disk.
- The registry (SQLite) holds the home id, the box key, the signed roster,
  owners' suspensions, APNs registrations and the hashes of extension
  tokens. A box that turns FTW Cloud off gets its home deleted
  and a signed receipt.
- `/source` serves the source of the running build, as AGPL-3.0 asks, and
  names its commit and image digest.
- A phone reads its home at `/v1/app?home=<id>`: Noise IK to the service's
  Noise key, with the home id in the prologue. The service admits only a
  phone whose key the box listed in its signed roster, and no owner has
  suspended. Handshake message 2 carries the snapshot from memory; after it
  each new box envelope the phone may read follows on the same socket,
  unchanged. A roster change, a suspension, an expired roster or a purge
  closes the sessions it touches at once.
- While a phone looks, the service asks the box for one-second updates and
  asks again every 50 s; when nobody looks, it stops.
- **One-shot read (ADR 0009).** watchOS gives an app HTTPS and nothing
  lower, so a watch reads at `POST /v1/app/once?home=<id>`: the body is
  Noise IK message 1 with the prologue `ftw.cloud.once.v1:` and the home id,
  and it carries one of `read {have, hz}`, `token.get`, `push.register` or
  `push.unregister`. The service admits the watch exactly as `/v1/app`
  admits a phone: its key in the box's roster, a roster that has not run
  out, no suspension. The box lists a watch with role `watch` and the
  scopes it derives; the service checks no role. A refusal is
  403 with an empty body. The answer is message 2 with the snapshot, less
  the envelopes `have` says the watch holds, and the envelopes that did not
  fit after it, each after its length. The box's bytes go unchanged, so the
  watch grades their freshness itself. The service keeps no session and no
  Noise state after the answer. Limits: one read at a time per device and 30
  a minute, 16 at once per home, 64 at once in the process, message 1 at
  most 4 KiB, the answer within 10 s.
- Limits per home: 16 sessions, one per device, 256 envelopes queued per
  phone, and a small message rate from each phone.
- **Alerts (C4).** A box's signed `event` goes to its phones through APNs,
  wrapped unchanged: the phone checks the signature, writes its own words and
  picks the buttons from the verified kind. Every alert has the same aps,
  priority and push type and no collapse id. Ten minutes without the box's
  socket sends `box.unreachable`, unless the box said `bye` for an update,
  which holds it back for an hour. A phone registers its token over its app
  session with `push.register`. Tokens are bound to roster entries that may
  read `ftw.events.read`, get nothing while an owner has suspended the
  device, and go when the roster drops them or Apple says they are gone.
  Apple's key comes from Parameter Store
  ([deploy/apns.md](deploy/apns.md)).
- **Widget push.** A widget registers its push token with `push.register
  {kind: widgets}`, which needs `ftw.live.read`. A watch registers its
  alert and widget tokens with `app: watch`; its pushes go to the watch
  app's topic (`-apns-watch-topic`), and an alert to a watch is the same
  payload, byte for byte, as to its phone. When a box's prices reach
  further than before, as when tomorrow's arrive, or a car is plugged in,
  the service sends Apple's widgets push: no data, only "content changed".
  The widgets then read `/v1/now`. At most 4 an hour per home, since Apple
  budgets widget reloads. A device holds at most 4 tokens of each kind; a
  new one pushes out its oldest.
- **Widget token.** A device asks for its extension token over its app
  session with `token.get`. A widget reads `GET /v1/now` with it: the newest
  `live`, `prices` and `hb` as the box signed them, and nothing else. The
  service keeps the token's SHA-256, never the token. A device holds one
  token, valid for 7 days; a new one replaces the old. It stops reading when
  the roster drops the device, moves its epoch or runs out, an owner
  suspends the device, or the home is purged.
- **Remote commands.** The Frankfurt relay's protocol, on this server.
  A box dials out to `/r/<epoch>/<handle>/box`, an app to `…/app`, and the
  box's exchange socket to `…/exchange`. A watch posts one command at
  `/x/<epoch>/<handle>`. Binary frames pass through unchanged and stay in
  the room named by the handle. The handle rotates every hour, spread over
  five minutes, and `/x/` accepts the previous epoch during that window.
  `/deadman` holds the box's sealed "I am gone" row and posts it when the
  claim stays down past the deadline. The handle is the capability today's
  clients already present, so an app, a watch or a box switches by changing
  the origin and nothing else. A box may also send `X-FTW-Box-Key` and
  `X-FTW-Box-Sig`; a proof that does not verify is refused, and a join with
  neither header is still admitted, because current boxes send none. This
  path is not `/v1/box`. That socket's downlink is still only `challenge`,
  `hello_ok`, `watch`, `resync` and `purged`.

Not built yet:

| Step | What | Where |
|---|---|---|
| C6 | Tiles | `internal/server` |
| C7–C8 | Statistics | not started |
| — | Anonymous fleet ping (`POST /fleet`) | still only on `relay.ftw.energy`; Core's default URL is not this origin |

## How it holds a home

```
box ──wss, TLS 1.3, signed frames──▶ /v1/box ──▶ store (memory) ◀── store.For(principal) ◀── /v1/app ◀──Noise IK── phone
                                         │                                  ◀── /v1/app/once ◀──Noise IK in one POST── watch
                                         │                                  ◀── /v1/now ◀──token──── widget
                                         └────▶ registry (SQLite: key, roster, tombstones, suspensions, APNs, token hashes)

box ──wss, dials out──▶ /r/…/box ──┐
app ──wss──────────▶ /r/…/app ─────┼──▶ relay (blind; frames not stored) ──▶ the other peer
watch ──POST──────▶ /x/…  ─────────┘
```

- **The home id is a hash of the box's key.** It comes from the key that
  signed `hello`, never from a field anyone sends. A second box cannot claim
  a home that is not its own.
- **One way in.** `store.For(principal)` is the only access to a home: a
  `Box` principal may write its own home, a `Device` principal may
  read the classes its role and the owner's grant both allow, and a `Token`
  principal reads only `live`, `prices` and `hb` within that same scope. There is no
  listing and no principal for staff; `TestNoRouteReadsAHome` checks every
  route.
- **A phone or a watch can narrow and nothing else** on the readable path.
  A phone can say whether it is looking, and an owner can suspend a device
  in the roster. A watch can read, ask for its token and register for push.
  A command is Noise between the app and the box. It crosses this process
  on `/r/` and `/x/` and is not written into the home.
- **The service sends five things on `/v1/box`.** `challenge`, `hello_ok`,
  `watch`, `resync` and `purged` are the whole downlink, and none asks the
  box to act. The box closes the uplink on anything else. `ready` and `gone`
  are words of the command path, and they are not sent on `/v1/box`.
- **No TLS terminator in front.** Box and service bind the handshake to the
  TLS session, so `ftwcloudd` ends TLS itself. A TCP load balancer is fine.
- **Root on the host can read memory.** The privacy notice says so.

## Run it locally

```bash
go build -tags ftwclouddev -o ftwcloudd ./cmd/ftwcloudd
./ftwcloudd keygen -out service.key        # prints the public key, for Core
./ftwcloudd keygen -noise -out noise.key   # prints the Noise public key, for the app
./ftwcloudd -listen 127.0.0.1:18443 -state ./state -service-key service.key \
  -noise-key noise.key -tls-cert leaf.pem -tls-key leaf.key
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

Without `-noise-key` (or with the file missing) the service still serves
boxes, and `/v1/app` answers 501: phones read through the relay until a
Noise key is installed. A host that should serve phones needs the key as a
second secret beside the service key.

`-tags ftwclouddev` adds `/dev/held?home=<id>` on loopback, which shows what
the service holds so a test can compare it with the preview, and
`-dev-push-listen 127.0.0.1:18444`, where `POST /dev/push/register` with
`{home, deviceId, apnsToken (hex), environment}` registers a token for a
device in the home's roster, as the app session does; `POST /dev/push/raw`
with `{home, payload}` sends a payload as it is, so a test can put a forged
one through Apple. `-dev-apns-capture <dir>` writes alerts to files instead
of sending them. `-apns-dir` names a
directory holding `key.p8`, `key-id` and `team-id`; without it nothing is
sent. Release builds have neither dev route.

## Develop

```bash
go vet ./... && go test -race ./...
go test -run XXX -fuzz FuzzBoxMessage -fuzztime 30s ./internal/uplink
go test -run XXX -fuzz FuzzPhoneMessage -fuzztime 30s ./internal/appsession
go test -run TestTheSnapshotArrivesFast -v ./internal/appsession   # loopback p50/p95
go test -run XXX -bench BenchmarkSnapshot ./internal/appsession
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
