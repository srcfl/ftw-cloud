# FTW Cloud

FTW Cloud is the one door between a home's phones and its box. It carries
each phone's own Noise session with the box as ciphertext it cannot read or
forge, and keeps a signed, readable copy of each home whose owner turns that
on. It never chooses an action. The box opens the connection, picks and signs
every message but the phones' ciphertext, and can revoke at any time.

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
- What the service holds follows the newest roster's grant, never `hello`:
  the readable copy can turn on or off while the uplink stays up.
- The registry (SQLite) holds the home id, the box key, the signed roster,
  owners' suspensions, APNs registrations, the hashes of extension tokens
  and when an away box's alert is due. A box whose owner turns the readable
  copy off gets that copy deleted and a signed receipt (`purged {what:
  "copy"}`); a box whose link ends gets its home deleted and a receipt.
- **Room to grow.** Each home lives on one shard; an instance that does not
  hold a home names the host that does, and clients follow once
  (`internal/shard`, protocol "Shards and restarts"). With no `-shards` file
  one instance holds every home. A deploy closes every socket with 4503 and
  a spread, so boxes and phones come back over seconds rather than at once.
  `/metrics` on loopback and one log line a minute count what the service
  does without naming a home. `deploy/README.md` has the load numbers and
  when to add a shard.
- **A restart forgets no one.** At start the service reads every signed
  roster back from the registry and checks it with the home's key, so a
  home's phones are admitted before its box reconnects, and the wait for
  `box.unreachable` resumes where it was. A connection becomes the home's
  only after `hello_ok` has gone, so nothing reaches a box ahead of it.
- **The tunnel.** A box that lists `tun` in `hello.caps` takes its phones'
  sessions: a phone sends `tun {sid, d}` on its app session, where `d` is its
  `ftw.session.v1` session with the box byte for byte; the service adds the
  device id of the roster entry its own handshake matched and sends `tun
  {dev, sid, d}` down `/v1/box`, and the box's answers come back the same
  way. The box session's first message may ride in the app session's message
  1 (`now.tun`), so it is up one round trip after TLS. An empty `d` ends a
  session: the box hears when the phone's app session ends, and the phone
  when the box's uplink does, or when the box dials again. From the box,
  tun rides a queue of its own per phone session, apart from the readings;
  from a phone it is written straight to the box's socket. Each direction
  has limits per home: 240 messages then 60 a second, 4 MiB then 512 KiB a
  second. Past them the service drops and counts, and logs the count each
  minute; a box at twice them is closed, and so is a phone. A roster device
  needs `tun` or a readable copy to be admitted at all.
- **Pairing through the service.** While a QR code is on the box's screen,
  its roster lists the code's hash. A new phone proves the hash in `now.pair`
  and is admitted once, as a device that may only open a tunnel; the box
  checks the code itself inside the phone's handshake. When the roster lists
  the new phone its session takes that entry and stays open.
- The web app may open `/v1/app` from `https://app.ftw.energy`; any other
  `Origin` is refused.
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
- **QUIC.** UDP 443 carries what TCP 443 does, with the same certificate
  (`internal/quicdoor`, [deploy/http3.md](deploy/http3.md)). The plain
  HTTPS routes answer over HTTP/3, and TCP responses say so in `Alt-Svc`,
  except a WebSocket upgrade's. The uplink and the app session run over
  QUIC with the WebSockets' handlers (`internal/wire`): a control stream, a
  bulk stream for the tunnel's lane 1, and datagrams for `hb` and a `live`
  without its table. Clients race QUIC against the WebSocket, and the door
  offers only the protocols it serves. A box's target may come in early
  data; a phone's session waits for the handshake, so a replay changes
  nothing. A phone that moves from Wi-Fi to cellular keeps its connection
  and its box session.
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
- **Security notices.** A box's signed `notice` (someone gained access,
  asks for a change, is about to lose access, can now approve access, or
  paired as an owner) goes the same way, unchanged, but to the home's owner
  phones only, with the readable copy on or off, and never to a viewer or a
  watch. An owner's phone may therefore register for alerts with the copy
  off. A notice holding anything beyond its kind and, on `agent.added`, the
  client's name is dropped and counted. Notices have their own hourly cap.
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

- **The keys part (`ftwkeysd`).** A second process on the same host, as
  another user, answering only on a unix socket. It makes each assistant's
  agent key (X25519) when an authorization starts, seals it at rest with a
  data key from AWS KMS, and keeps it pending until the owner approves. It
  unseals a key only to open that agent's Noise session to its box, keeps
  the session's transport keys, and seals and opens each frame for
  `ftwcloudd`, which carries them as `tun`. Forgetting a key ends its
  sessions. [deploy/keys.md](deploy/keys.md) has the shape and how to turn
  it on.

- **Assistants sign in with OAuth, and the owner approves at home.** The
  authorization server follows the MCP authorization spec, revision
  2026-07-28: OAuth 2.1 with PKCE S256 only, metadata at
  `/.well-known/oauth-authorization-server` with `iss` in every
  authorization response (RFC 9207), protected resource metadata for
  `https://cloud.ftw.energy/mcp` (RFC 9728), and tokens bound to that
  resource (RFC 8707). A client names itself by a client ID metadata
  document, fetched behind a fence (https on 443 to a public address checked
  as the socket connects, no redirects, no proxy, 16 KiB, 5 s, cached), or
  registers at `/oauth/register` (RFC 7591), kept for ChatGPT and older
  clients. There is no account and no password: `/oauth/authorize` asks
  `ftwkeysd` for a new agent key and has it sign the grant offer
  (srcfl/ftw `docs/agents.md`), sent as `{o, kid, sig}`: the key, the
  client, the host it is known by and whether FTW Cloud knows it, the
  scopes, ops and caps asked for, the page's code, and an end ten minutes
  out, with no home, since the owner picks it. The page shows the client's name, where the browser goes back, the
  rights, the code, a QR and `https://app.ftw.energy/a#<request>.<offer>`;
  the app checks the offer against the offer key it pins by kid, which
  `/.well-known/ftw-offer-key` serves. The box's page or an owner who types
  the eight-character code finds the offer once at `/oauth/requests?code=`.
  A client FTW Cloud knows by the exact URL of its document is shown as
  verified, and an error goes back to it at once; any other gets a page
  with a link back. Each endpoint a stranger can call is limited per
  address and for everyone, before anything is fetched. The owner
  approves in the app or on the box's page; the box lists the agent's key,
  for that client, in the roster it signs (an agent row, with no tunnel of
  its own), and when that roster arrives the
  page, waiting on a server-sent event, returns to the client with a code.
  Only the browser that started the request gets it. Access tokens last 10
  minutes; refresh tokens rotate, a retry within 5 s works once more, and a
  later reuse revokes the family, as does a code used twice, even after its
  consent is gone. A token carries its home sealed with a fresh nonce under
  the route key (`oauth-route.key`, shared by every instance that routes),
  so any instance can route it and no client sees an id that links its
  tokens; the service keeps hashes, never tokens. A token allows the scopes it
  carries that the newest roster still grants, so an owner who narrows a
  grant narrows it at once, and it stops at the agent's end by the
  service's own clock. A roster without the agent ends
  its tokens and its key, and so does a second home listing the same key,
  or the box purging its home; a key the keys part could not forget stays
  queued until it has. Only each home's newest roster is applied.

- **MCP at `/mcp`, Streamable HTTP.** It speaks revision 2026-07-28, which
  is stateless: each request carries its version and capabilities in
  `_meta`, mirrored in `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name`,
  and a header that disagrees with the body is refused. It also answers
  clients of 2025-03-26 to 2025-11-25 that start with `initialize`, without
  session ids or a GET stream. The read tools are `homes_list`, `status`,
  `chargers_list`, `cars_list`, `plan_get`, `plan_explain`,
  `history_query`, `health_get`, `events_list`, `logs_tail` (both with
  before and after cursors), `drivers_status`, `config_get` and
  `diag_run` (names any model API accepts), each with typed arguments, each one of the box's own reads for
  agents (`live.get`, `loadpoints.get`, `cars.get`, `plan.get`, `price.get`,
  `hist.query`, `health.get`, `events.get`, `logs.get`, `config.get`,
  `diag.run`, `drivers.get`; srcfl/ftw `docs/agents.md`), under the scope
  the registry names for it. `status` keeps the box's `live` body as it
  is, keyed by field id, and adds `readings`: each field by its registry
  name (`grid_w`, `pv_w`, `battery_soc`, ...) with its unit, sources, state
  and age, and any id the registry does not name under `unknownFields`.
  `history_query` asks for every stored point of the range's tiles and
  trims and averages them to the range and the points asked for here,
  since the box spreads `maxPoints` over whole tiles. Powers are signed by
  FTW's site convention (srcfl/ftw `docs/site-convention.md`).
  The box names chargers and cars by its agent
  ids, which the control tools take back. The box refuses the passthrough to agents,
  and the readable copy is never an agent's: every read goes through the
  box, which audits it and enforces revoke. An agent row has no tunnel of
  its own. A call without its scope gets
  403 `insufficient_scope`, so the client can ask the owner for more. Each
  call rides the agent's own Noise session: `ftwkeysd` seals each frame and
  the door carries it as `tun`, one forward to the box. The door admits an
  agent row only to these sessions, never on `/v1/app` or `/v1/app/once`,
  and only before its end. A session stays warm for 60 s and calls on one
  home queue, four at most; a process runs 256 at once, and each agent
  may send 30 requests, then 10 a second. Agents' sessions have a budget
  of their own at each home, so an assistant never takes a phone's place. Agents' calls on a
  home are paced under the box's 60 reads a minute and a quarter of the
  door's tun limits, which the home's phones share: 15 in a row, then 0.75
  a second. Results are data: each says it came from the box and is not
  instructions, and characters that can hide text (controls, format and
  private-use characters, variation selectors) are removed. The
  session goes to the Noise key the box names in the roster it signs
  (`noise`); a box that names none takes no assistants yet, and each such
  home says so.
- **Control, capped and temporary.** `ev_charge_now` sends one
  `loadpoint.hold` with a power and an end (or `clear` with `stop`), the one
  hold the contract opens to agents: only when the owner's grant lists it,
  with the arguments the registry allows an agent (`RegistryAgentArgs`) and
  within the grant's caps (`holdS`, `maxW`), checked here before the box
  does and never loosened. Control ends when the assistant stops renewing;
  the service never renews a hold by itself, and another hold on the
  charger wins. Each `cmd` expects the control revision the chargers'
  answer named, read first if need be, so the first command spends nothing
  on a conflict; a stale one is learnt from `E_CONFLICT` and tried once
  more. A client's retry of the same call within a minute is the same
  command id, so the box acts once. `goal_request` asks for a lasting
  change (the mode, the planning style, a charger's solar-only charging, a
  car's charge level) as `agent.request`, with the assistant's own words for
  why; the box keeps it until an owner confirms it with Face ID, and
  `requests_list` shows how it ended. A command the box refused is a tool
  error, in words.

Not built yet:

| Step | What | Where |
|---|---|---|
| C6 | Tiles | `internal/server` |
| C7–C8 | Statistics | not started |

## How it holds a home

```
box ──wss, TLS 1.3, signed frames──▶ /v1/box ──▶ store (memory) ◀── store.For(principal) ◀── /v1/app ◀──Noise IK── phone
                                         │                                  ◀── /v1/app/once ◀──Noise IK in one POST── watch
                                         │                                  ◀── /v1/now ◀──token──── widget
                                         └────▶ registry (SQLite: key, roster, tombstones, suspensions, APNs, token hashes, away)
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
- **A phone or a watch can narrow, and talk to its own box.** A phone can
  say whether it is looking, an owner can suspend a device in the roster, and
  a phone sends its box session as `tun`, which the service cannot read. A
  watch can read, ask for its token and register for push.
- **The service sends six things.** `challenge`, `hello_ok`, `watch`,
  `resync`, `purged` and `tun` are the whole downlink. The first five ask
  the box for nothing; `tun` carries a phone's ciphertext, which the box
  judges as it judges the same session over the relay. The box closes the
  uplink on anything else.
- **No TLS terminator in front.** Box and service bind the handshake to the
  TLS session, so `ftwcloudd` ends TLS itself. A TCP load balancer is fine,
  and so is a UDP one that forwards packets; nothing may end QUIC.
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
go build -o /tmp/ftwload/ftwcloudd ./cmd/ftwcloudd   # then, briefly and on a quiet machine:
go run ./cmd/ftwload -ftwcloudd /tmp/ftwload/ftwcloudd -homes 1000 -phones 1 -duration 45s
```

`cmd/ftwload` starts its own `ftwcloudd`, drives simulated boxes and phones
against it, prints latencies (its own and the service's from `/metrics`),
CPU and memory, and exits by itself.

The wire types come from `github.com/srcfl/ftw/go/protocol`, Apache-2.0,
pinned to a commit in `go.mod`. A wire change is a pair of pull requests:
first in `srcfl/ftw` (`go/protocol` and its golden vectors), then here, moving
the pin. The service may import nothing else from `srcfl/ftw`; CI checks that
with `go list -deps`, so no control code can reach this build.

## License

`ftwcloudd` is licensed under the GNU Affero General Public License, version 3
only (AGPL-3.0-only). See [LICENSE](LICENSE) and
[CONTRIBUTING.md](CONTRIBUTING.md).

Anonymous box reports use `POST /v1/fleet`. It accepts only the seven
`ftw.fleet/1` fields and reduces each report into bounded daily counts for
90 days. It stores no raw report, address or home id. An operator can read
`/fleet/stats` only on the loopback metrics listener, with
`docker exec ftw-cloud-ftwcloudd-1 ftwcloudd fleet`. These counts measure
reports, not unique boxes.

Browser offline notices use the box's optional signed roster rows. The box
encrypts each notice and signs a short-lived VAPID header; the service holds
no browser encryption key or box signing key. It uses the APNs outage timer,
including update grace and deploy drain, and checks the current device epoch,
events scope and suspension before sending. A readable-copy grant is not
needed. The roster holds the delivery endpoints and ciphertext; a separate
per-home row holds only the current outage's sent ids. Purge removes both.
The sender refuses redirects, proxies and local destinations.

## Project usage statistics

`GET /v1/stats` publishes only group cells under
`ftw-project-stats-2026-10-v1`. Boxes send signed `stats` hours only after the
owner accepts that policy and the service advertises it in signed `hello_ok`.
The service starts with collection off. After the signed C8 DPIA review,
operators can set `FTW_CLOUD_STATISTICS_POLICY` to that exact policy in the
host's compose environment; empty keeps it off. An unapproved policy makes
`/v1/stats` return 503 with `FTW-Statistics-State: disabled`. Withdrawal,
purge and retention remain active while collection is off. The review draft
is in [privacy/project-statistics-dpia.md](privacy/project-statistics-dpia.md). The previous statistics policy sends no new
fields. Reporting installations in the last 24 closed hours are not people
or total FTW installs. Power and capacity are configured; energy sums
recorded hours, including partial hours. Missing data is unknown.

Cloud stores consented hourly values for 13 months, upserts reconnects, and
deletes household rows on a signed withdrawal or purge. Cells need 20 homes
and no home above 30 percent of the sum. The stats Worker polls this public
view; it receives no home id or per-home value. One instance supplies its
local shard only; public multi-shard totals need an explicit safe collector.

Owner acceptance uses the existing box API. On the box's loopback interface,
read `GET /api/cloud/stats-policy`, accept its terms, then
`POST /api/cloud/stats` with `{"policy":"ftw-project-stats-2026-10-v1"}`.
The readable Cloud grant must already be on. `DELETE /api/cloud/stats`
withdraws this choice. Do not enable it for someone else or reuse an older
consent. Native apps keep the old scope until their consent screen adopts
this policy. The first contributing hour starts after consent; the sender
does not upload earlier ledger history.

Deploying this ingestion scope still needs the signed C8 DPIA and the
updated consent text described by Core's ADR 0008. This change does not
claim that sign-off, change an owner's saved choice, or release a Core
update. The paired native consent change requires a fresh choice for this policy.


The separate anonymous daily-report feed is `GET /v1/fleet/public`. It exposes
only daily counts and dimension labels with at least 10 reports, for at most
90 days. It contains imported relay history and new reports received by Cloud;
consumers replace the old archive rather than adding both. It needs no hourly
energy policy. Averaging seven complete UTC days gives an estimate of active
reporting installations, never people or all installations ever made.
