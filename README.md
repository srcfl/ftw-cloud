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
  never written to disk. History tiles stay longer, also in memory only.
- What the service holds follows the newest roster's grant, never `hello`:
  the readable copy can turn on or off while the uplink stays up.
- The registry (SQLite) holds the home id, the box key, the signed roster,
  owners' suspensions, APNs registrations, the hashes of extension tokens,
  when an away box's alert is due, and the service's own hourly counts. A box whose owner turns the readable
  copy off gets that copy deleted and a signed receipt (`purged {what:
  "copy"}`); a box whose link ends gets its home deleted and a receipt.
- **Room to grow.** Each home lives on one shard; an instance that does not
  hold a home names the host that does, and clients follow once
  (`internal/shard`, protocol "Shards and restarts"). With no `-shards` file
  one instance holds every home. A deploy closes every socket with 4503 and
  a spread, so boxes and phones come back over seconds rather than at once.
  `/metrics` on loopback and one log line a minute count what the service
  does without naming a home; the registry keeps the same counts an hour
  at a time for 90 days ([Internal operations](#internal-operations)). `deploy/README.md` has the load numbers and
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
  and it carries one of `read {have, hz}`, `token.get`, `push.register`,
  `push.unregister` or `x {d}`. The service admits the watch exactly as
  `/v1/app` admits a phone: its key in the box's roster, a roster that has
  not run out, no suspension. `x` needs the entry's `tun` and role `watch`;
  the rest need a scope the readable copy grants. The box lists a watch
  with role `watch` and the scopes it derives; the service checks no other
  role. A refusal is
  403 with an empty body. The answer is message 2 with the snapshot, less
  the envelopes `have` says the watch holds, and the envelopes that did not
  fit after it, each after its length. The box's bytes go unchanged, so the
  watch grades their freshness itself. The service keeps no session and no
  Noise state after the answer. Limits: one read at a time per device and 30
  a minute, 16 at once per home, 64 at once in the process, message 1 at
  most 4 KiB, the answer within 10 s.
- **A watch's commands ride `x`.** Its `d` is one message of the watch's
  own short Noise session with the box (`ftw.exchange.v1`), which the
  service cannot read. The service sends `x {dev, id, d}` down `/v1/box`,
  with the device id its own handshake matched and a number of its own, and
  answers with the `d` of the box's `x` under the same two, unchanged. It
  answers an empty `d` at once when the box is not connected, did not list
  `x` in `hello.caps` or has 8 exchanges open, and after 5 s without an
  answer. `d` is at most 2,048 bytes, and the one-shot limits hold for the
  whole wait. The service drops and counts an answer nobody waits for.
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
- **History tiles (C6).** A box whose owner's grant has `ftw.history.read`
  sends its last 48 hours of 5-minute history as `tiles`: 12-hour tiles, each
  closed one the same bytes the box serves over Noise, and the tile still
  filling whole or as an append when a bucket closes. The service checks
  each against the protocol's three shapes and the four series, refuses an
  envelope over 4 KiB, and holds it in memory as the box signed it: per home
  at most five closed tiles, 16 pieces of the filling one and 64 KiB, all
  homes together at most 256 MiB. A closed tile is replaced only by one the
  box sent later. A tile the box did not sign closes the uplink, as any such
  message does; one of no shape is dropped and counted. `hello_ok.have`
  names the closed tiles held, so a box that comes back sends only what is
  missing, and the service sends `resync {what: [tiles]}`, at most once per
  5 minutes, when a roster gives history back or room frees after a drop. A
  phone with `ftw.history.read` asks with `tiles.get {have}`, gets the tiles
  it lacks and then `tiles.end {n}`, and gets each new tile as it comes. The
  snapshot, `/v1/app/once` and `/v1/now` carry none. Tiles are dated history,
  so they outlive the hour after which readings go: each stays until 48
  hours after it ends, up to 60 hours of history, while the roster is in
  force. With the box away a phone can therefore read them for 18 to 24
  hours. A revoke, a grant without history, a roster that runs out, a purge
  and the 90-day expiry delete them. Assistants read history from the box,
  never from these tiles; while the box is away, `history_query` says so and
  when FTW Cloud last heard from it.
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
  `ftwkeysd` for a new agent key. If the client omits `scope`, the original
  browser first chooses read/troubleshoot or read/configure. Nothing exposes
  the key, offer, QR or owner code before that choice. Configure adds
  `ftw.setup.write` to the read scopes; neither choice adds control. An
  explicit scope parameter keeps its existing meaning, including an explicitly
  blank value. Only the original cookie and exact issuer Origin can save a
  mode, once, without changing the key or deadline. Competing choices read
  the saved result; a late signature cannot revive a cancelled request.
  Signing uses the same global and address limits as authorization.
  Then `ftwkeysd` signs the grant offer
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

- **An owner can share access with six characters.** The owner creates a
  strong, single-use invitation on Core, with chosen rights and access expiry.
  Their page or app publishes that proof through TLS to `POST /oauth/invitations`.
  The service checks its home, box and verifier against the current signed
  roster, then returns a unique code such as `K7M-4PX`, valid for at most ten
  minutes. No cookie grants the right to publish. The recipient pastes the
  short code into their own OAuth connection page. Its original browser
  cookie, Origin and separate rate limits apply before lookup. A pending key
  can open only a typed invitation Noise handshake; Core consumes the
  invitation after proof of that key and intersects the chosen rights with
  the recipient's request. Only the new signed roster permits Keep, PKCE
  completion and normal MCP access. Cancellation and revocation still belong
  to Core. The short code does not give an owner role.

  The alias-to-proof mapping stays in memory and expires within ten minutes;
  the normal minute sweep removes expired mappings. SQLite holds only keyed
  digest reservations and expiry. A MAC key derived from `oauth-route.key`,
  outside that database, protects those reservations. A restart cannot assign
  an unexpired code to a different invitation. After a restart the owner can
  republish the same proof for a working code without another Core grant.
  No raw code, proof or secret enters a log, URL or database. This mapping
  currently requires the single OAuth process used by the deployment.

- **MCP at `/mcp`, Streamable HTTP.** It speaks revision 2026-07-28, which
  is stateless: each request carries its version and capabilities in
  `_meta`, mirrored in `MCP-Protocol-Version`, `Mcp-Method` and `Mcp-Name`,
  and a header that disagrees with the body is refused. It also answers
  clients of 2025-03-26 to 2025-11-25 that start with `initialize`, without
  session ids or a GET stream. The read tools are `homes_list`, `status`,
  `chargers_list`, `cars_list`, `plan_get`, `plan_explain`,
  `history_query`, `health_get`, `logs_tail` (with before/after cursors),
  `drivers_status`, `config_get` and `measurement_diagnostics`, each with
  typed arguments and the scope its box operation requires.
  `measurement_diagnostics` needs the owner's diagnostic grant. Both MCP
  profiles offer its fixed, read-only views of measurement reasons, saved
  charger associations, energy provenance and stored series. Names and
  hardware identifiers become opaque selections; other private fields stay
  out. Refresh the catalogue after a service restart. No arbitrary path,
  settings write, control or credential export is accepted by this tool.
  `diag_run` and `events_list` are not listed until Core serves them. Cached
  calls get an explicit unsupported result and never reach Core.
  Full technical reads remain separate through `api_catalog` / `api_read`
  on the technical profile. `status` keeps the box's `live` body as it
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
  403 `insufficient_scope`, so the client can ask the owner for more. A
  `setup_begin` and every setup write ask for both `ftw.diag.run` and `ftw.setup.write`, so a fresh
  connection can read its schema and save receipt. Tool metadata and the
  runtime OAuth challenge name the same scopes, as required by
  [ChatGPT's authentication flow](https://developers.openai.com/plugins/build/auth#triggering-authentication-ui).
  Existing token scopes stay in the request; no scope is granted by inference.
  Setup tools use the connected box's schema and resumable question guide.
  Explicit discovery, private draft connection tests and MyUplink browser
  sign-in stay bound to that draft. An empty box first needs its local
  assistant setup, house password and owner-approved Cloud terms. After the
  first measurement save, ordinary `goal_request` and `car_goal_request`
  choose mode, planning style and car departure schedules. The owner can
  approve in local Settings → Access as well as in the FTW app; each request
  keeps its existing permission check and receipt. Configuration and hardware
  evidence remain separate. These tools need the paired onboarding Core;
  older boxes refuse unsupported draft actions without changing settings.
  Each call rides the agent's own Noise session: `ftwkeysd` seals each frame and
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
| C7–C8 | Statistics | implemented with collection off; review pending |

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
  watch can read, ask for its token, register for push and send its
  exchange with the box as `x`, which the service cannot read either.
- **The service sends seven things.** `challenge`, `hello_ok`, `watch`,
  `resync`, `purged`, `tun` and `x` are the whole downlink. The first five
  ask the box for nothing; `tun` carries a phone's ciphertext and `x` a
  watch's, which the box judges as it judges the same session over the
  relay. The box closes the uplink on anything else.
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

Anonymous box reports use `POST /v1/fleet`, or, from a Core release that
names a relay, `POST /v1/ohttp` (see "Anonymous daily reports" below). The
direct route sees the box's address; it stays for older releases and can go
one stable Core release after the first that pins the relay. Either way it
accepts only the seven `ftw.fleet/1` fields and reduces each report into
bounded daily counts for 90 days. It stores no raw report, address or home id. An operator can read
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
`ftw-project-stats-2026-10-v3`. Collection stays off until the signed C8 DPIA
and the legal basis for both flows have been reviewed. Empty
`FTW_CLOUD_STATISTICS_POLICY` keeps it off; an exact approved policy is needed
to advertise collection. While paused, `/v1/stats` returns 503 with
`FTW-Statistics-State: disabled`. Withdrawal, purge and retention still run.
The unsigned [review draft](privacy/project-statistics-dpia.md) records the
open decisions. Clear terms alone do not establish a lawful basis.

Statistics are included for every FTW Cloud user under
`ftw-cloud-2026-10-v3`. Owners accept the current scope through
`POST /api/cloud/grant`. There is no separate statistics opt-out within Cloud;
`DELETE /api/cloud` ends Cloud and requests deletion. Old terms do not accept
the new scope. Deploy compatible Core and clients, show the new terms, and
review the migration before policy activation. When activated, the service
refuses legacy rosters and does not restore their cached access after restart.
Until activation, existing Cloud traffic continues under the old scope.

Local FTW users can instead answer Yes or No on the box. Yes is the suggested
action, but no new report starts without an answer. `POST /api/cloud/stats`
with the current statistics policy creates a statistics-only signed uplink:
no phone keys, pairing codes, Noise key, live cache or remote access.
`DELETE /api/cloud/stats` stops this local contribution. A current Cloud grant
refuses that separate stop with 409. Never answer for another household.

Cloud stores the approved hourly fields for 48 hours and deletes unpublished
household rows on withdrawal or purge. Only closed hours starting after the
new choice contribute; no earlier ledger history is uploaded. Group values
need 20 homes and no home above 30 percent of a sum. The stats Worker receives
no home id or per-home value. Counts describe reporting installations, not
people or all-time installs. Capacity and power are configured limits, not
proof of physical control. Energy includes only recorded hours, which can be
partial; missing data is unknown. One instance supplies its local shard only;
public multi-shard totals need an explicit safe collector.

The separate anonymous daily-report feed is `GET /v1/fleet/public`. It exposes
only daily counts and dimension labels with at least 5 reports, for at most
90 days. It contains imported relay history and new reports received by Cloud;
consumers replace the old archive rather than adding both. It needs no hourly
energy activation. Updated Core sends it only after the current project
statistics answer; legacy versions retain their existing daily-report setting. Averaging seven complete UTC days gives an estimate of active
reporting installations, never people or all installations ever made.

## Anonymous daily reports

Statistics from a box are two anonymous daily reports, each sent alone and at
its own random time, never in one message. With FTW Cloud they are part of
Cloud; without it they are on until the owner turns them off on the box. The
rule lives in Core (`cloudlink.SharesStatistics` in srcfl/ftw).

- The fleet report (`ftw.fleet/1`): version, channel, drivers, battery size,
  price zone and install age, into the counts `/v1/fleet/public` publishes.
- The energy report (`ftw.energy/1`): once per closed UTC day, 1 to 12 hours
  after it closes, the date and six whole-kWh sums (solar generation, grid
  import and export, battery charge and discharge, vehicle charge). A day
  with a gap in the box's energy ledger is skipped.

They never travel together because, with a fleet of a few boxes, a driver set
and a price zone can point at one home, and energy beside them would then be
that home's.

From a Core release that names a relay, the box seals each report with
Oblivious HTTP (RFC 9458) to the gateway key its release pins, and posts it
to an independent relay ([deploy/ohttp.md](deploy/ohttp.md)). The relay sees
the box's address and a ciphertext of fixed length (1,591 bytes).
`POST /v1/ohttp` (`internal/gateway`) sees the report and the relay's
address. It reads the one padded inner request, chooses the decoder by
schema, adds the report to its own day totals and answers a sealed 204, or
400 for anything else: exact fields, and for energy at most 1,000 kWh each
and a date in the last three closed days. Each request carries a random
report id and the UTC date it was sent. The gateway refuses one sent before
yesterday, and keeps a hash of each id under its date for three days, in a
table with no time or arrival order, so a replay or a retry counts once and
is still answered 204 (RFC 9458, section 6.5). Beyond that it keeps nothing
per report: no row, logged body or address. Each kind has its own rate
budget, spent only by a report that opened and decoded, so junk cannot
silence real reports. A day takes at most 100,000 reports of each kind, and
a body has 10 seconds to arrive.
`GET /.well-known/ohttp-gateway` serves the key configuration for the relay
operator and for anyone checking the pin.

`GET /v1/energy/public` lists the closed dates of the last 30 days, newest
first: the report count and the six sums. A date appears only once no report
may name it any more, so two readings never differ by one report. A date with
fewer than 5 reports shows null, as `/v1/fleet/public` does. So does a sum that
between one and four of them had any of: five reports with one car is that
car's charge. A sum nobody had any of shows 0. Rows, which hold for each sum
how many reports had any of it, go after 30 days. These are reports, not
homes.

`/v1/fleet/public` also lists closed days only, so whoever forwarded a
report, the relay above all, cannot poll the view and see which count it
moved.

Limits, plainly. The floor of five counts reports, not boxes; Fredrik
accepted this on 24 October 2026. A report cannot prove that a real box sent
it. The relay alone can drop the other reports and add fakes to isolate one
home's day, and that shows on our side as missing reports. Anyone else can
do it only on a day when one real home reported. Rejecting replays and
listing closed days only remove the cheap attacks. Anonymous tokens (Privacy
Pass) are the later fix, once the fleet grows or someone shows a need. The
relay and Sourceful together could join reports to addresses by time. This
service also holds readings from homes with the readable copy on, including
48 hours of history tiles, from which the same daily sums could be computed;
the gateway does not do this and keeps nothing to match with, but that is a
rule in code, not one the cryptography enforces.

Open for Fredrik's lawyer: reports that are anonymous to Sourceful through
OHTTP should be outside GDPR, but reading data from the owner's equipment to
make them may still need consent under the ePrivacy rule (Swedish LEK,
chapter 9, section 28). If it does, neither the opt-out for boxes without
Cloud nor the requirement with Cloud holds.

## Internal operations

Sourceful runs the service and the fleet from one internal view: the private
page of stats.ftw.energy, behind Cloudflare Access. It needs no system of
its own. The service keeps its counts; the stats Worker pulls them once an
hour into its D1 database.

**What the service keeps.** Every hour `internal/metrics` hands the hour to
the registry (`ops_hours`, one row an hour): how much each counter rose,
each gauge's low, mean and high over the minutes sampled, each latency's
buckets, how much of the hour a process ran, and how many processes started
in it. A deploy hands over its part of the hour after the drain, and the
next process adds the rest to the same row. The series are the ones
`/metrics` serves: sockets by kind and by transport (QUIC or WebSocket),
homes held and connected, bytes written to boxes and phones, tun frames and
bytes, drops by reason, push queues and the answers of Apple and of browsers'
push services, MCP requests and tool calls by outcome and their time,
handshake and forward latency, the drain's sockets and the Go runtime.
Hours go after 90 days, at each write and at upkeep.

**What it serves.** `GET /v1/ops` answers only the key the Worker holds,
`Authorization: Bearer <key>`. The service holds the key's SHA-256
(`-ops-key-sha256`), which is no secret; without it the route answers 404
to everyone, and the hours are kept all the same. An answer carries at most
a week of settled hours (`?since=`, five minutes after an hour ends), and the
exact totals of the anonymous fleet and energy reports for closed days: a
fleet day once it has ended, an energy date once no report may name it, as
`/v1/energy/public` has it. Below the public group size of 5 too, but never
an open day, so two answers never differ by one report. `/v1/ops` is
`ftw.cloud-ops/1`; the Worker refuses any field it does not name.

**Why none of it is about a household.** Each series sums over the whole
process. A label is a word fixed in the code, never a home, a device, a key
or an address (`TestCountsNameNobody`), and no series is made for a home
(`TestAnHourOfCountsNamesNobody`). The fleet and energy days are totals of
reports that carry no id and keep nothing per report. The limits, plainly:
while the fleet is a handful of homes, an hour's phone count or a closed
day's single report says something about those few, and staff who know
them could guess. The feed gives nobody more than the totals, and nobody
outside Access sees them. [privacy/internal-operations.md](privacy/internal-operations.md)
has the argument and the retention in full.

Per-home data stays where it is: in memory for the home's own phones, and in
support access only when an owner opts in for a ticket.
