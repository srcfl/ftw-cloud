// Package relay is the remote-command path: the blind relay, in this process.
//
// A box dials out and a phone, a browser or a watch meets it under a
// rendezvous handle that rotates every hour. Frames are end-to-end Noise
// between those peers. This package forwards the bytes and reads two things
// off them: their length, and, on the box's exchange socket, the 16-byte id
// it wrote there itself. It has no key that opens a command, and it does not
// import the Noise session or the readable store.
//
// The path is separate from /v1/box. That socket carries signed cloud
// envelopes and a closed downlink (challenge, hello_ok, watch, resync,
// purged); the box closes it on anything else. Command frames are not those
// envelopes, and ready/gone are not those five messages. Multiplexing the
// two would either make this service parse commands or make the box drop
// the uplink. Clients that already speak the Frankfurt relay switch by
// changing the origin alone: /r/<epoch>/<handle>/<box|app|exchange> and
// POST /x/<epoch>/<handle> are the same paths, on this server.
package relay

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// Options configures the path. Zero values are the Frankfurt limits.
type Options struct {
	Log *slog.Logger
	Now func() time.Time
	// DeadmanPath is the sealed-row file. Empty keeps the rows in memory,
	// which is what tests want. The file holds push ciphertext, not readings.
	DeadmanPath string
	// Post delivers a fired dead-man row. Nil posts HTTPS and refuses a
	// private address.
	Post PushPost
	// BoxKeys, when set, is consulted for a join that presents a box-key
	// proof. A proof from a key it does not recognise is refused.
	BoxKeys BoxKeys
	// RequireBoxKey refuses a box or exchange join that presents no proof.
	// Leave it false until boxes send the proof: existing clients join with
	// the handle alone, and requiring the proof before they send it would
	// cut every house off.
	RequireBoxKey bool
}

// Relay is the command path's handler for /r/, /x/ and /deadman.
type Relay struct {
	log           *slog.Logger
	now           func() time.Time
	keys          BoxKeys
	requireBoxKey bool
	dead          *deadman

	mu            sync.Mutex
	rooms         map[string]*room
	epoch         int64
	rotateStarted time.Time
	sockets       int
	perAddr       map[string]int
	frames        int64
	nbytes        int64
	heartbeats    atomic.Int64
	openN         int
	joins         *attempts
	exchanges     *attempts
	closed        bool
}

type room struct {
	uplink   *peer
	streams  map[*peer]struct{}
	exchange *peer
	open     map[string]*pending
	rate     *bucket
	epoch    int64
}

func (m *room) empty() bool {
	return m.uplink == nil && m.exchange == nil && len(m.streams) == 0
}

func (m *room) peers() []*peer {
	out := make([]*peer, 0, len(m.streams)+2)
	if m.uplink != nil {
		out = append(out, m.uplink)
	}
	for p := range m.streams {
		out = append(out, p)
	}
	if m.exchange != nil {
		out = append(out, m.exchange)
	}
	return out
}

// peer is one socket. Its buckets die with it.
type peer struct {
	conn    *websocket.Conn
	role    string
	frames  *bucket
	bytes   *bucket
	alive   atomic.Bool
	linked  bool
	addr    string
	claims  map[string]struct{}
	writeMu sync.Mutex
	removed bool
	closing atomic.Bool
}

type pending struct {
	w     http.ResponseWriter
	done  chan struct{}
	timer *time.Timer
}

// New builds the handler. It does not start the heartbeat; call Run.
func New(opts Options) *Relay {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	log := opts.Log
	if log == nil {
		log = slog.Default()
	}
	at := now()
	r := &Relay{
		log:           log,
		now:           now,
		keys:          opts.BoxKeys,
		requireBoxKey: opts.RequireBoxKey,
		rooms:         map[string]*room{},
		epoch:         CurrentEpoch(at),
		perAddr:       map[string]int{},
		joins:         newAttempts(attemptLimit, attemptWindow, attemptSlots, at),
		exchanges:     newAttempts(exchangePerMinute, attemptWindow, attemptSlots, at),
	}
	r.dead = newDeadman(opts.DeadmanPath, now, opts.Post, func(status int, failed bool) {
		// Status only. The endpoint is a push token, which is a household
		// identifier, so it never reaches the log.
		if failed {
			log.Info("relay deadman", "result", "failed")
			return
		}
		log.Info("relay deadman", "status", status)
	})
	return r
}

// Run drives the one timer: heartbeats, reaping and the hour's rotation.
// The cadence is fixed, so nothing the peers send can change it.
func (r *Relay) Run(ctx context.Context) {
	t := time.NewTicker(heartbeatEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.Close()
			return
		case <-t.C:
			r.beat()
		}
	}
}

// Close drops every socket and answers every watch that is still waiting.
func (r *Relay) Close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	var peers []*peer
	var waiting []*pending
	for _, m := range r.rooms {
		peers = append(peers, m.peers()...)
		for k, p := range m.open {
			delete(m.open, k)
			r.openN--
			waiting = append(waiting, p)
		}
	}
	r.rooms = map[string]*room{}
	r.mu.Unlock()
	for _, p := range waiting {
		writeStatus(p.w, http.StatusGatewayTimeout, "")
		close(p.done)
		if p.timer != nil {
			p.timer.Stop()
		}
	}
	for _, p := range peers {
		_ = p.conn.Close()
	}
}

// ServeHTTP answers the command path. Anything else is a 404, which is what
// a request for a home would get here too: this handler has no way to read one.
func (r *Relay) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	switch {
	case strings.HasPrefix(req.URL.Path, "/r/"):
		r.serveJoin(w, req)
	case strings.HasPrefix(req.URL.Path, "/x/"):
		r.serveExchange(w, req)
	case req.URL.Path == "/deadman" || strings.HasPrefix(req.URL.Path, "/deadman/"):
		r.serveDeadman(w, req)
	default:
		http.NotFound(w, req)
	}
}

var upgrader = websocket.Upgrader{
	EnableCompression: false, // a compressed frame's size depends on its content
	ReadBufferSize:    4096,
	WriteBufferSize:   4096,
	// The webapp is a browser on another origin. The handle is the
	// capability; an Origin check would only refuse the clients this path
	// exists for. Browsers still cannot read a watch's HTTP answer: /x/
	// sends no CORS header.
	CheckOrigin: func(*http.Request) bool { return true },
}

func (r *Relay) serveJoin(w http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Upgrade") == "" {
		writeStatus(w, http.StatusUpgradeRequired, "upgrade required\n")
		return
	}
	now := r.now()
	addr := clientIP(req, false)

	r.mu.Lock()
	switch {
	case r.closed || r.sockets >= maxSockets:
		r.mu.Unlock()
		r.rejectUpgrade(w, req, CloseBusy, "full")
		return
	case !r.joins.allow(addr, now):
		r.mu.Unlock()
		r.rejectUpgrade(w, req, CloseBusy, "slow down")
		return
	}
	epoch := r.epoch
	r.mu.Unlock()

	j, ok := parseJoin(req.URL.Path)
	if !ok {
		r.rejectUpgrade(w, req, CloseBadJoin, "join")
		return
	}
	if j.epoch != epoch {
		r.rejectUpgrade(w, req, CloseEpoch, strconv.FormatInt(epoch, 10))
		return
	}
	switch checkBoxProof(req, r.keys, j.epoch, j.handle, j.role) {
	case proofBad:
		r.rejectUpgrade(w, req, CloseBadJoin, boxKeyReason())
		return
	case proofAbsent:
		if r.requireBoxKey && j.role != roleApp {
			r.rejectUpgrade(w, req, CloseBadJoin, boxKeyReason())
			return
		}
	}

	conn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(maxFrameBytes)
	p := &peer{
		conn:   conn,
		role:   j.role,
		frames: newBucket(frameCapacity, framesPerSecond, now),
		bytes:  newBucket(byteCapacity, bytesPerSecond, now),
		addr:   addr,
	}
	p.alive.Store(true)
	conn.SetPongHandler(func(string) error {
		p.alive.Store(true)
		return nil
	})

	r.mu.Lock()
	if r.closed || r.sockets >= maxSockets || r.perAddr[addr] >= maxSocketsPerAddr {
		r.mu.Unlock()
		closeConn(conn, CloseBusy, "full")
		return
	}
	m := r.rooms[j.handle]
	if m == nil {
		m = &room{
			streams: map[*peer]struct{}{},
			open:    map[string]*pending{},
			rate:    newBucket(exchangePerMinute, float64(exchangePerMinute)/60, now),
			epoch:   j.epoch,
		}
	}
	switch j.role {
	case roleBox:
		if m.uplink != nil {
			r.mu.Unlock()
			closeConn(conn, CloseBusy, "uplink")
			return
		}
		m.uplink = p
	case roleExchange:
		if m.exchange != nil {
			r.mu.Unlock()
			closeConn(conn, CloseBusy, "exchange")
			return
		}
		m.exchange = p
	default:
		if len(m.streams) >= maxStreamsPerRoom {
			r.mu.Unlock()
			closeConn(conn, CloseBusy, "streams")
			return
		}
		m.streams[p] = struct{}{}
	}
	r.rooms[j.handle] = m
	r.sockets++
	r.perAddr[addr]++
	notes := r.sync(m)
	r.mu.Unlock()
	r.flushText(notes)
	r.readLoop(j.handle, m, p)
}

// rejectUpgrade accepts the WebSocket and closes it with a relay code.
// Closing before the upgrade would turn every refusal into an HTTP status,
// which the box and the app do not read: they read the close code.
func (r *Relay) rejectUpgrade(w http.ResponseWriter, req *http.Request, code int, reason string) {
	conn, err := upgrader.Upgrade(w, req, nil)
	if err != nil {
		return
	}
	closeConn(conn, code, reason)
}

func (r *Relay) readLoop(handle string, m *room, p *peer) {
	defer r.onClose(handle, m, p)
	for {
		kind, msg, err := p.conn.ReadMessage()
		if err != nil {
			return
		}
		if r.onMessage(m, p, kind, msg) {
			return
		}
	}
}

// onMessage reports whether the loop should stop. The bytes of a binary
// frame are forwarded unchanged; the only use of the slice is its length,
// except on the exchange socket where the first 16 bytes are the id this
// service chose.
func (r *Relay) onMessage(m *room, p *peer, kind int, msg []byte) bool {
	if kind != websocket.BinaryMessage {
		if id, ok := deadmanClaimID(string(msg)); ok && p.role == roleBox {
			r.noteClaim(p, id)
			return false
		}
		r.drop(p, CloseBadJoin, "binary only")
		return true
	}
	if len(msg) > maxFrameBytes {
		r.drop(p, CloseBadJoin, "oversize")
		return true
	}
	now := r.now()
	if !p.frames.take(1, now) || !p.bytes.take(float64(len(msg)), now) {
		r.drop(p, CloseBusy, "rate")
		return true
	}
	if p.role == roleExchange {
		r.onAnswer(p, m, msg)
		return false
	}

	// Copy before the next read reuses the buffer. WriteMessage copies too,
	// and the writes below finish before the next read; the copy is what
	// keeps a later change from aliasing a frame.
	frame := append([]byte(nil), msg...)
	r.mu.Lock()
	var dest []*peer
	if p.role == roleBox {
		for s := range m.streams {
			dest = append(dest, s)
		}
	} else if m.uplink != nil {
		dest = append(dest, m.uplink)
	}
	r.frames++
	r.nbytes += int64(len(frame))
	r.mu.Unlock()
	for _, d := range dest {
		if err := d.send(websocket.BinaryMessage, frame); err != nil {
			r.drop(d, CloseBusy, "slow reader")
		}
	}
	return false
}

func (r *Relay) noteClaim(p *peer, id string) {
	if p.claims == nil {
		p.claims = map[string]struct{}{}
	}
	if _, ok := p.claims[id]; ok {
		return
	}
	p.claims[id] = struct{}{}
	r.dead.claim(id)
}

func (r *Relay) onAnswer(p *peer, m *room, frame []byte) {
	if len(frame) <= ExchangeIDBytes || len(frame) > ExchangeIDBytes+exchangeMaxReply {
		r.drop(p, CloseBadJoin, "size")
		return
	}
	key := hex.EncodeToString(frame[:ExchangeIDBytes])
	reply := append([]byte(nil), frame[ExchangeIDBytes:]...)
	r.settle(m, key, http.StatusOK, reply)
}

func (r *Relay) onClose(handle string, m *room, p *peer) {
	r.mu.Lock()
	if p.removed {
		r.mu.Unlock()
		return
	}
	p.removed = true
	r.sockets--
	if p.addr != "" {
		if n := r.perAddr[p.addr] - 1; n > 0 {
			r.perAddr[p.addr] = n
		} else {
			delete(r.perAddr, p.addr)
		}
	}
	var waiting []*pending
	switch {
	case m.uplink == p:
		m.uplink = nil
	case m.exchange == p:
		m.exchange = nil
		waiting = takeWaiting(r, m)
	default:
		delete(m.streams, p)
	}
	if r.rooms[handle] == m && m.empty() {
		delete(r.rooms, handle)
	}
	notes := r.sync(m)
	r.mu.Unlock()
	for id := range p.claims {
		r.dead.release(id)
	}
	r.finishWaiting(waiting, http.StatusGatewayTimeout)
	r.flushText(notes)
}

// sync queues ready/gone. The exchange socket is not a side of the room:
// it is never told, and it never tells.
func (r *Relay) sync(m *room) []textNote {
	var notes []textNote
	note := func(p *peer, present bool) {
		if p == nil || p.linked == present || p.removed {
			return
		}
		p.linked = present
		word := CtrlGone
		if present {
			word = CtrlReady
		}
		notes = append(notes, textNote{p, word})
	}
	if m.uplink != nil {
		note(m.uplink, len(m.streams) > 0)
	}
	up := m.uplink != nil
	for s := range m.streams {
		note(s, up)
	}
	return notes
}

type textNote struct {
	p    *peer
	word string
}

func (r *Relay) flushText(notes []textNote) {
	for _, n := range notes {
		if err := n.p.send(websocket.TextMessage, []byte(n.word)); err != nil {
			r.drop(n.p, CloseBusy, "slow reader")
		}
	}
}

// beat is the heartbeat, the reap and the rotation check.
func (r *Relay) beat() {
	r.dead.beat()
	now := r.now()
	epoch := CurrentEpoch(now)

	r.mu.Lock()
	var dead []*peer
	var ping []*peer
	for _, m := range r.rooms {
		for _, p := range m.peers() {
			if !p.alive.Load() {
				dead = append(dead, p)
				continue
			}
			p.alive.Store(false)
			ping = append(ping, p)
		}
	}
	if epoch != r.epoch {
		r.epoch = epoch
		r.rotateStarted = now
	}
	type rot struct {
		peers []*peer
		wait  []*pending
	}
	var rotate []rot
	if !r.rotateStarted.IsZero() {
		elapsed := now.Sub(r.rotateStarted)
		for handle, m := range r.rooms {
			// A room that joined this hour already has this hour's handle.
			// Evicting it would kick a healthy peer, and kick it again on
			// every tick, which is also the vanish-and-return pattern
			// rotation exists to avoid.
			if m.epoch == r.epoch || elapsed < RotationOffset(handle, rotateSpread) {
				continue
			}
			rotate = append(rotate, rot{peers: m.peers(), wait: takeWaiting(r, m)})
			delete(r.rooms, handle)
		}
		if elapsed >= rotateSpread {
			r.rotateStarted = time.Time{}
		}
	}
	epoch = r.epoch
	rooms, sockets := len(r.rooms), r.sockets
	frames, nbytes := r.frames, r.nbytes
	r.mu.Unlock()

	for _, p := range dead {
		_ = p.conn.Close()
	}
	for _, p := range ping {
		deadline := time.Now().Add(maxBufferedWrite)
		if p.conn.WriteControl(websocket.PingMessage, nil, deadline) != nil {
			_ = p.conn.Close()
			continue
		}
		r.heartbeats.Add(1)
	}
	reason := strconv.FormatInt(epoch, 10)
	for _, item := range rotate {
		for _, p := range item.peers {
			closeConn(p.conn, CloseRotated, reason)
		}
		r.finishWaiting(item.wait, http.StatusGatewayTimeout)
	}
	r.log.Info("relay", "epoch", epoch, "rooms", rooms, "sockets", sockets, "frames", frames, "bytes", nbytes)
}

// takeWaiting removes a room's open exchanges. The caller holds r.mu.
// Calling it twice returns an empty slice the second time.
func takeWaiting(r *Relay, m *room) []*pending {
	if len(m.open) == 0 {
		return nil
	}
	out := make([]*pending, 0, len(m.open))
	for k, p := range m.open {
		delete(m.open, k)
		r.openN--
		out = append(out, p)
	}
	return out
}

func (r *Relay) finishWaiting(waiting []*pending, status int) {
	for _, p := range waiting {
		if p.timer != nil {
			p.timer.Stop()
		}
		writeStatus(p.w, status, "")
		close(p.done)
	}
}

func (r *Relay) drop(p *peer, code int, reason string) {
	if !p.closing.CompareAndSwap(false, true) {
		return
	}
	closeConn(p.conn, code, reason)
}

func closeConn(conn *websocket.Conn, code int, reason string) {
	_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, reason), time.Now().Add(time.Second))
	_ = conn.Close()
}

func (p *peer) send(kind int, data []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if err := p.conn.SetWriteDeadline(time.Now().Add(maxBufferedWrite)); err != nil {
		return err
	}
	return p.conn.WriteMessage(kind, data)
}

// --------------------------------------------------------------------------
// Watch exchange
// --------------------------------------------------------------------------

func (r *Relay) serveExchange(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	now := r.now()
	addr := clientIP(req, false)
	r.mu.Lock()
	allowed := !r.closed && r.exchanges.allow(addr, now)
	epoch := r.epoch
	rotating := !r.rotateStarted.IsZero()
	r.mu.Unlock()
	if !allowed {
		writeStatus(w, http.StatusTooManyRequests, "")
		return
	}
	target, ok := parseExchange(req.URL.Path)
	media := strings.ToLower(strings.TrimSpace(strings.Split(req.Header.Get("Content-Type"), ";")[0]))
	if !ok || media != "application/octet-stream" {
		writeStatus(w, http.StatusBadRequest, "")
		return
	}
	if !epochOK(target.epoch, epoch, rotating) {
		writeStatus(w, http.StatusConflict, strconv.FormatInt(epoch, 10))
		return
	}
	if cl := req.Header.Get("Content-Length"); cl != "" {
		n, err := strconv.Atoi(cl)
		if err != nil || (n != exchangeOpenBytes && n != exchangeRequestBytes) {
			writeStatus(w, http.StatusBadRequest, "")
			return
		}
	}
	body, err := readLimited(req.Body, exchangeOpenBytes)
	if err != nil || (len(body) != exchangeOpenBytes && len(body) != exchangeRequestBytes) {
		writeStatus(w, http.StatusBadRequest, "")
		return
	}
	r.forward(target, body, w, req)
}

func epochOK(got, current int64, rotating bool) bool {
	if got == current {
		return true
	}
	return rotating && got == current-1
}

func (r *Relay) forward(target exchangeTarget, body []byte, w http.ResponseWriter, req *http.Request) {
	if req.Context().Err() != nil {
		return
	}
	id := make([]byte, ExchangeIDBytes)
	if _, err := rand.Read(id); err != nil {
		writeStatus(w, http.StatusGatewayTimeout, "")
		return
	}
	key := hex.EncodeToString(id)

	r.mu.Lock()
	m := r.rooms[target.handle]
	if m == nil || m.epoch != target.epoch || (m.uplink == nil && m.exchange == nil) {
		r.mu.Unlock()
		writeStatus(w, http.StatusNotFound, "")
		return
	}
	if m.exchange == nil {
		r.mu.Unlock()
		writeStatus(w, http.StatusNotImplemented, "")
		return
	}
	now := r.now()
	if r.openN >= exchangeOpenProcess || len(m.open) >= exchangeOpenPerRoom || !m.rate.take(1, now) {
		r.mu.Unlock()
		writeStatus(w, http.StatusTooManyRequests, "")
		return
	}
	box := m.exchange
	pend := &pending{w: w, done: make(chan struct{})}
	m.open[key] = pend
	r.openN++
	// Armed under the lock, after the row exists. The callback takes the
	// same lock, so it cannot win the race against the insert.
	pend.timer = time.AfterFunc(exchangeTimeout, func() {
		r.settle(m, key, http.StatusGatewayTimeout, nil)
	})
	r.mu.Unlock()
	frame := make([]byte, ExchangeIDBytes+len(body))
	copy(frame, id)
	copy(frame[ExchangeIDBytes:], body)
	if err := box.send(websocket.BinaryMessage, frame); err != nil {
		r.settle(m, key, http.StatusGatewayTimeout, nil)
	}
	select {
	case <-pend.done:
	case <-req.Context().Done():
		r.settle(m, key, 0, nil)
		<-pend.done
	}
}

func (r *Relay) settle(m *room, key string, status int, reply []byte) {
	r.mu.Lock()
	p := m.open[key]
	if p == nil {
		r.mu.Unlock()
		return
	}
	delete(m.open, key)
	r.openN--
	r.mu.Unlock()
	if p.timer != nil {
		p.timer.Stop()
	}
	if status == http.StatusOK {
		p.w.Header().Set("Content-Type", "application/octet-stream")
		p.w.Header().Set("Cache-Control", "no-store")
		p.w.WriteHeader(http.StatusOK)
		_, _ = p.w.Write(reply)
	} else if status != 0 {
		writeStatus(p.w, status, "")
	}
	close(p.done)
}

// --------------------------------------------------------------------------
// Dead man
// --------------------------------------------------------------------------

func (r *Relay) serveDeadman(w http.ResponseWriter, req *http.Request) {
	path := req.URL.Path
	if req.Method == http.MethodPost && (path == "/deadman" || path == "/deadman/") {
		r.postDeadman(w, req)
		return
	}
	if req.Method == http.MethodDelete {
		id := strings.TrimPrefix(path, "/deadman/")
		if deadmanID.MatchString(id) && "/deadman/"+id == path {
			r.dead.remove(id)
			w.WriteHeader(http.StatusNoContent)
			return
		}
	}
	http.NotFound(w, req)
}

func (r *Relay) postDeadman(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	raw, err := readLimited(req.Body, deadmanMaxBody)
	if err != nil {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_, _ = w.Write([]byte(`{"error":"too large"}`))
		return
	}
	var b deadmanIn
	if json.Unmarshal(raw, &b) != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"a JSON object"}`))
		return
	}
	ct, ctErr := base64.StdEncoding.DecodeString(b.CT)
	ctLen := len(ct)
	if ctErr != nil {
		ctLen = 0
		if b.CT != "" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"ct must be base64"}`))
			return
		}
	}
	if fault := putError(b, ctLen); fault != "" {
		code := http.StatusBadRequest
		if fault == "ct too large" {
			code = http.StatusRequestEntityTooLarge
		}
		w.WriteHeader(code)
		raw, _ := json.Marshal(struct {
			Error string `json:"error"`
		}{fault})
		_, _ = w.Write(raw)
		return
	}
	r.dead.put(b)
	w.Header().Del("Content-Type")
	w.WriteHeader(http.StatusNoContent)
}

func readLimited(body io.Reader, max int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(body, int64(max)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > max {
		return nil, errors.New("too large")
	}
	return b, nil
}

func writeStatus(w http.ResponseWriter, status int, body string) {
	if w == nil {
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if body != "" {
		_, _ = io.WriteString(w, body)
	}
}
