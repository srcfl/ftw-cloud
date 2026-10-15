package mcp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/srcfl/ftw-cloud/internal/oauth"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// An agent's session with its box. One warm session per agent of a home:
// the first call opens it (a handshake, one round trip to the box), later
// calls ride it (one round trip each), and it closes after a short idle
// time. Calls on one session go one at a time, so calls on one home wait
// their turn, a few at most.

// Door carries tun to a home's box: package uplink.
type Door interface {
	Tun(home string, t cloudwire.Tun) bool
}

// Keys is the keys part, as the MCP server uses it: package keys.
type Keys interface {
	Open(ctx context.Context, kid string, boxStatic []byte) (sess string, msg1 []byte, err error)
	Finish(ctx context.Context, sess string, msg2 []byte) error
	Seal(ctx context.Context, sess string, frame []byte) ([]byte, error)
	Unseal(ctx context.Context, sess string, msg []byte) ([]byte, error)
	End(ctx context.Context, sess string) error
}

// BoxKey gives a home's box Noise static key, which an agent's session is
// opened to. It comes from the box, signed; false means the box has not
// said, and takes no agents yet.
type BoxKey func(home string) ([]byte, bool)

// Pool holds the warm agent sessions of one process.
type Pool struct {
	store  *store.Store
	door   Door
	keys   Keys
	boxKey BoxKey
	log    *slog.Logger
	now    func() time.Time

	// Handshake bounds the wait for the box's message 2; a box that
	// refuses an agent sends none. Idle closes a quiet session. Call bounds
	// one request.
	Handshake, Idle, Call time.Duration
	// PaceBurst and PacePerSecond are each home's budget of calls.
	PaceBurst, PacePerSecond float64

	mu    sync.Mutex
	conns map[connKey]*agentConn
	paces map[string]*pacer
}

type connKey struct{ home, agent string }

// Limits.
const (
	// maxConns bounds the warm sessions in one process; past it the least
	// recently used closes.
	maxConns = 1024
	// maxWaiting bounds the calls queued on one session.
	maxWaiting = 4
	// maxAnswer bounds what one history query may return; every other read
	// fits one 16 KiB frame.
	maxAnswer = 1 << 20
)

// NewPool builds the pool. Run sweeps it.
func NewPool(st *store.Store, door Door, keys Keys, boxKey BoxKey, log *slog.Logger) *Pool {
	if log == nil {
		log = slog.Default()
	}
	return &Pool{store: st, door: door, keys: keys, boxKey: boxKey, log: log, now: time.Now,
		Handshake: 5 * time.Second, Idle: 60 * time.Second, Call: 15 * time.Second, PaceBurst: PaceBurst, PacePerSecond: PacePerSecond,
		conns: map[connKey]*agentConn{},
		paces: map[string]*pacer{}}
}

type pool = Pool

// Run closes idle sessions until ctx ends.
func (p *Pool) Run(ctx context.Context) {
	t := time.NewTicker(max(p.Idle/4, time.Second))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			p.closeAll()
			return
		case <-t.C:
			p.sweep()
		}
	}
}

func (p *Pool) sweep() {
	now := p.now()
	p.mu.Lock()
	var idle []*agentConn
	for k, c := range p.conns {
		if c.idleSince(now) > p.Idle {
			idle = append(idle, c)
			delete(p.conns, k)
		}
	}
	p.forgetFullPacesLocked(now)
	p.mu.Unlock()
	for _, c := range idle {
		c.close(errIdle)
	}
}

func (p *Pool) closeAll() {
	p.mu.Lock()
	all := p.conns
	p.conns = map[connKey]*agentConn{}
	p.mu.Unlock()
	for _, c := range all {
		c.close(errIdle)
	}
}

// Drop closes an agent's session at once: its owner removed it.
func (p *Pool) Drop(home, agent string) {
	p.mu.Lock()
	c := p.conns[connKey{home, agent}]
	delete(p.conns, connKey{home, agent})
	p.mu.Unlock()
	if c != nil {
		c.close(errRevoked)
	}
}

// Warm is how many sessions are open, for tests and the log.
func (p *Pool) Warm() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.conns)
}

// get returns the agent's session, opening one if none is warm.
func (p *Pool) get(ctx context.Context, sub oauth.Subject) (*agentConn, error) {
	k := connKey{sub.Home, sub.Agent}
	p.mu.Lock()
	c := p.conns[k]
	if c != nil && !c.ended() {
		p.mu.Unlock()
		select {
		case <-c.ready:
		case <-ctx.Done():
			return nil, errTimeout
		}
		if c.openErr != nil {
			return nil, c.openErr
		}
		return c, nil
	}
	if len(p.conns) >= maxConns {
		p.evictLocked()
	}
	c = &agentConn{p: p, home: sub.Home, agent: sub.Agent, ready: make(chan struct{}), done: make(chan struct{}),
		turn: make(chan struct{}, 1), waiting: map[uint32]chan appwire.Envelope{}, byCmd: map[string]chan appwire.Envelope{},
		helloReady: make(chan struct{}), used: p.now()}
	p.conns[k] = c
	p.mu.Unlock()

	c.openErr = c.open(ctx, sub)
	if c.openErr == nil && c.ended() {
		// Dropped or evicted while it opened.
		c.openErr = c.closeErr
	}
	close(c.ready)
	if c.openErr != nil {
		p.mu.Lock()
		if p.conns[k] == c {
			delete(p.conns, k)
		}
		p.mu.Unlock()
		c.close(c.openErr)
		return nil, c.openErr
	}
	return c, nil
}

func (p *Pool) evictLocked() {
	var oldest connKey
	var at time.Time
	for k, c := range p.conns {
		c.mu.Lock()
		u := c.used
		c.mu.Unlock()
		if at.IsZero() || u.Before(at) {
			oldest, at = k, u
		}
	}
	if c := p.conns[oldest]; c != nil {
		delete(p.conns, oldest)
		go c.close(errIdle)
	}
}

// Errors a tool turns into words for the model.
var (
	errNoAgents = userError("This box does not take assistants yet; it needs a newer FTW version.")
	errDenied   = userError("The box no longer lets this assistant in. Its owner may have removed it.")
	errBusy     = userError("This home is busy with other calls. Try again in a moment.")
	errOffline  = userError("The box is offline right now.")
	errNoAnswer = userError("The box did not answer. It may be offline, or its owner removed this assistant.")
	errTimeout  = userError("The box took too long to answer.")
	errEnded    = userError("The box ended the session. Try again.")
	errRevoked  = userError("The owner removed this assistant.")
	errExpired  = userError("This assistant's access ran out. The owner can renew it in the FTW app.")
	errIdle     = errors.New("mcp: idle")
)

// agentConn is one agent's session with its box.
type agentConn struct {
	p           *Pool
	home, agent string

	ready   chan struct{}
	openErr error
	// turn is held by the one call on the session.
	turn chan struct{}
	done chan struct{}
	msg2 chan []byte
	// opened closes when the handshake is done; the fields open sets
	// happen before it.
	opened chan struct{}

	mu sync.Mutex
	// What open acquires, set under mu and only while the session is not
	// closing, so a close in the middle of an open releases what exists.
	dev      string
	sess     *store.Session
	ksess    string
	sid      uint32
	closing  bool
	closeErr error
	queued   int
	used     time.Time
	nextID   uint32
	waiting  map[uint32]chan appwire.Envelope
	byCmd    map[string]chan appwire.Envelope
	// hello is the box's answer to this session's hello, or helloErr its
	// refusal (a box without a clock refuses agents); helloReady closes
	// when either comes.
	helloID    uint32
	hello      *protocol.HelloOK
	helloErr   error
	helloAt    time.Time
	helloReady chan struct{}
	// rev is the controlRev the box last named; 0 is not known yet.
	rev uint64
}

// adopt records what open acquired, unless the session is already closing:
// then the caller releases it.
func (c *agentConn) adopt(set func()) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closing {
		return false
	}
	set()
	return true
}

func (c *agentConn) ended() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

func (c *agentConn) idleSince(now time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.queued > 0 {
		return 0
	}
	return now.Sub(c.used)
}

// open runs the handshake: admission by the box's roster here, message 1
// from the keys part, message 2 from the box. Then hello goes, without
// waiting for its answer.
func (c *agentConn) open(ctx context.Context, sub oauth.Subject) error {
	boxStatic, ok := c.p.boxKey(sub.Home)
	if !ok {
		return errNoAgents
	}
	h, err := c.p.store.For(store.Principal{Kind: store.Agent, Home: sub.Home, DeviceKey: sub.Key})
	if err != nil {
		return errDenied
	}
	_, sess, err := h.Open()
	if errors.Is(err, store.ErrBusy) {
		return errBusy
	}
	if err != nil {
		return errDenied
	}
	var b [4]byte
	var sid uint32
	for sid == 0 {
		_, _ = rand.Read(b[:])
		sid = binary.BigEndian.Uint32(b[:])
	}
	sess.SetSid(sid)
	dev := h.Device().ID
	if !c.adopt(func() { c.sess, c.dev, c.sid = sess, dev, sid }) {
		sess.Close()
		return errEnded
	}
	c.msg2, c.opened = make(chan []byte, 1), make(chan struct{})
	go c.read(sess, sid)

	ksess, msg1, err := c.p.keys.Open(ctx, sub.Kid, boxStatic)
	if err != nil {
		c.p.log.Warn("the keys part could not open an agent session", "err", err)
		return userError("FTW Cloud could not open a session for this assistant.")
	}
	if !c.adopt(func() { c.ksess = ksess }) {
		end, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = c.p.keys.End(end, ksess)
		cancel()
		return errEnded
	}
	if !c.p.door.Tun(sub.Home, cloudwire.Tun{Dev: dev, Sid: sid, D: msg1}) {
		return errOffline
	}
	t := time.NewTimer(c.p.Handshake)
	defer t.Stop()
	var msg2 []byte
	select {
	case msg2 = <-c.msg2:
	case <-c.done:
		return errNoAnswer
	case <-t.C:
		return errNoAnswer
	case <-ctx.Done():
		return errTimeout
	}
	if err := c.p.keys.Finish(ctx, ksess, msg2); err != nil {
		return errNoAnswer
	}
	close(c.opened)
	// hello carries an id, so a refusal (no clock on the box) reaches the
	// calls waiting for it rather than being dropped.
	id := c.newID()
	c.mu.Lock()
	c.helloID = id
	c.mu.Unlock()
	hello := protocol.Hello{Proto: protocol.ProtoRange{Min: protocol.ProtoMin, Max: protocol.ProtoMax},
		App: protocol.AppInfo{Build: "ftw-cloud-mcp/" + ServerVersion, UA: "FTW Cloud MCP"}, Locales: []string{"en"}}
	return c.send(ctx, protocol.MsgHello, &id, hello)
}

// endHello records the box's answer to hello, once. The caller holds c.mu.
func (c *agentConn) endHelloLocked(h *protocol.HelloOK, err error) {
	if c.hello != nil || c.helloErr != nil {
		return
	}
	c.hello, c.helloErr, c.helloAt = h, err, c.p.now()
	close(c.helloReady)
}

// read takes the box's side of the session off the door, and the copy's
// envelopes, which an agent session does not read.
func (c *agentConn) read(sess *store.Session, sid uint32) {
	handshook := false
	for {
		select {
		case <-c.done:
			return
		case <-sess.Done():
			c.close(errEnded)
			return
		case <-sess.C():
		case t := <-sess.Tun():
			if t.Sid != sid {
				continue
			}
			if len(t.D) == 0 {
				c.close(errEnded)
				return
			}
			if !handshook {
				handshook = true
				c.msg2 <- t.D
				// Transport messages wait for the handshake to finish.
				select {
				case <-c.opened:
				case <-c.done:
					return
				}
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			frame, err := c.p.keys.Unseal(ctx, c.ksess, t.D)
			cancel()
			if err != nil {
				continue
			}
			f, err := appwire.DecodeFrame(frame)
			if err != nil {
				continue
			}
			c.dispatch(f.Envelope)
		}
	}
}

// dispatch hands one message to the call waiting for it.
func (c *agentConn) dispatch(env appwire.Envelope) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch env.T {
	case protocol.MsgHelloOK:
		var h protocol.HelloOK
		if cbor.Unmarshal(env.B, &h) == nil {
			c.endHelloLocked(&h, nil)
		}
		return
	case protocol.MsgError:
		if env.ID != nil && *env.ID == c.helloID {
			c.endHelloLocked(nil, decodeBoxError(env.B))
			return
		}
	case protocol.MsgSessionTerminate:
		var st protocol.SessionTerminate
		_ = cbor.Unmarshal(env.B, &st)
		go c.close(terminated(st.Reason))
		return
	case protocol.MsgCmdAck, protocol.MsgCmdResult:
		var b struct {
			CmdID string `cbor:"cmdId"`
		}
		if cbor.Unmarshal(env.B, &b) == nil {
			if ch := c.byCmd[b.CmdID]; ch != nil {
				select {
				case ch <- env:
				default:
				}
				return
			}
		}
	}
	// Every answer carries its request's id. A message without one that is
	// not above (agent.decided, the box telling an open session how a
	// request ended) answers no call; requests.list reads the same.
	if env.ID == nil {
		return
	}
	if ch := c.waiting[*env.ID]; ch != nil {
		select {
		case ch <- env:
		default:
			// A call that cannot keep up has failed anyway.
		}
	}
}

// send seals one message and puts it on the door.
func (c *agentConn) send(ctx context.Context, t string, id *uint32, body any) error {
	raw, err := appwire.MarshalBody(body)
	if err != nil {
		return err
	}
	var frame []byte
	for _, bucket := range appwire.BulkBuckets {
		frame, err = appwire.EncodeFrame(appwire.Frame{Lane: appwire.LaneBulk, Bucket: bucket,
			Envelope: appwire.Envelope{T: t, ID: id, B: raw}})
		if err == nil {
			break
		}
	}
	if err != nil {
		return userError("The request is too large for the box.")
	}
	c.mu.Lock()
	ksess, dev, sid := c.ksess, c.dev, c.sid
	c.mu.Unlock()
	msg, err := c.p.keys.Seal(ctx, ksess, frame)
	if err != nil {
		go c.close(errEnded)
		return errEnded
	}
	if !c.p.door.Tun(c.home, cloudwire.Tun{Dev: dev, Sid: sid, D: msg}) {
		go c.close(errOffline)
		return errOffline
	}
	return nil
}

// take waits for the session's turn. At most maxWaiting calls wait.
func (c *agentConn) take(ctx context.Context) (func(), error) {
	c.mu.Lock()
	if c.queued >= maxWaiting {
		c.mu.Unlock()
		return nil, errBusy
	}
	c.queued++
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.queued--
		c.used = c.p.now()
		c.mu.Unlock()
	}()
	if err := c.p.pace(c.home).wait(ctx, c.p.now); err != nil {
		return nil, err
	}
	select {
	case c.turn <- struct{}{}:
		return func() {
			c.mu.Lock()
			c.used = c.p.now()
			c.mu.Unlock()
			<-c.turn
		}, nil
	case <-c.done:
		return nil, c.closeErr
	case <-ctx.Done():
		return nil, errTimeout
	}
}

func (c *agentConn) register(id uint32) chan appwire.Envelope {
	ch := make(chan appwire.Envelope, 256)
	c.mu.Lock()
	c.waiting[id] = ch
	c.mu.Unlock()
	return ch
}

func (c *agentConn) unregister(id uint32) {
	c.mu.Lock()
	delete(c.waiting, id)
	c.mu.Unlock()
}

func (c *agentConn) newID() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	return c.nextID
}

// close ends the session for good: the box hears it ended, the keys part
// drops its keys, the store frees the slot. It may run while open still
// works: what open has acquired is released here, and what it acquires
// later open releases itself.
func (c *agentConn) close(why error) {
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return
	}
	c.closing = true
	tellBox := why != errEnded
	if why == errIdle || why == nil {
		why = errEnded
	}
	c.closeErr = why
	sid, dev, ksess, sess := c.sid, c.dev, c.ksess, c.sess
	c.mu.Unlock()
	close(c.done)
	if sid != 0 && tellBox {
		c.p.door.Tun(c.home, cloudwire.Tun{Dev: dev, Sid: sid})
	}
	if ksess != "" {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = c.p.keys.End(ctx, ksess)
		cancel()
	}
	if sess != nil {
		sess.Close()
	}
	c.p.mu.Lock()
	if k := (connKey{c.home, c.agent}); c.p.conns[k] == c {
		delete(c.p.conns, k)
	}
	c.p.mu.Unlock()
}

// terminated is why the box ended a session, in words.
func terminated(reason string) error {
	switch reason {
	case protocol.TerminateRevoked:
		return errRevoked
	case protocol.TerminateExpired:
		return errExpired
	case protocol.TerminateSuperseded, "replaced":
		return userError("Another session of this assistant took over. Try again.")
	case protocol.TerminateBoxShutdown:
		return userError("The box is restarting. Try again in a minute.")
	}
	return errEnded
}

// --------------------------------------------------------------------------
// Requests
// --------------------------------------------------------------------------

// boxError is the box refusing a request, by its registry code.
type boxError struct {
	Code string
	Args map[string]any
}

func (e boxError) Error() string { return "box: " + e.Code }

// ask sends one request on the session and waits for its answer: the next
// message with the request's id, or an error. The box answers an agent's
// reads with messages of their own (docs/agents.md, "What each scope
// opens"); api.req, the passthrough, is refused to agents.
func (c *agentConn) ask(ctx context.Context, t string, body any) (appwire.Envelope, error) {
	release, err := c.take(ctx)
	if err != nil {
		return appwire.Envelope{}, err
	}
	defer release()
	id := c.newID()
	ch := c.register(id)
	defer c.unregister(id)
	if err := c.send(ctx, t, &id, body); err != nil {
		return appwire.Envelope{}, err
	}
	select {
	case env := <-ch:
		if env.T == protocol.MsgError {
			return env, decodeBoxError(env.B)
		}
		c.p.pace(c.home).spend(len(env.B), c.p.now())
		return env, nil
	case <-c.done:
		return appwire.Envelope{}, c.closeErr
	case <-ctx.Done():
		// The box may still be working on it; a fresh session is the
		// clean way on.
		c.close(errTimeout)
		return appwire.Envelope{}, errTimeout
	}
}

// hist runs one history query: hist.chunk tiles until hist.end.
func (c *agentConn) hist(ctx context.Context, q protocol.HistQuery) ([]protocol.HistChunk, protocol.HistEnd, error) {
	release, err := c.take(ctx)
	if err != nil {
		return nil, protocol.HistEnd{}, err
	}
	defer release()
	id := c.newID()
	ch := c.register(id)
	defer c.unregister(id)
	if err := c.send(ctx, protocol.MsgHistQuery, &id, q); err != nil {
		return nil, protocol.HistEnd{}, err
	}
	var chunks []protocol.HistChunk
	size := 0
	for {
		select {
		case env := <-ch:
			switch env.T {
			case protocol.MsgHistChunk:
				var hc protocol.HistChunk
				if cbor.Unmarshal(env.B, &hc) != nil {
					return nil, protocol.HistEnd{}, errEnded
				}
				if size += len(env.B); size > maxAnswer {
					return nil, protocol.HistEnd{}, userError("The box's answer is too large. Ask for less.")
				}
				chunks = append(chunks, hc)
			case protocol.MsgHistEnd:
				var end protocol.HistEnd
				_ = cbor.Unmarshal(env.B, &end)
				c.p.pace(c.home).spend(size, c.p.now())
				return chunks, end, nil
			case protocol.MsgError:
				return nil, protocol.HistEnd{}, decodeBoxError(env.B)
			}
		case <-c.done:
			return nil, protocol.HistEnd{}, c.closeErr
		case <-ctx.Done():
			c.close(errTimeout)
			return nil, protocol.HistEnd{}, errTimeout
		}
	}
}

func decodeBoxError(b []byte) error {
	var e protocol.ErrorBody
	if cbor.Unmarshal(b, &e) != nil {
		return errEnded
	}
	return boxError{Code: e.Code, Args: e.Args}
}

// helloOK waits briefly for the box's hello_ok on this session.
func (c *agentConn) helloOK(ctx context.Context) (*protocol.HelloOK, time.Time, error) {
	select {
	case <-c.helloReady:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.hello, c.helloAt, c.helloErr
	case <-c.done:
		return nil, time.Time{}, c.closeErr
	case <-ctx.Done():
		return nil, time.Time{}, errTimeout
	}
}
