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
// time. The box serves one request per session at a time, so calls on one
// home wait their turn, a few at most.

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

	mu    sync.Mutex
	conns map[connKey]*agentConn
}

type connKey struct{ home, agent string }

// Limits.
const (
	// maxConns bounds the warm sessions in one process; past it the least
	// recently used closes.
	maxConns = 1024
	// maxWaiting bounds the calls queued on one session.
	maxWaiting = 4
	// maxAnswer bounds what one api.req may return.
	maxAnswer = 1 << 20
)

// NewPool builds the pool. Run sweeps it.
func NewPool(st *store.Store, door Door, keys Keys, boxKey BoxKey, log *slog.Logger) *Pool {
	if log == nil {
		log = slog.Default()
	}
	return &Pool{store: st, door: door, keys: keys, boxKey: boxKey, log: log, now: time.Now,
		Handshake: 5 * time.Second, Idle: 60 * time.Second, Call: 15 * time.Second, conns: map[connKey]*agentConn{}}
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
	errIdle     = errors.New("mcp: idle")
)

// agentConn is one agent's session with its box.
type agentConn struct {
	p           *Pool
	home, agent string
	dev         string
	handle      *store.Handle
	sess        *store.Session
	ksess       string
	sid         uint32

	ready   chan struct{}
	openErr error
	// turn is held by the one call on the session.
	turn     chan struct{}
	queued   int
	done     chan struct{}
	closeErr error
	once     sync.Once
	msg2     chan []byte
	// opened closes when the handshake is done.
	opened chan struct{}

	mu      sync.Mutex
	used    time.Time
	nextID  uint32
	waiting map[uint32]chan appwire.Envelope
	byCmd   map[string]chan appwire.Envelope
	hello   *protocol.HelloOK
	helloAt time.Time
	// helloReady closes when hello_ok arrives.
	helloReady chan struct{}
	// rev is the controlRev the box last named.
	rev uint64
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
	h, err := c.p.store.For(store.Principal{Kind: store.Device, Home: sub.Home, DeviceKey: sub.Key})
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
	c.handle, c.sess, c.dev = h, sess, h.Device().ID
	var b [4]byte
	for c.sid == 0 {
		_, _ = rand.Read(b[:])
		c.sid = binary.BigEndian.Uint32(b[:])
	}
	sess.SetSid(c.sid)
	c.msg2, c.opened = make(chan []byte, 1), make(chan struct{})
	go c.read()

	ksess, msg1, err := c.p.keys.Open(ctx, sub.Kid, boxStatic)
	if err != nil {
		c.p.log.Warn("the keys part could not open an agent session", "err", err)
		return userError("FTW Cloud could not open a session for this assistant.")
	}
	c.ksess = ksess
	if !c.p.door.Tun(sub.Home, cloudwire.Tun{Dev: c.dev, Sid: c.sid, D: msg1}) {
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
	hello := protocol.Hello{Proto: protocol.ProtoRange{Min: protocol.ProtoMin, Max: protocol.ProtoMax},
		App: protocol.AppInfo{Build: "ftw-cloud-mcp/" + ServerVersion, UA: "FTW Cloud MCP"}, Locales: []string{"en"}}
	return c.send(ctx, protocol.MsgHello, nil, hello)
}

// read takes the box's side of the session off the door, and the copy's
// envelopes, which an agent session does not read.
func (c *agentConn) read() {
	handshook := false
	for {
		select {
		case <-c.done:
			return
		case <-c.sess.Done():
			c.close(errEnded)
			return
		case <-c.sess.C():
		case t := <-c.sess.Tun():
			if t.Sid != c.sid {
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
		if cbor.Unmarshal(env.B, &h) == nil && c.hello == nil {
			c.hello, c.helloAt = &h, c.p.now()
			close(c.helloReady)
		}
		return
	case protocol.MsgSessionTerminate:
		go c.close(errRevoked)
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
	if env.ID != nil {
		if ch := c.waiting[*env.ID]; ch != nil {
			select {
			case ch <- env:
			default:
				// A call that cannot keep up has failed anyway.
			}
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
	msg, err := c.p.keys.Seal(ctx, c.ksess, frame)
	if err != nil {
		go c.close(errEnded)
		return errEnded
	}
	if !c.p.door.Tun(c.home, cloudwire.Tun{Dev: c.dev, Sid: c.sid, D: msg}) {
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
// drops its keys, the store frees the slot.
func (c *agentConn) close(why error) {
	c.once.Do(func() {
		c.closeErr = why
		if c.closeErr == errIdle || c.closeErr == nil {
			c.closeErr = errEnded
		}
		close(c.done)
		if c.sid != 0 && why != errEnded {
			c.p.door.Tun(c.home, cloudwire.Tun{Dev: c.dev, Sid: c.sid})
		}
		if c.ksess != "" {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = c.p.keys.End(ctx, c.ksess)
			cancel()
		}
		if c.sess != nil {
			c.sess.Close()
		}
		c.p.mu.Lock()
		if k := (connKey{c.home, c.agent}); c.p.conns[k] == c {
			delete(c.p.conns, k)
		}
		c.p.mu.Unlock()
	})
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

// apiAnswer is one answer from the box's own HTTP API.
type apiAnswer struct {
	Status  int
	Headers map[string]string
	Body    []byte
}

// api runs one request against the box's HTTP API, over api.req.
func (c *agentConn) api(ctx context.Context, method, path string, query map[string]string, body []byte) (apiAnswer, error) {
	release, err := c.take(ctx)
	if err != nil {
		return apiAnswer{}, err
	}
	defer release()
	id := c.newID()
	ch := c.register(id)
	defer c.unregister(id)
	req := protocol.APIReq{Method: method, Path: path, Query: query, Body: body, MaxBytes: maxAnswer}
	if err := c.send(ctx, protocol.MsgAPIReq, &id, req); err != nil {
		return apiAnswer{}, err
	}
	var ans apiAnswer
	var next uint32
	for {
		select {
		case env := <-ch:
			switch env.T {
			case protocol.MsgAPIHead:
				var h protocol.APIHeadMsg
				if cbor.Unmarshal(env.B, &h) != nil {
					return ans, errEnded
				}
				ans.Status, ans.Headers = h.Status, h.Headers
			case protocol.MsgAPIChunk:
				var ck protocol.APIChunk
				if cbor.Unmarshal(env.B, &ck) != nil || ck.Seq != next {
					c.close(errEnded)
					return ans, userError("Part of the box's answer was lost. Try again.")
				}
				next++
				if len(ans.Body)+len(ck.Data) > maxAnswer {
					return ans, userError("The box's answer is too large. Ask for less.")
				}
				ans.Body = append(ans.Body, ck.Data...)
			case protocol.MsgAPIEnd:
				var end protocol.APIEnd
				if cbor.Unmarshal(env.B, &end) == nil && end.Truncated {
					return ans, userError("The box's answer is too large. Ask for less.")
				}
				return ans, nil
			case protocol.MsgError:
				return ans, decodeBoxError(env.B)
			}
		case <-c.done:
			return ans, c.closeErr
		case <-ctx.Done():
			// The box may still be working on it; a fresh session is the
			// clean way on.
			c.close(errTimeout)
			return ans, errTimeout
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
		return c.hello, c.helloAt, nil
	case <-c.done:
		return nil, time.Time{}, c.closeErr
	case <-ctx.Done():
		return nil, time.Time{}, errTimeout
	}
}
