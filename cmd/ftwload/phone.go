package main

import (
	"context"
	"encoding/binary"
	mrand "math/rand/v2"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// lostAfter is how long an echo may take before it counts as lost.
const lostAfter = 5 * time.Second

// phone is one app session: Noise IK to the service, a tun every -cmd that
// the box echoes, and the live the service forwards.
type phone struct {
	b   *box
	key appwire.KeyPair
}

func (p *phone) run(ctx context.Context, at time.Time) {
	select {
	case <-p.b.ready:
	case <-ctx.Done():
		return
	}
	// A little after the roster at least, so the service has taken it.
	if !sleep(ctx, max(time.Until(at), 100*time.Millisecond)) {
		return
	}
	h := p.b.h
	attempt := 0
	for ctx.Err() == nil && !h.stopping.Load() {
		began := time.Now()
		conn, tr, err := p.connect(ctx)
		if err != nil {
			if !h.redial(ctx, "phone."+stepOf(err), err, &attempt) {
				return
			}
			continue
		}
		h.stats.phoneHS.add(time.Since(began))
		attempt = 0
		err = p.session(ctx, conn, tr)
		if !h.redial(ctx, "phone.session", err, &attempt) {
			return
		}
	}
}

// connect opens /v1/app: message 1 carries now{hz:1}, message 2 the
// snapshot, then the Noise transport.
func (p *phone) connect(ctx context.Context) (*websocket.Conn, *appwire.Transport, error) {
	h := p.b.h
	conn, _, err := h.dialer.DialContext(ctx, h.url+"/v1/app?"+cloudwire.AppHomeParam+"="+p.b.home, nil)
	if err != nil {
		return nil, nil, &failure{"dial", err}
	}
	tr, err := p.handshake(conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, &failure{"handshake", err}
	}
	keepAlive(conn)
	return conn, tr, nil
}

func (p *phone) handshake(conn *websocket.Conn) (*appwire.Transport, error) {
	in, err := appwire.NewInitiator(appwire.InitiatorOptions{StaticKey: p.key, RemoteStatic: p.b.h.noise,
		Prologue: cloudwire.AppPrologue(p.b.home)})
	if err != nil {
		return nil, err
	}
	payload, err := cloudwire.Unsigned(cloudwire.MsgNow, cloudwire.Now{Hz: cloudwire.HzLooking})
	if err != nil {
		return nil, err
	}
	msg1, err := in.WriteMessage(payload)
	if err != nil {
		return nil, err
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := conn.WriteMessage(websocket.BinaryMessage, msg1); err != nil {
		return nil, err
	}
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	_, msg2, err := conn.ReadMessage()
	if err != nil {
		return nil, err // a refusal arrives here as a close code
	}
	reply, err := in.ReadMessage(msg2)
	if err != nil {
		return nil, err
	}
	if _, err := cloudwire.ParseSnapshot(reply); err != nil {
		return nil, err
	}
	keys, err := in.Split()
	if err != nil {
		return nil, err
	}
	return appwire.NewTransport(keys), nil
}

// phoneSession is one open app session. sid stays for its life.
type phoneSession struct {
	p    *phone
	conn *websocket.Conn
	tr   *appwire.Transport
	sid  uint32
	seq  uint64

	mu      sync.Mutex
	pending map[uint64]sentTun
}

type sentTun struct {
	at      time.Time
	counted bool
}

func (p *phone) session(ctx context.Context, conn *websocket.Conn, tr *appwire.Transport) error {
	h := p.b.h
	h.up(&h.phonesUp, h.wantPhones, &h.allPhonesAt)
	defer h.phonesUp.Add(-1)
	s := &phoneSession{p: p, conn: conn, tr: tr, sid: mrand.Uint32() | 1, pending: map[uint64]sentTun{}}
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() { s.sendLoop(done) })
	err := s.readLoop()
	_ = conn.Close()
	close(done)
	wg.Wait()
	// What is still out will not come back on another session.
	s.expire(time.Time{})
	return err
}

func (s *phoneSession) sendLoop(done <-chan struct{}) {
	h := s.p.b.h
	t := time.NewTimer(jitter(h.cfg.cmd))
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
		}
		t.Reset(h.cfg.cmd)
		s.expire(time.Now().Add(-lostAfter))
		if h.quiet.Load() {
			continue
		}
		if s.send() != nil {
			return
		}
	}
}

// send writes tun{sid, d}: d is 64 bytes holding a sequence number and the
// send time, which the box echoes unchanged.
func (s *phoneSession) send() error {
	h := s.p.b.h
	s.seq++
	now := time.Now()
	d := make([]byte, 64)
	binary.BigEndian.PutUint64(d[0:], s.seq)
	binary.BigEndian.PutUint64(d[8:], uint64(now.UnixNano()))
	env, err := cloudwire.Unsigned(cloudwire.MsgTun, cloudwire.AppTun{Sid: s.sid, D: d})
	if err != nil {
		return err
	}
	frame, err := cloudwire.EncodeFrame(env)
	if err != nil {
		return err
	}
	msg, err := s.tr.Encrypt(frame)
	if err != nil {
		return err
	}
	counted := h.measuring.Load()
	s.mu.Lock()
	s.pending[s.seq] = sentTun{at: now, counted: counted}
	s.mu.Unlock()
	if counted {
		h.stats.tunSent.Add(1)
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	return s.conn.WriteMessage(websocket.BinaryMessage, msg)
}

// expire counts as lost what was sent before cutoff; a zero cutoff is all.
func (s *phoneSession) expire(cutoff time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for seq, t := range s.pending {
		if cutoff.IsZero() || t.at.Before(cutoff) {
			delete(s.pending, seq)
			if t.counted {
				s.p.b.h.stats.tunLost.Add(1)
			}
		}
	}
}

func (s *phoneSession) readLoop() error {
	for {
		_, msg, err := s.conn.ReadMessage()
		if err != nil {
			return err
		}
		_ = s.conn.SetReadDeadline(time.Now().Add(readTimeout))
		frame, err := s.tr.Decrypt(msg)
		if err != nil {
			return err
		}
		payload, err := cloudwire.DecodeFrame(frame)
		if err != nil {
			return err
		}
		env, err := cloudwire.DecodeEnvelope(payload)
		if err != nil {
			return err
		}
		switch env.T {
		case cloudwire.MsgTun:
			s.echo(env.B)
		case cloudwire.MsgLive:
			s.live(env.B)
		}
	}
}

func (s *phoneSession) echo(body []byte) {
	st := s.p.b.h.stats
	var t cloudwire.AppTun
	if cloudwire.Unmarshal(body, &t) != nil {
		return
	}
	if len(t.D) == 0 {
		st.tunEnded.Add(1) // the service says the box side went
		return
	}
	if t.Sid != s.sid || len(t.D) < 16 {
		return
	}
	seq := binary.BigEndian.Uint64(t.D)
	s.mu.Lock()
	sent, ok := s.pending[seq]
	delete(s.pending, seq)
	s.mu.Unlock()
	switch {
	case !ok:
		st.tunLate.Add(1)
	case sent.counted:
		st.tunEchoed.Add(1)
		st.tunRTT.add(time.Since(sent.at))
	}
}

// live matches a forwarded live to the moment its box sent it.
func (s *phoneSession) live(body []byte) {
	var hdr cloudwire.Header
	if cloudwire.Unmarshal(body, &hdr) != nil {
		return
	}
	b := s.p.b
	b.liveMu.Lock()
	rec := b.sent[hdr.Seq%64]
	b.liveMu.Unlock()
	if rec.seq == hdr.Seq && rec.counted {
		b.h.stats.live.add(time.Since(rec.at))
	}
}
