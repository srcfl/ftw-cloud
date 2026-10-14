// Package store holds each home's state in memory. Nothing here is written to
// disk: a restart empties it, and boxes fill it again when they reconnect.
//
// The only way to a home is For, with a principal that proves whose home it
// is: the box, by the signed hello on its own connection; a phone in the
// home's roster, by its Noise handshake; or an extension token the registry
// bound to a roster entry. There is no listing, no lookup by anything else,
// and no principal for staff. One bug in a second access path
// would expose every home at once, so there is no second access path.
package store

import (
	"bytes"
	"errors"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// ReadingsKeptFor is how long readings outlive the box's last socket. After
// that a phone gets only when the box was last seen.
const ReadingsKeptFor = time.Hour

// Kind says how a principal proved itself.
type Kind int

const (
	// Box is the box, proven by the hello it signed on this connection.
	Box Kind = iota + 1
	// Device is a phone in the home's roster, proven by its Noise static key.
	Device
	// Token is a widget or an extension, proven by a token the registry
	// bound to one roster entry. It reads only Now.
	Token
)

// Principal is who is asking for a home.
type Principal struct {
	Kind Kind
	Home string
	// DeviceKey is the phone's X25519 static key, for Device.
	DeviceKey []byte
	// DeviceID and Epoch are the roster entry a token is bound to, for
	// Token.
	DeviceID string
	Epoch    uint64
}

// ErrDenied is every refusal. It does not say whether the home exists.
var ErrDenied = errors.New("store: denied")

// ErrBusy is a home with as many phone sessions open as it may have.
var ErrBusy = errors.New("store: busy")

// Store is every home the service holds.
type Store struct {
	mu    sync.Mutex
	homes map[string]*home
	now   func() time.Time
	// suspended reports an owner's suspension of a roster device. Nil
	// suspends nobody.
	suspended func(home, deviceID string, epoch uint64) bool
}

// New starts an empty store. now is for tests; nil uses the clock.
func New(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{homes: map[string]*home{}, now: now}
}

// UseSuspensions sets where owners' suspensions are kept. Call it before
// serving.
func (s *Store) UseSuspensions(suspended func(home, deviceID string, epoch uint64) bool) {
	s.suspended = suspended
}

type home struct {
	mu sync.Mutex
	// latest is the newest envelope of each class, exactly as the box sent
	// it; full is the newest live that carried its source table.
	latest   map[string]Held
	full     *Held
	roster   *cloudwire.Roster
	rosterAt time.Time
	online   bool
	conn     uint64
	lastSeen time.Time
	// sessions are the phones reading this home now.
	sessions map[*Session]struct{}
}

// Held is one envelope as received.
type Held struct {
	T        string
	Envelope []byte
	Seq      uint64
}

// Handle is one principal's access to one home.
type Handle struct {
	s    *Store
	id   string
	h    *home
	kind Kind
	// device is the roster entry a device principal matched, and scopes its
	// effective scope: its roster scopes intersected with the grant's.
	device cloudwire.Device
	scopes []string
}

// For returns the principal's access to its home, or ErrDenied. A box may
// create its home; a device reaches only a home whose current roster lists
// its key, and only while no owner has suspended it. A token reaches it by
// the same rule, through the roster entry it is bound to at that epoch.
func (s *Store) For(p Principal) (*Handle, error) {
	s.mu.Lock()
	h := s.homes[p.Home]
	if h == nil && p.Kind == Box && p.Home != "" {
		h = &home{latest: map[string]Held{}, sessions: map[*Session]struct{}{}}
		s.homes[p.Home] = h
	}
	s.mu.Unlock()
	if h == nil {
		return nil, ErrDenied
	}
	switch p.Kind {
	case Box:
		return &Handle{s: s, id: p.Home, h: h, kind: Box}, nil
	case Device:
		h.mu.Lock()
		defer h.mu.Unlock()
		dev, scopes, ok := s.access(p.Home, h, byKey(p.DeviceKey))
		if !ok {
			return nil, ErrDenied
		}
		return &Handle{s: s, id: p.Home, h: h, kind: Device, device: dev, scopes: scopes}, nil
	case Token:
		h.mu.Lock()
		defer h.mu.Unlock()
		dev, scopes, ok := s.access(p.Home, h, func(d cloudwire.Device) bool {
			return p.DeviceID != "" && d.ID == p.DeviceID && d.Epoch == p.Epoch
		})
		if !ok {
			return nil, ErrDenied
		}
		return &Handle{s: s, id: p.Home, h: h, kind: Token, device: dev, scopes: scopes}, nil
	}
	return nil, ErrDenied
}

// byKey matches the roster entry with a device's Noise static key.
func byKey(key []byte) func(cloudwire.Device) bool {
	return func(d cloudwire.Device) bool { return len(key) == 32 && bytes.Equal(d.Key, key) }
}

// access is the one admission rule for a device: a roster in force that
// lists it, and no suspension. The caller holds h.mu.
func (s *Store) access(id string, h *home, match func(cloudwire.Device) bool) (cloudwire.Device, []string, bool) {
	r := h.roster
	if r == nil || s.now().After(h.rosterAt.Add(time.Duration(r.TTLS)*time.Second)) {
		return cloudwire.Device{}, nil, false
	}
	for _, d := range r.Devices {
		if !match(d) {
			continue
		}
		if s.suspended != nil && s.suspended(id, d.ID, d.Epoch) {
			return cloudwire.Device{}, nil, false
		}
		var scopes []string
		for _, sc := range d.Scopes {
			if slices.Contains(r.Grant.Scopes, sc) {
				scopes = append(scopes, sc)
			}
		}
		return d, scopes, true
	}
	return cloudwire.Device{}, nil, false
}

// --------------------------------------------------------------------------
// The box's handle
// --------------------------------------------------------------------------

// Connected marks the box's socket up and returns its number. A later
// connection replaces this one; Disconnected with an older number is ignored.
func (x *Handle) Connected() uint64 {
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	x.h.conn++
	x.h.online = true
	x.h.lastSeen = x.s.now()
	return x.h.conn
}

// Disconnected marks the socket down, if it is still the current one.
func (x *Handle) Disconnected(conn uint64) {
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	if x.h.conn == conn {
		x.h.online = false
		x.h.lastSeen = x.s.now()
	}
}

// Put keeps env as the newest of its class.
func (x *Handle) Put(t string, env []byte, seq uint64, carriesTable bool) error {
	if x.kind != Box {
		return ErrDenied
	}
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	held := Held{T: t, Envelope: env, Seq: seq}
	x.h.latest[t] = held
	if t == cloudwire.MsgLive && carriesTable {
		x.h.full = &held
	}
	x.h.lastSeen = x.s.now()
	for sess := range x.h.sessions {
		if sess.x.mayRead(t) {
			sess.deliver(env)
		}
	}
	return nil
}

// Roster returns the roster held, and its number, 0 when none.
func (x *Handle) Roster() (*cloudwire.Roster, uint64) {
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	if x.h.roster == nil {
		return nil, 0
	}
	return x.h.roster, x.h.roster.RosterSeq
}

// SetRoster keeps r when its number is at least the one held. An equal
// number renews its time to live.
func (x *Handle) SetRoster(r *cloudwire.Roster) bool {
	if x.kind != Box {
		return false
	}
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	if x.h.roster != nil && r.RosterSeq < x.h.roster.RosterSeq {
		return false
	}
	x.h.roster, x.h.rosterAt = r, x.s.now()
	x.recheckLocked()
	return true
}

// Recheck ends every session whose access is no longer what it was opened
// with, as after an owner suspends a device. The phone reconnects and learns
// its new access, or is refused.
func (x *Handle) Recheck() {
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	x.recheckLocked()
}

func (x *Handle) recheckLocked() {
	for sess := range x.h.sessions {
		dev, scopes, ok := x.s.access(x.id, x.h, byKey(sess.x.device.Key))
		switch {
		case !ok:
			sess.endLocked(cloudwire.CloseDenied)
		case dev.ID != sess.x.device.ID || dev.Epoch != sess.x.device.Epoch || dev.Role != sess.x.device.Role ||
			!slices.Equal(scopes, sess.x.scopes):
			sess.endLocked(cloudwire.CloseChanged)
		}
	}
}

// Delete forgets the home. Only its box may.
func (x *Handle) Delete() {
	if x.kind != Box {
		return
	}
	x.s.mu.Lock()
	delete(x.s.homes, x.id)
	x.s.mu.Unlock()
	x.h.mu.Lock()
	x.h.latest, x.h.full, x.h.roster = map[string]Held{}, nil, nil
	for sess := range x.h.sessions {
		sess.endLocked(cloudwire.CloseDenied)
	}
	x.h.mu.Unlock()
}

// --------------------------------------------------------------------------
// A device's handle
// --------------------------------------------------------------------------

// Snapshot is what a phone gets first: for each class it may read, the
// newest envelope; the newest live that carried sources; and the newest hb,
// in rising seq. After an hour without the box, no readings at all.
type Snapshot struct {
	Envelopes  [][]byte
	LastSeenMs int64
	Online     bool
}

// Snapshot returns the device's view.
func (x *Handle) Snapshot() (Snapshot, error) {
	if x.kind != Device {
		return Snapshot{}, ErrDenied
	}
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	return x.snapshotLocked(), nil
}

func (x *Handle) snapshotLocked() Snapshot { return x.viewLocked(nil) }

// viewLocked is the newest envelope of each class the device may read, of
// only those classes when only is not nil, and the newest live that carried
// sources, in rising seq. The caller holds the home's lock.
func (x *Handle) viewLocked(only []string) Snapshot {
	out := Snapshot{LastSeenMs: x.h.lastSeen.UnixMilli(), Online: x.h.online}
	if !x.h.online && x.s.now().Sub(x.h.lastSeen) > ReadingsKeptFor {
		return out
	}
	var held []Held
	for t, e := range x.h.latest {
		if x.mayRead(t) && (only == nil || slices.Contains(only, t)) {
			held = append(held, e)
		}
	}
	if x.h.full != nil && x.mayRead(cloudwire.MsgLive) && x.h.latest[cloudwire.MsgLive].Seq != x.h.full.Seq {
		held = append(held, *x.h.full)
	}
	sort.Slice(held, func(a, b int) bool { return held[a].Seq < held[b].Seq })
	for _, e := range held {
		out.Envelopes = append(out.Envelopes, e.Envelope)
	}
	return out
}

// NowClasses are what a token reads: the newest live, prices and hb, and the
// newest live that carried sources. Never lp, plan, event, tiles or health.
var NowClasses = []string{cloudwire.MsgLive, cloudwire.MsgPrices, cloudwire.MsgHB}

// Now is what a widget reads with its token: the newest envelope of each of
// NowClasses the device may read, and the newest live that carried sources,
// in rising seq. After an hour without the box, no readings at all.
func (x *Handle) Now() (Snapshot, error) {
	if x.kind != Token {
		return Snapshot{}, ErrDenied
	}
	x.h.mu.Lock()
	defer x.h.mu.Unlock()
	return x.viewLocked(NowClasses), nil
}

func (x *Handle) mayRead(class string) bool {
	scope, forwarded := cloudwire.ClassScope[class]
	return forwarded && (scope == "" || slices.Contains(x.scopes, scope))
}

// --------------------------------------------------------------------------
// Upkeep
// --------------------------------------------------------------------------

// Sweep drops the readings of every home whose box has been gone longer than
// ReadingsKeptFor. What the box was last seen at stays.
func (s *Store) Sweep() {
	now := s.now()
	s.mu.Lock()
	homes := make([]*home, 0, len(s.homes))
	for _, h := range s.homes {
		homes = append(homes, h)
	}
	s.mu.Unlock()
	for _, h := range homes {
		h.mu.Lock()
		if !h.online && now.Sub(h.lastSeen) > ReadingsKeptFor {
			h.latest, h.full = map[string]Held{}, nil
		}
		// A roster that ran out closes the home's sessions: the box has not
		// confirmed who may read for a day.
		if r := h.roster; r != nil && now.After(h.rosterAt.Add(time.Duration(r.TTLS)*time.Second)) {
			for sess := range h.sessions {
				sess.endLocked(cloudwire.CloseDenied)
			}
		}
		h.mu.Unlock()
	}
}

// Forget drops a home the registry has deleted, as after 90 days without a
// roster. It is called by upkeep, never by a request.
func (s *Store) Forget(id string) {
	s.mu.Lock()
	h := s.homes[id]
	delete(s.homes, id)
	s.mu.Unlock()
	if h != nil {
		h.mu.Lock()
		for sess := range h.sessions {
			sess.endLocked(cloudwire.CloseDenied)
		}
		h.mu.Unlock()
	}
}
