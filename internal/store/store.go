// Package store holds each home's state in memory. Nothing here is written to
// disk: a restart empties it, and boxes fill it again when they reconnect.
//
// The only way to a home is For, with a principal that proves whose home it
// is: the box, by the signed hello on its own connection, or a phone in the
// home's roster, by its Noise handshake. There is no listing, no lookup by
// anything else, and no principal for staff. One bug in a second access path
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
)

// Principal is who is asking for a home.
type Principal struct {
	Kind Kind
	Home string
	// DeviceKey is the phone's X25519 static key, for Device.
	DeviceKey []byte
}

// ErrDenied is every refusal. It does not say whether the home exists.
var ErrDenied = errors.New("store: denied")

// Store is every home the service holds.
type Store struct {
	mu    sync.Mutex
	homes map[string]*home
	now   func() time.Time
}

// New starts an empty store. now is for tests; nil uses the clock.
func New(now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{homes: map[string]*home{}, now: now}
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
	// scopes is a device's effective scope: its roster scopes intersected
	// with the grant's.
	scopes []string
}

// For returns the principal's access to its home, or ErrDenied. A box may
// create its home; a device reaches only a home whose current roster lists
// its key.
func (s *Store) For(p Principal) (*Handle, error) {
	s.mu.Lock()
	h := s.homes[p.Home]
	if h == nil && p.Kind == Box && p.Home != "" {
		h = &home{latest: map[string]Held{}}
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
		r := h.roster
		if r == nil || s.now().After(h.rosterAt.Add(time.Duration(r.TTLS)*time.Second)) {
			return nil, ErrDenied
		}
		for _, d := range r.Devices {
			if bytes.Equal(d.Key, p.DeviceKey) && len(p.DeviceKey) == 32 {
				var scopes []string
				for _, sc := range d.Scopes {
					if slices.Contains(r.Grant.Scopes, sc) {
						scopes = append(scopes, sc)
					}
				}
				return &Handle{s: s, id: p.Home, h: h, kind: Device, scopes: scopes}, nil
			}
		}
	}
	return nil, ErrDenied
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
	return true
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
	out := Snapshot{LastSeenMs: x.h.lastSeen.UnixMilli(), Online: x.h.online}
	if !x.h.online && x.s.now().Sub(x.h.lastSeen) > ReadingsKeptFor {
		return out, nil
	}
	var held []Held
	for t, e := range x.h.latest {
		if x.mayRead(t) {
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
	return out, nil
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
		h.mu.Unlock()
	}
}

// Forget drops a home the registry has deleted, as after 90 days without a
// roster. It is called by upkeep, never by a request.
func (s *Store) Forget(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.homes, id)
}
