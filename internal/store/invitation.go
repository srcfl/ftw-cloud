package store

import (
	"bytes"
	"encoding/hex"
	"time"
)

// Invitation checks a strong bearer proof against the current signed hint.
// It grants no session and never consumes a hint.
func (s *Store) Invitation(home string, hash, box []byte) (time.Time, bool) {
	s.mu.Lock()
	h := s.homes[home]
	s.mu.Unlock()
	if h == nil {
		return time.Time{}, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.online || h.roster == nil || !bytes.Equal(h.roster.Noise, box) || !s.now().Before(h.rosterAt.Add(time.Duration(h.roster.TTLS)*time.Second)) {
		return time.Time{}, false
	}
	until, ok := h.invitePending[hex.EncodeToString(hash)]
	return until, ok && s.now().Before(until)
}
