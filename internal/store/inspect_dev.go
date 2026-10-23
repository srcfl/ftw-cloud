//go:build ftwclouddev

package store

import "strconv"

// Inspect returns every envelope a home holds. It exists only in local test
// binaries built with -tags ftwclouddev, so an end-to-end run can compare
// what the service holds with what the box says it sent. A release build has
// no way to call it.
func (s *Store) Inspect(id string) (latest map[string][]byte, online bool, ok bool) {
	s.mu.Lock()
	h := s.homes[id]
	s.mu.Unlock()
	if h == nil {
		return nil, false, false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	latest = map[string][]byte{}
	for t, e := range h.latest {
		latest[t] = e.Envelope
	}
	if h.full != nil {
		latest["live+sources"] = h.full.Envelope
	}
	for id, c := range h.tiles.closed {
		latest["tiles "+id] = c.env
	}
	for i, p := range h.tiles.open {
		latest["tiles "+p.id+" piece "+strconv.Itoa(i)] = p.env
	}
	return latest, h.online, true
}
