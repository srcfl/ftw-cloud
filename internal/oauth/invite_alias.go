package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/srcfl/ftw/go/protocol"
)

const inviteAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
const inviteAliasFor = 10 * time.Minute
const inviteAliasesMax = 4096

type inviteAlias struct {
	proof       protocol.AgentInviteCode
	until       time.Time
	fingerprint [32]byte
}
type inviteAliases struct {
	mu           sync.Mutex
	codes        map[string]inviteAlias
	fingerprints map[[32]byte]string
	random       io.Reader
}

func (a *inviteAliases) pruneLocked(now time.Time) {
	for code, row := range a.codes {
		if !now.Before(row.until) {
			delete(a.codes, code)
			delete(a.fingerprints, row.fingerprint)
		}
	}
}

func (s *Server) pruneInvitationAliases(now time.Time) {
	s.aliases.mu.Lock()
	s.aliases.pruneLocked(now)
	s.aliases.mu.Unlock()
}

func normalizeInviteAlias(raw string) string {
	raw = strings.ToUpper(strings.NewReplacer("-", "", " ", "", "\t", "", "\r", "", "\n", "").Replace(raw))
	if len(raw) != 6 {
		return ""
	}
	for _, ch := range raw {
		if !strings.ContainsRune(inviteAlphabet, ch) {
			return ""
		}
	}
	return raw
}

func (s *Server) currentInvitation(p protocol.AgentInviteCode) (time.Time, bool) {
	if s.Invitation == nil {
		return time.Time{}, false
	}
	return s.Invitation(p.Home, protocol.AgentInviteHash(p.Home, p.Secret), p.Box)
}

// The short code names a strong invitation held only in this process for
// ten minutes. It never replaces the box's 256-bit verifier or Noise proof.
func (s *Server) publishInvitation(p protocol.AgentInviteCode) (string, time.Time, error) {
	until, ok := s.currentInvitation(p)
	if !ok {
		return "", time.Time{}, errors.New("waiting for the box's invitation")
	}
	canonical, err := p.Encode()
	if err != nil {
		return "", time.Time{}, err
	}
	fingerprint := sha256.Sum256([]byte(canonical))
	s.aliases.mu.Lock()
	defer s.aliases.mu.Unlock()
	if s.aliases.codes == nil {
		s.aliases.codes = map[string]inviteAlias{}
		s.aliases.fingerprints = map[[32]byte]string{}
	}
	now := s.now()
	s.aliases.pruneLocked(now)
	if code := s.aliases.fingerprints[fingerprint]; code != "" {
		row := s.aliases.codes[code]
		return code[:3] + "-" + code[3:], row.until, nil
	}
	if len(s.aliases.codes) >= inviteAliasesMax {
		return "", time.Time{}, errors.New("invitation service is busy")
	}
	end := now.Add(inviteAliasFor)
	if until.Before(end) {
		end = until
	}
	for n := 0; n < 32; n++ {
		var random [6]byte
		reader := s.aliases.random
		if reader == nil {
			reader = rand.Reader
		}
		if _, err := io.ReadFull(reader, random[:]); err != nil {
			return "", time.Time{}, err
		}
		var text [6]byte
		for n, b := range random {
			text[n] = inviteAlphabet[int(b)&31]
		}
		code := string(text[:])
		if _, used := s.aliases.codes[code]; used {
			continue
		}
		reserved, err := s.st.reserveInvitationCode(s.route.invitationCodeHash(code), end, now)
		if err != nil {
			return "", time.Time{}, err
		}
		if !reserved {
			continue
		}
		s.aliases.codes[code] = inviteAlias{proof: p, until: end, fingerprint: fingerprint}
		s.aliases.fingerprints[fingerprint] = code
		return code[:3] + "-" + code[3:], end, nil
	}
	return "", time.Time{}, errors.New("could not make an invitation code")
}

// Only spent-code reservations survive a process restart. No alias, home,
// strong secret or bearer mapping is stored. An old unused code cannot name
// a different invitation after a restart while its ten minutes remain.
func (s *store) reserveInvitationCode(sum []byte, until, now time.Time) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM invitation_code_reservations WHERE expires_ms<=?`, now.UnixMilli()); err != nil {
		return false, err
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM invitation_code_reservations`).Scan(&count); err != nil {
		return false, err
	}
	if count >= inviteAliasesMax {
		return false, errors.New("invitation service is busy")
	}
	result, err := tx.Exec(`INSERT OR IGNORE INTO invitation_code_reservations(hash,expires_ms) VALUES(?,?)`, sum, until.UnixMilli())
	if err != nil {
		return false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	return inserted == 1, tx.Commit()
}

func (s *Server) resolveInvitation(raw string) (protocol.AgentInviteCode, error) {
	// The strong format remains an internal publishing proof and lets an
	// older client finish its existing invitation during an update.
	if len(raw) > 16 {
		return protocol.ParseAgentInviteCode(raw)
	}
	code := normalizeInviteAlias(raw)
	s.aliases.mu.Lock()
	s.aliases.pruneLocked(s.now())
	row, ok := s.aliases.codes[code]
	s.aliases.mu.Unlock()
	if !ok || !s.now().Before(row.until) {
		return protocol.AgentInviteCode{}, errors.New("invitation code ended")
	}
	if _, ok := s.currentInvitation(row.proof); !ok {
		return protocol.AgentInviteCode{}, errors.New("waiting for the invitation or its approval")
	}
	return row.proof, nil
}

func (s *Server) servePublishInvitation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	// The body is a bearer proof, never a browser cookie. Public CORS lets
	// a box on a local HTTP address publish it through TLS without a proxy.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if s.limited(&s.invitePublishLimit, s.invitePublishByIP, r) {
		http.Error(w, "Please wait before trying again.", http.StatusTooManyRequests)
		return
	}
	var body struct {
		Invitation string `json:"invitation"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "Invalid invitation.", http.StatusBadRequest)
		return
	}
	p, err := protocol.ParseAgentInviteCode(body.Invitation)
	if err != nil {
		http.Error(w, "Invalid invitation.", http.StatusBadRequest)
		return
	}
	code, until, err := s.publishInvitation(p)
	if err != nil {
		http.Error(w, "Waiting for the box. Keep this page open and retry the same invitation.", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": code, "expiresAtMs": until.UnixMilli()}, false)
}
