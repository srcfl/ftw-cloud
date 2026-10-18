package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Only the browser that started a request may choose its default rights.
// A client that names scopes keeps exactly that request, without this step.
func (s *Server) modeBrowser(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	rid := r.PathValue("rid")
	id, err := base64.RawURLEncoding.DecodeString(rid)
	if err != nil || len(id) != 16 || (r.Method == http.MethodPost && r.Header.Get("Origin") != Issuer) {
		http.Error(w, "Open this connection page from your assistant.", http.StatusForbidden)
		return "", "", false
	}
	ck, err := r.Cookie(cookieName(rid))
	if err != nil || !s.st.browserMatches(rid, ck.Value) {
		http.Error(w, "Return to the browser that started this connection.", http.StatusForbidden)
		return "", "", false
	}
	return rid, ck.Value, true
}

func (s *Server) serveConnect(w http.ResponseWriter, r *http.Request) {
	rid, _, ok := s.modeBrowser(w, r)
	if !ok {
		return
	}
	c, exists, err := s.st.consentByRID(rid)
	if err != nil || !exists {
		http.NotFound(w, r)
		return
	}
	if c.Status == statusDenied || !s.now().Before(c.Expires) {
		s.authorizePage(w, http.StatusGone, pageError{Title: "Connect again", Text: "This request ended. Start a new connection from your assistant."})
		return
	}
	s.consentPage(w, rid, c)
}

func (s *Server) serveMode(w http.ResponseWriter, r *http.Request) {
	rid, browser, ok := s.modeBrowser(w, r)
	if !ok {
		return
	}
	var body struct {
		Mode string `json:"mode"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil || d.Decode(new(any)) != io.EOF || (body.Mode != "read" && body.Mode != "setup") {
		http.Error(w, "Choose read and troubleshoot, or set up and configure.", http.StatusBadRequest)
		return
	}
	c, exists, err := s.st.consentByRID(rid)
	if err != nil || !exists {
		http.NotFound(w, r)
		return
	}
	if (c.Status != statusPending && c.Status != statusApproved) || !s.now().Before(c.Expires) {
		http.Error(w, "This request ended. Connect again from your assistant.", http.StatusGone)
		return
	}
	scopes := slices.Clone(ReadScopes)
	if body.Mode == "setup" {
		scopes = append(scopes, ScopeSetupWrite)
	}
	wanted := strings.Join(scopes, " ")
	if c.Status == statusPending && c.Scope == "" && c.Offer == "" {
		if s.limited(&s.authorizeLimit, s.authorizeByIP, r) {
			w.Header().Set("Retry-After", "10")
			http.Error(w, "FTW Cloud is busy connecting assistants. Try the same choice again shortly.", http.StatusTooManyRequests)
			return
		}
		// Signing can wait on the key process. Do it outside SQLite's lock;
		// the write below checks the browser, phase and deadline again.
		c.Scope = wanted
		ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
		defer cancel()
		c.Offer, err = s.signOffer(ctx, c.Kid, buildOffer(c))
		if err != nil {
			http.Error(w, "The choice was not saved. Try the same choice again.", http.StatusServiceUnavailable)
			return
		}
		_, err = s.st.db.Exec(`UPDATE requests SET scope = ?, offer = ?
			WHERE rid = ? AND browser = ? AND scope = '' AND offer = '' AND status = ? AND expires_ms > ?`,
			c.Scope, c.Offer, hash(rid), hash(browser), statusPending, s.now().UnixMilli())
		if err != nil {
			http.Error(w, "The choice is not confirmed. Try the same choice again.", http.StatusServiceUnavailable)
			return
		}
		c, exists, err = s.st.consentByRID(rid)
		if err != nil || !exists {
			http.Error(w, "The choice is not confirmed. Try the same choice again.", http.StatusServiceUnavailable)
			return
		}
	}
	if (c.Status != statusPending && c.Status != statusApproved) || !s.now().Before(c.Expires) {
		http.Error(w, "This request ended. Connect again from your assistant.", http.StatusGone)
		return
	}
	if c.Offer == "" {
		http.Error(w, "This request is incomplete. Connect again from your assistant.", http.StatusGone)
		return
	}
	status := http.StatusOK
	state := "ready"
	if c.Scope != wanted {
		status, state = http.StatusConflict, "choice_locked"
	}
	writeJSON(w, status, map[string]string{"state": state, "connect": "/oauth/requests/" + rid + "/connect"}, false)
}
