package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/srcfl/ftw/go/protocol"
)

// InviteClaim holds one browser's claim only in memory. Neither its bearer
// secret nor its encrypted handshake payload belongs in OAuth storage.
type InviteClaim struct {
	Home, Kid               string
	Key, Box, Hash, Payload []byte
}

func (s *Server) serveInvite(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	rid := r.PathValue("rid")
	id, err := base64.RawURLEncoding.DecodeString(rid)
	if err != nil || len(id) != 16 || r.Header.Get("Origin") != Issuer {
		http.Error(w, "Open this connection page from your assistant.", http.StatusForbidden)
		return
	}
	ck, err := r.Cookie(cookieName(rid))
	if err != nil || !s.st.browserMatches(rid, ck.Value) {
		http.Error(w, "Return to the browser that started this connection.", http.StatusForbidden)
		return
	}
	if s.limited(&s.inviteClaimLimit, s.inviteClaimByIP, r) {
		http.Error(w, "Too many attempts. Try again shortly.", http.StatusTooManyRequests)
		return
	}
	c, ok, err := s.st.consentByRID(rid)
	if err != nil || !ok {
		http.NotFound(w, r)
		return
	}
	if c.Status == statusApproved {
		writeJSON(w, http.StatusOK, map[string]string{"state": "approved"}, false)
		return
	}
	if c.Status != statusPending || !s.now().Before(c.Expires) {
		http.Error(w, "This connection request ended. Connect again from your assistant.", http.StatusGone)
		return
	}
	if c.Offer == "" {
		http.Error(w, "Choose what this connection is for first.", http.StatusConflict)
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	d.DisallowUnknownFields()
	if d.Decode(&body) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "Paste the invitation code from the owner.", http.StatusBadRequest)
		return
	}
	code, err := s.resolveInvitation(strings.TrimSpace(body.Code))
	if err != nil {
		http.Error(w, "The code is not ready or has ended. Keep this page open while FTW checks approval. If it stays here, check the six characters with the owner or ask for a new code.", http.StatusConflict)
		return
	}
	if s.ClaimInvite == nil {
		http.Error(w, "Invitations are not available. Ask the owner to approve this connection in FTW.", http.StatusServiceUnavailable)
		return
	}
	raw, _ := base64.RawURLEncoding.DecodeString(c.Offer)
	var offer protocol.SignedOffer
	if protocol.UnmarshalSigned(raw, &offer) != nil {
		http.Error(w, "Connect again from your assistant.", http.StatusGone)
		return
	}
	payload, err := (protocol.AgentInviteClaim{Secret: code.Secret, Offer: offer}).Payload()
	if err != nil {
		http.Error(w, "Connect again from your assistant.", http.StatusGone)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	err = s.ClaimInvite(ctx, InviteClaim{Home: code.Home, Kid: c.Kid, Key: c.AgentKey, Box: code.Box, Hash: protocol.AgentInviteHash(code.Home, code.Secret), Payload: payload})
	// Core's signed roster is the sole approval. It may have arrived even
	// when a Noise reply was lost or Keep already moved the pending key.
	latest, exists, _ := s.st.consentByRID(rid)
	if exists && latest.Status == statusApproved {
		writeJSON(w, http.StatusOK, map[string]string{"state": "approved"}, false)
		return
	}
	if err != nil {
		http.Error(w, "The connection is not confirmed. Keep this page open. Check that the box is online and the code has not expired or been used, then try the same code again.", http.StatusConflict)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"state": "waiting"}, false)
}
