// Package webpush delivers only the box's pre-encrypted offline notices.
package webpush

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/srcfl/ftw-cloud/internal/metrics"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// Push services' answers per browser, summed over every home.
var results = map[string]*metrics.Counter{}

func init() {
	for _, r := range []string{"ok", "refused", "retry"} {
		results[r] = metrics.Default.Counter("ftwcloud_webpush_total", "Push services' answers per browser, by result.", "result", r)
	}
}

type Service struct {
	reg    *registry.Registry
	client *http.Client
	now    func() time.Time
}

func New(reg *registry.Registry) (*Service, error) {
	if err := reg.WebPushInit(); err != nil {
		return nil, err
	}
	// No proxy and no redirects. The resolved address itself is checked on
	// every dial, so neither a URL nor DNS can reach a local service.
	transport := &http.Transport{DialContext: publicDial, ForceAttemptHTTP2: true, TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second, MaxIdleConns: 8, IdleConnTimeout: time.Minute}
	return &Service{reg: reg, now: time.Now, client: &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func publicIP(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "2001:db8::/32"} {
		if netip.MustParsePrefix(p).Contains(ip) {
			return false
		}
	}
	return true
}

func publicDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || port != "443" {
		return nil, errors.New("webpush: invalid destination")
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, errors.New("webpush: name lookup failed")
	}
	for _, ip := range ips {
		if !publicIP(ip) {
			return nil, errors.New("webpush: local destination refused")
		}
	}
	for _, ip := range ips {
		c, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if e == nil {
			return c, nil
		}
	}
	return nil, errors.New("webpush: connection failed")
}

// deliveryURL also binds the short-lived VAPID token to this endpoint's
// origin. The push vendor verifies the box's signature; we hold no key.
func deliveryURL(row cloudwire.WebPushRow, now time.Time) bool {
	u, err := url.Parse(row.Endpoint)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return false
	}
	if ip, err := netip.ParseAddr(u.Hostname()); err == nil && !publicIP(ip) {
		return false
	}
	auth, ok := strings.CutPrefix(row.Auth, "vapid t=")
	if !ok {
		return false
	}
	jwt, key, ok := strings.Cut(auth, ", k=")
	if !ok || key == "" {
		return false
	}
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false
	}
	var claims struct {
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return false
	}
	return claims.Aud == u.Scheme+"://"+u.Host && claims.Exp > now.Unix() && claims.Exp <= now.Add(24*time.Hour).Unix()
}

// Send shares the APNs outage timer and queue. It rechecks the signed roster,
// epochs and suspensions on every try. A copy grant is not needed: the box
// authored and encrypted these notices for the browsers that subscribed.
func (s *Service) Send(ctx context.Context, home string) (took int, retry bool) {
	due, err := s.reg.WebPushOutage(home)
	if err != nil {
		return 0, true
	}
	if due == 0 || due > s.now().UnixMilli() {
		return 0, false
	}
	h, ok, err := s.reg.Get(home)
	if err != nil {
		return 0, true
	}
	if !ok {
		return 0, false
	}
	env, err := cloudwire.DecodeEnvelope(h.Roster)
	if err != nil {
		return 0, false
	}
	var roster cloudwire.Roster
	if cloudwire.Unmarshal(env.B, &roster) != nil || cloudwire.ValidateWebPush(roster.WebPush) != nil {
		return 0, false
	}
	if roster.TTLS <= 0 || !s.now().Before(h.RosterAt.Add(time.Duration(min(roster.TTLS, 86400))*time.Second)) {
		return 0, false
	}
	sent, err := s.reg.WebPushSent(home, due)
	if err != nil {
		return 0, true
	}
	for _, row := range roster.WebPush {
		mark := row.ID + ":" + strconv.FormatUint(row.Epoch, 10)
		if slices.Contains(sent, mark) {
			continue
		}
		eligible := slices.ContainsFunc(roster.Devices, func(d cloudwire.Device) bool {
			return d.ID == row.Device && d.Epoch == row.Epoch && d.Agent == nil && slices.Contains(d.Scopes, protocol.ScopeEventsRead)
		})
		if !eligible || s.reg.Suspended(home, row.Device, row.Epoch) || !deliveryURL(row, s.now()) {
			continue
		}
		current, e := s.reg.WebPushOutage(home)
		if e != nil {
			return took, true
		}
		if current != due {
			return took, false
		}
		req, e := http.NewRequestWithContext(ctx, http.MethodPost, row.Endpoint, bytes.NewReader(row.CT))
		if e != nil {
			continue
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Encoding", "aes128gcm")
		req.Header.Set("TTL", "3600")
		req.Header.Set("Urgency", "high")
		req.Header.Set("Authorization", row.Auth)
		resp, e := s.client.Do(req)
		if e != nil {
			results["retry"].Inc()
			retry = true
			continue
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
		_ = resp.Body.Close()
		if resp.StatusCode == 429 || resp.StatusCode >= 500 {
			results["retry"].Inc()
			retry = true
			continue
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			results["ok"].Inc()
			took++
		} else {
			results["refused"].Inc()
		}
		// Terminal refusals (including expired subscriptions) do not repeat.
		if s.reg.WebPushMark(home, due, mark) != nil {
			retry = true
		}
	}
	return took, retry
}

// Homes includes browser-only homes in the restart grace, even if their
// box was online when the service stopped and left no away row.
func (s *Service) Homes() ([]string, error) {
	homes, err := s.reg.Rosters()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, h := range homes {
		env, err := cloudwire.DecodeEnvelope(h.Roster)
		if err != nil {
			continue
		}
		var r cloudwire.Roster
		if cloudwire.Unmarshal(env.B, &r) == nil && len(r.WebPush) > 0 && cloudwire.ValidateWebPush(r.WebPush) == nil {
			out = append(out, h.ID)
		}
	}
	return out, nil
}
