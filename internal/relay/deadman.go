package relay

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The dead man's switch is the one thing this path keeps. A box can push
// every notification except the one that says it is gone, so it leaves a
// sealed row here: an opaque id, a push endpoint, a ciphertext encrypted at
// home, a deadline, and a delivery authorisation the box already signed.
// While a socket claims the id the switch is held. When the claim stays
// dropped past the deadline, the row is posted once.
//
// The ciphertext is RFC 8291. This file has no key for it and does not try
// to read it. The id is 128 bits the box derived from a secret that never
// arrives here.

const (
	deadmanRefireFloor = 30 * time.Minute
	deadmanMaxCT       = 8192
	deadmanMaxAuth     = 512
	deadmanMaxBody     = 16 << 10
)

var deadmanID = regexp.MustCompile(`^[0-9a-f]{32}$`)

// deadmanClaimID reads the one text frame the box may send on its command
// socket. Anything else on that socket is still a protocol error.
func deadmanClaimID(text string) (string, bool) {
	const prefix = "deadman "
	if len(text) != len(prefix)+32 || !strings.HasPrefix(text, prefix) {
		return "", false
	}
	id := text[len(prefix):]
	if !deadmanID.MatchString(id) {
		return "", false
	}
	return id, true
}

// PushPost delivers one fired row. Tests replace it. Production posts HTTPS
// and refuses a private or link-local address.
type PushPost func(ctx context.Context, endpoint string, body []byte, header http.Header) (status int, err error)

type deadmanRow struct {
	ID            string `json:"id"`
	Endpoint      string `json:"endpoint"`
	CT            string `json:"ct"`
	DeadlineS     int    `json:"deadline_s"`
	Auth          string `json:"auth,omitempty"`
	LastFiredAtMs int64  `json:"lastFiredAtMs,omitempty"`
}

type deadman struct {
	mu     sync.Mutex
	path   string
	now    func() time.Time
	post   PushPost
	log    func(status int, failed bool)
	rows   map[string]*deadmanRow
	claims map[string]int
	armed  map[string]time.Time
}

func newDeadman(path string, now func() time.Time, post PushPost, log func(int, bool)) *deadman {
	if post == nil {
		post = postPush
	}
	d := &deadman{
		path:   path,
		now:    now,
		post:   post,
		log:    log,
		rows:   map[string]*deadmanRow{},
		claims: map[string]int{},
		armed:  map[string]time.Time{},
	}
	d.load()
	// A row that outlived a restart has no claim. Arm it for a full
	// deadline so a live box can reconnect first and a dead one is still
	// spoken for.
	at := now()
	for _, row := range d.rows {
		d.armed[row.ID] = at.Add(time.Duration(row.DeadlineS) * time.Second)
	}
	return d
}

type deadmanIn struct {
	ID        string `json:"id"`
	Endpoint  string `json:"endpoint"`
	CT        string `json:"ct"`
	Auth      string `json:"auth"`
	DeadlineS int    `json:"deadline_s"`
}

// putError validates a POST body the way the Frankfurt relay does. The
// sentence is the JSON error field.
func putError(b deadmanIn, ctLen int) string {
	if !deadmanID.MatchString(b.ID) {
		return "id must be 32 hex chars"
	}
	if !strings.HasPrefix(b.Endpoint, "https://") {
		return "endpoint must be an https url"
	}
	if ctLen == 0 {
		return "ct must be base64"
	}
	if ctLen > deadmanMaxCT {
		return "ct too large"
	}
	if b.DeadlineS < 60 || b.DeadlineS > 86400 {
		return "deadline_s must be 60..86400"
	}
	if len(b.Auth) > deadmanMaxAuth {
		return "auth must be a short string"
	}
	return ""
}

func (d *deadman) put(b deadmanIn) {
	d.mu.Lock()
	defer d.mu.Unlock()
	row := &deadmanRow{ID: b.ID, Endpoint: b.Endpoint, CT: b.CT, DeadlineS: b.DeadlineS, Auth: b.Auth}
	if prev := d.rows[b.ID]; prev != nil {
		row.LastFiredAtMs = prev.LastFiredAtMs
	}
	d.rows[b.ID] = row
	if d.claims[b.ID] > 0 {
		delete(d.armed, b.ID)
	} else {
		d.armed[b.ID] = d.now().Add(time.Duration(b.DeadlineS) * time.Second)
	}
	d.save()
}

func (d *deadman) remove(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.rows, id)
	delete(d.armed, id)
	d.save()
}

// claim marks id held by one more socket. An id with no row yet is
// remembered: the POST may still be in flight beside the socket.
func (d *deadman) claim(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.claims[id]++
	delete(d.armed, id)
}

// release drops one socket's hold. The last one starts the countdown.
func (d *deadman) release(id string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := d.claims[id] - 1
	if n > 0 {
		d.claims[id] = n
		return
	}
	delete(d.claims, id)
	if row := d.rows[id]; row != nil {
		d.armed[id] = d.now().Add(time.Duration(row.DeadlineS) * time.Second)
	}
}

type deadmanView struct {
	rows, claimed, armed int
}

func (d *deadman) inspect() deadmanView {
	d.mu.Lock()
	defer d.mu.Unlock()
	return deadmanView{len(d.rows), len(d.claims), len(d.armed)}
}

// beat fires whatever is due. The post happens off this call so a slow push
// service cannot stall the heartbeat.
func (d *deadman) beat() {
	d.mu.Lock()
	now := d.now()
	type job struct {
		row deadmanRow
	}
	var jobs []job
	for id, at := range d.armed {
		if at.After(now) {
			continue
		}
		delete(d.armed, id)
		row := d.rows[id]
		if row == nil {
			continue
		}
		if row.LastFiredAtMs != 0 && now.Sub(time.UnixMilli(row.LastFiredAtMs)) < deadmanRefireFloor {
			continue
		}
		row.LastFiredAtMs = now.UnixMilli()
		jobs = append(jobs, job{row: *row})
	}
	if len(jobs) > 0 {
		d.save()
	}
	post := d.post
	d.mu.Unlock()
	for _, j := range jobs {
		go d.fire(post, j.row)
	}
}

func (d *deadman) fire(post PushPost, row deadmanRow) {
	body, err := base64.StdEncoding.DecodeString(row.CT)
	if err != nil {
		d.log(0, true)
		return
	}
	h := make(http.Header)
	h.Set("TTL", "86400")
	h.Set("Content-Encoding", "aes128gcm")
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Urgency", "high")
	if row.Auth != "" {
		h.Set("Authorization", row.Auth)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	status, err := post(ctx, row.Endpoint, body, h)
	d.log(status, err != nil)
	if err == nil && (status == http.StatusNotFound || status == http.StatusGone) {
		d.remove(row.ID)
	}
}

func (d *deadman) load() {
	if d.path == "" {
		return
	}
	raw, err := os.ReadFile(d.path)
	if err != nil {
		return
	}
	var rows []deadmanRow
	if json.Unmarshal(raw, &rows) != nil {
		return
	}
	for i := range rows {
		if deadmanID.MatchString(rows[i].ID) {
			d.rows[rows[i].ID] = &rows[i]
		}
	}
}

func (d *deadman) save() {
	if d.path == "" {
		return
	}
	rows := make([]deadmanRow, 0, len(d.rows))
	for _, row := range d.rows {
		rows = append(rows, *row)
	}
	raw, err := json.Marshal(rows)
	if err != nil {
		return
	}
	if err := os.MkdirAll(filepath.Dir(d.path), 0o755); err != nil {
		return
	}
	tmp := d.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return
	}
	_ = os.Rename(tmp, d.path)
}

// postPush is the production delivery. It refuses a URL that is not public
// HTTPS, including after a redirect, so a row cannot point this process at
// the metadata service or a host on the machine's own network.
func postPush(ctx context.Context, endpoint string, body []byte, header http.Header) (int, error) {
	if err := allowPushURL(endpoint); err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header = header.Clone()
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:           nil,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			DialContext:     dialPublic,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("relay: too many redirects")
			}
			return allowPushURL(req.URL.String())
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer res.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1024))
	return res.StatusCode, nil
}

func allowPushURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return errors.New("relay: push url refused")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if !publicIP(ip) {
			return errors.New("relay: push url refused")
		}
		return nil
	}
	return nil
}

func dialPublic(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errors.New("relay: push url refused")
	}
	for _, ip := range ips {
		if !publicIP(ip.IP) {
			return nil, errors.New("relay: push url refused")
		}
	}
	var d net.Dialer
	return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

func publicIP(ip net.IP) bool {
	if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	// Carrier-grade NAT. Go's IsPrivate does not cover it, and a push
	// service is not there.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64 {
		return false
	}
	return true
}
