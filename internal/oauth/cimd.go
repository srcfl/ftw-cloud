package oauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

// Client ID metadata documents: a client's id is an https URL, and the
// document at that URL names the client and its redirect URIs. The service
// fetches a URL a stranger chose, so the fetch is fenced: https on port 443
// to a DNS name, only to public addresses (checked on the address actually
// dialled, so a name that changes its answer between lookup and connect
// gains nothing), no proxy, no redirects, no cookies, a small body and a
// short time, a few at once and a few per host, and the answers cached:
// documents for at least a minute, failures apart for a minute.

const (
	cimdMaxBytes    = 16 << 10
	cimdTimeout     = 5 * time.Second
	cimdMaxURL      = 2048
	cimdCacheMin    = time.Minute
	cimdCacheMax    = 24 * time.Hour
	cimdCacheNone   = 10 * time.Minute // with no Cache-Control
	cimdCacheFailed = time.Minute
	cimdCacheSize   = 1024
	cimdFailedSize  = 256
	cimdConcurrent  = 8
	// Per host: a few fetches at once, then one every ten seconds.
	cimdHostBurst = 4
	cimdHostRate  = 0.1
	cimdHosts     = 4096
)

// clientMetadata is the part of a metadata document the service reads.
type clientMetadata struct {
	ClientID                          string   `json:"client_id"`
	ClientName                        string   `json:"client_name"`
	ClientURI                         string   `json:"client_uri"`
	RedirectURIs                      []string `json:"redirect_uris"`
	GrantTypes                        []string `json:"grant_types"`
	ResponseTypes                     []string `json:"response_types"`
	TokenEndpointAuthMethod           string   `json:"token_endpoint_auth_method"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
}

// Fetch refusals. Each is a reason to refuse the client, never to retry.
var (
	errCIMDURL      = errors.New("client_id is not a URL this service fetches")
	errCIMDAddress  = errors.New("client_id resolves to an address this service does not fetch from")
	errCIMDFetch    = errors.New("client metadata could not be fetched")
	errCIMDDocument = errors.New("client metadata document is not valid")
)

// fetcher gets metadata documents.
type fetcher struct {
	client *http.Client
	// resolve looks a name up. Tests point it at their own server.
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	// public decides which addresses may be dialled.
	public func(netip.Addr) bool
	// dial connects to an address that passed the checks. Tests point it
	// at their own server.
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
	timeout time.Duration
	now     func() time.Time
	sem     chan struct{}
	// hostBurst and hostRate bound fetches per host.
	hostBurst, hostRate float64

	mu     sync.Mutex
	cache  map[string]cimdEntry
	failed map[string]cimdEntry
	hosts  map[string]*limiter
}

type cimdEntry struct {
	md    clientMetadata
	err   error
	until time.Time
}

// put keeps an entry in a bounded cache: what has run out goes first, then
// whatever the map yields.
func put(cache map[string]cimdEntry, size int, key string, e cimdEntry, now time.Time) {
	if len(cache) >= size {
		for k, old := range cache {
			if !now.Before(old.until) {
				delete(cache, k)
			}
		}
		for k := range cache {
			if len(cache) < size {
				break
			}
			delete(cache, k)
		}
	}
	cache[key] = e
}

// newFetcher builds the fenced fetcher. roots is nil for the system's.
func newFetcher(roots *x509.CertPool) *fetcher {
	f := &fetcher{
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		},
		public:    publicAddr,
		timeout:   cimdTimeout,
		now:       time.Now,
		sem:       make(chan struct{}, cimdConcurrent),
		hostBurst: cimdHostBurst, hostRate: cimdHostRate,
		cache:  map[string]cimdEntry{},
		failed: map[string]cimdEntry{},
		hosts:  map[string]*limiter{},
	}
	// The address is checked again as the socket connects, on the address
	// itself.
	dialer := &net.Dialer{Timeout: 3 * time.Second, Control: func(_, address string, _ syscall.RawConn) error {
		ap, err := netip.ParseAddrPort(address)
		if err != nil || !f.public(ap.Addr()) {
			return errCIMDAddress
		}
		return nil
	}}
	f.dial = dialer.DialContext
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := f.resolve(ctx, host)
			if err != nil {
				return nil, errCIMDFetch
			}
			for _, ip := range ips {
				if !f.public(ip) {
					// One private answer is enough to refuse: a name that
					// mixes them is pointing somewhere it should not.
					return nil, errCIMDAddress
				}
			}
			if len(ips) == 0 {
				return nil, errCIMDFetch
			}
			return f.dial(ctx, network, net.JoinHostPort(ips[0].Unmap().String(), port))
		},
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:    3 * time.Second,
		ResponseHeaderTimeout:  3 * time.Second,
		MaxResponseHeaderBytes: 8 << 10,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      true,
	}
	f.client = &http.Client{
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return f
}

// isCIMD reports whether a client_id is a URL, and so names a metadata
// document rather than a registered client.
func isCIMD(clientID string) bool { return strings.HasPrefix(clientID, "https://") }

// checkCIMDURL holds a client_id URL to the rules: https, a DNS name on the
// default port, a path that is not the root and has no dot segments, no
// credentials and no fragment.
func checkCIMDURL(raw string) (*url.URL, error) {
	if len(raw) > cimdMaxURL {
		return nil, errCIMDURL
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || u.RawFragment != "" ||
		strings.Contains(raw, "#") || u.Opaque != "" {
		return nil, errCIMDURL
	}
	host := u.Hostname()
	if host == "" || u.Port() != "" && u.Port() != "443" || !strings.Contains(host, ".") || strings.HasSuffix(host, ".") {
		return nil, errCIMDURL
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return nil, errCIMDURL // an address, not a name
	}
	// The document's URL names its host as the owner will see it: in
	// lower case ASCII already.
	if a, ok := asciiHost(host); !ok || a != host {
		return nil, errCIMDURL
	}
	if u.Path == "" || u.Path == "/" {
		return nil, errCIMDURL
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return nil, errCIMDURL
		}
	}
	return u, nil
}

// get returns the validated metadata for a client_id URL, from the cache
// when it may.
func (f *fetcher) get(ctx context.Context, clientID string) (clientMetadata, error) {
	u, err := checkCIMDURL(clientID)
	if err != nil {
		return clientMetadata{}, err
	}
	now := f.now()
	f.mu.Lock()
	for _, c := range []map[string]cimdEntry{f.cache, f.failed} {
		if e, ok := c[clientID]; ok && now.Before(e.until) {
			f.mu.Unlock()
			return e.md, e.err
		}
	}
	host, _ := asciiHost(u.Hostname())
	hl := f.hosts[host]
	if hl == nil {
		if len(f.hosts) >= cimdHosts {
			clear(f.hosts)
		}
		l := newLimiter(f.hostBurst, f.hostRate)
		hl = &l
		f.hosts[host] = hl
	}
	f.mu.Unlock()
	if !hl.allow(now) {
		return clientMetadata{}, fmt.Errorf("%w: too many fetches from %s", errCIMDFetch, host)
	}

	select {
	case f.sem <- struct{}{}:
		defer func() { <-f.sem }()
	case <-ctx.Done():
		return clientMetadata{}, errCIMDFetch
	}
	md, ttl, err := f.fetch(ctx, u)
	f.mu.Lock()
	defer f.mu.Unlock()
	if err != nil {
		put(f.failed, cimdFailedSize, clientID, cimdEntry{err: err, until: now.Add(cimdCacheFailed)}, now)
	} else {
		put(f.cache, cimdCacheSize, clientID, cimdEntry{md: md, until: now.Add(ttl)}, now)
	}
	return md, err
}

func (f *fetcher) fetch(ctx context.Context, u *url.URL) (clientMetadata, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return clientMetadata{}, 0, errCIMDURL
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "FTW-Cloud (+https://cloud.ftw.energy/source)")
	resp, err := f.client.Do(req)
	if err != nil {
		if errors.Is(err, errCIMDAddress) {
			return clientMetadata{}, 0, errCIMDAddress
		}
		return clientMetadata{}, 0, errCIMDFetch
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return clientMetadata{}, 0, fmt.Errorf("%w: status %d", errCIMDFetch, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBytes+1))
	if err != nil {
		return clientMetadata{}, 0, errCIMDFetch
	}
	if len(body) > cimdMaxBytes {
		return clientMetadata{}, 0, fmt.Errorf("%w: larger than %d bytes", errCIMDDocument, cimdMaxBytes)
	}
	md, err := parseMetadata(body, u.String())
	if err != nil {
		return clientMetadata{}, 0, err
	}
	return md, cacheFor(resp.Header.Get("Cache-Control")), nil
}

// parseMetadata reads and checks one document fetched from clientID.
func parseMetadata(body []byte, clientID string) (clientMetadata, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return clientMetadata{}, fmt.Errorf("%w: not a JSON object", errCIMDDocument)
	}
	// A document is public: a client that puts a shared secret in it has
	// none.
	for _, k := range []string{"client_secret", "client_secret_expires_at"} {
		if _, ok := fields[k]; ok {
			return clientMetadata{}, fmt.Errorf("%w: %s in a public document", errCIMDDocument, k)
		}
	}
	var md clientMetadata
	if err := json.Unmarshal(body, &md); err != nil {
		return clientMetadata{}, fmt.Errorf("%w: %v", errCIMDDocument, err)
	}
	if md.ClientID != clientID {
		return clientMetadata{}, fmt.Errorf("%w: client_id does not match its URL", errCIMDDocument)
	}
	md.ClientName = cleanName(md.ClientName)
	if md.ClientName == "" {
		return clientMetadata{}, fmt.Errorf("%w: no client_name", errCIMDDocument)
	}
	if len(md.RedirectURIs) == 0 || len(md.RedirectURIs) > 16 {
		return clientMetadata{}, fmt.Errorf("%w: redirect_uris", errCIMDDocument)
	}
	for _, r := range md.RedirectURIs {
		if err := checkRedirect(r); err != nil {
			return clientMetadata{}, fmt.Errorf("%w: %v", errCIMDDocument, err)
		}
	}
	// The plural field lists what the client can use; the legacy field
	// is only its preference. This server offers none for CIMD clients.
	if _, ok := fields["token_endpoint_auth_methods_supported"]; ok {
		if !slices.Contains(md.TokenEndpointAuthMethodsSupported, authNone) {
			return clientMetadata{}, fmt.Errorf("%w: token_endpoint_auth_methods_supported must include %q", errCIMDDocument, authNone)
		}
	} else if m := md.TokenEndpointAuthMethod; m != "" && m != authNone {
		return clientMetadata{}, fmt.Errorf("%w: token_endpoint_auth_method %q is not supported", errCIMDDocument, m)
	}
	// A client may list grants this server does not offer (Claude lists
	// the JWT bearer grant); it gets the code and refresh grants only. It
	// must use the code grant with a code response.
	if len(md.GrantTypes) > 0 && !slices.Contains(md.GrantTypes, grantCode) ||
		len(md.ResponseTypes) > 0 && !slices.Contains(md.ResponseTypes, "code") {
		return clientMetadata{}, fmt.Errorf("%w: grant or response types", errCIMDDocument)
	}
	return md, nil
}

// cacheFor reads how long a document may be kept, within bounds. Even a
// document that asks not to be kept is kept a minute, so a page that loads
// it again and again cannot make the service fetch it each time.
func cacheFor(cc string) time.Duration {
	if cc == "" {
		return cimdCacheNone
	}
	for _, d := range strings.Split(cc, ",") {
		d = strings.ToLower(strings.TrimSpace(d))
		switch {
		case d == "no-store" || d == "no-cache":
			return cimdCacheMin
		case strings.HasPrefix(d, "max-age="):
			s, err := strconv.Atoi(strings.TrimPrefix(d, "max-age="))
			if err != nil || s < 0 {
				return cimdCacheNone
			}
			return min(max(time.Duration(s)*time.Second, cimdCacheMin), cimdCacheMax)
		}
	}
	return cimdCacheNone
}

// publicAddr is an address on the public internet: not loopback, private,
// link-local (where the cloud's metadata service answers), multicast,
// shared, reserved, documentation, IPv4-compatible IPv6, or a translation
// prefix that could lead back inside.
func publicAddr(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsInterfaceLocalMulticast() || a.IsMulticast() || a.IsUnspecified() {
		return false
	}
	for _, p := range blocked {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

var blocked = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "255.255.255.255/32",
		"::/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32", "2001:db8::/32", "2002::/16", "fec0::/10",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// cleanName keeps a client's name to one short line of printable text. It
// is shown to an owner deciding whom to let in, so nothing in it may pass
// for something the service wrote.
func cleanName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	if r := []rune(s); len(r) > 64 {
		s = string(r[:64]) + "…"
	}
	return s
}
