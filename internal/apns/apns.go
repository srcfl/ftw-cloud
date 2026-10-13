// Package apns sends alerts to Apple Push Notification service: HTTP/2 to
// Apple's provider API, authenticated with a token (a JWT signed with ES256
// by the team's .p8 key) that is renewed every 40 minutes.
//
// It knows nothing about homes or events. The caller hands it a device
// token and the payload bytes, and gets back what Apple said, including
// whether the token is gone for good.
package apns

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Apple's hosts. Sandbox serves development builds of the app; production
// serves TestFlight and the App Store.
const (
	ProductionURL = "https://api.push.apple.com"
	SandboxURL    = "https://api.sandbox.push.apple.com"
)

// Environments, as a phone names them when it registers.
const (
	Sandbox    = "sandbox"
	Production = "production"
)

// TokenLife is how long one provider token is used. Apple refuses a token
// older than an hour and one renewed more often than every 20 minutes.
const TokenLife = 40 * time.Minute

// requestTimeout bounds one request.
const requestTimeout = 10 * time.Second

// Config is one team key and the app it sends for.
type Config struct {
	// Key is the .p8 file Apple issued: a PKCS #8 P-256 key in PEM.
	Key []byte
	// KeyID is the key's 10-character id; TeamID the team's.
	KeyID  string
	TeamID string
	// Topic is the app's bundle id.
	Topic string

	// Seams for tests. Production leaves them zero.
	SandboxURL    string
	ProductionURL string
	HTTPClient    *http.Client
	Now           func() time.Time
}

// Client sends to Apple. It is safe for concurrent use and keeps one HTTP/2
// connection per host.
type Client struct {
	cfg  Config
	key  *ecdsa.PrivateKey
	http *http.Client
	now  func() time.Time

	mu      sync.Mutex
	token   string
	tokenAt time.Time
}

// New parses the key and returns a client.
func New(cfg Config) (*Client, error) {
	key, err := ParseKey(cfg.Key)
	if err != nil {
		return nil, err
	}
	if len(cfg.KeyID) != 10 || len(cfg.TeamID) != 10 || cfg.Topic == "" {
		return nil, errors.New("apns: a 10-character key id, a 10-character team id and a topic are required")
	}
	if cfg.SandboxURL == "" {
		cfg.SandboxURL = SandboxURL
	}
	if cfg.ProductionURL == "" {
		cfg.ProductionURL = ProductionURL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{MinVersion: tls.VersionTLS12},
			ForceAttemptHTTP2: true,
			IdleConnTimeout:   time.Hour,
		}}
	}
	return &Client{cfg: cfg, key: key, http: client, now: cfg.Now}, nil
}

// ParseKey reads a .p8: PEM around a PKCS #8 P-256 key.
func ParseKey(p8 []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(p8)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("apns: the key is not a PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("apns: %w", err)
	}
	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok || key.Curve.Params().Name != "P-256" {
		return nil, errors.New("apns: the key is not a P-256 key")
	}
	return key, nil
}

// Notification is one push.
type Notification struct {
	// Environment is Sandbox or Production.
	Environment string
	// DeviceToken is the token the phone got from iOS.
	DeviceToken []byte
	Payload     []byte
	// Expiration is when Apple may stop trying to deliver. Zero means
	// deliver now or not at all.
	Expiration time.Time
}

// Result is Apple's answer.
type Result struct {
	// Status is the HTTP status; 200 is delivered to Apple.
	Status int
	// Reason is Apple's reason string when Status is not 200.
	Reason string
	// Gone means the token no longer names a phone for this app: forget it.
	Gone bool
	// GoneSince is when Apple last knew the token was valid, for a 410.
	GoneSince time.Time
}

// OK reports whether Apple took the push.
func (r Result) OK() bool { return r.Status == http.StatusOK }

// Send posts one alert. Every alert has the same priority and push type,
// and no collapse id, so nothing in the request says what kind it is.
func (c *Client) Send(ctx context.Context, n Notification) (Result, error) {
	base := c.cfg.ProductionURL
	switch n.Environment {
	case Production:
	case Sandbox:
		base = c.cfg.SandboxURL
	default:
		return Result{}, fmt.Errorf("apns: unknown environment %q", n.Environment)
	}
	if len(n.DeviceToken) == 0 {
		return Result{}, errors.New("apns: no device token")
	}
	res, err := c.post(ctx, base, n, false)
	if err == nil && (res.Reason == "ExpiredProviderToken" || res.Reason == "InvalidProviderToken") {
		// A token Apple no longer takes: make a new one and try once more.
		res, err = c.post(ctx, base, n, true)
	}
	return res, err
}

func (c *Client) post(ctx context.Context, base string, n Notification, renew bool) (Result, error) {
	token, err := c.providerToken(renew)
	if err != nil {
		return Result{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/3/device/"+hex.EncodeToString(n.DeviceToken),
		bytes.NewReader(n.Payload))
	if err != nil {
		return Result{}, err
	}
	req.Header.Set("authorization", "bearer "+token)
	req.Header.Set("apns-topic", c.cfg.Topic)
	req.Header.Set("apns-push-type", "alert")
	req.Header.Set("apns-priority", "10")
	exp := int64(0)
	if !n.Expiration.IsZero() {
		exp = n.Expiration.Unix()
	}
	req.Header.Set("apns-expiration", strconv.FormatInt(exp, 10))
	req.Header.Set("content-type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("apns: %w", err)
	}
	defer resp.Body.Close()
	res := Result{Status: resp.StatusCode}
	if resp.StatusCode == http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		return res, nil
	}
	var body struct {
		Reason    string `json:"reason"`
		Timestamp int64  `json:"timestamp"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&body)
	res.Reason = body.Reason
	switch {
	case resp.StatusCode == http.StatusGone:
		res.Gone = true
		if body.Timestamp > 0 {
			res.GoneSince = time.UnixMilli(body.Timestamp)
		}
	case body.Reason == "BadDeviceToken" || body.Reason == "DeviceTokenNotForTopic":
		res.Gone = true
	}
	return res, nil
}

// providerToken is the JWT Apple authenticates the provider by, renewed
// after TokenLife or when renew asks.
func (c *Client) providerToken(renew bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if !renew && c.token != "" && now.Sub(c.tokenAt) < TokenLife {
		return c.token, nil
	}
	token, err := signToken(c.key, c.cfg.KeyID, c.cfg.TeamID, now)
	if err != nil {
		return "", err
	}
	c.token, c.tokenAt = token, now
	return token, nil
}

// signToken makes Apple's provider token: {alg: ES256, kid} . {iss, iat},
// signed with ES256 as r ‖ s.
func signToken(key *ecdsa.PrivateKey, keyID, teamID string, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	header, err := json.Marshal(map[string]string{"alg": "ES256", "kid": keyID})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{"iss": teamID, "iat": now.Unix()})
	if err != nil {
		return "", err
	}
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(claims)
	digest := sha256.Sum256([]byte(signing))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + enc.EncodeToString(sig), nil
}
