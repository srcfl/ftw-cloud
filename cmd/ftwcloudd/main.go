// Command ftwcloudd is FTW Cloud: it keeps a signed, readable copy of each
// home that turned it on, in memory, and serves it to that home's phones. It
// reads and never controls. See README.md.
//
//	ftwcloudd keygen -out service.key          make the service key; prints its public half
//	ftwcloudd keygen -noise -out noise.key     make the Noise key phones dial; prints its public half
//	ftwcloudd metrics                          print the running service's counts, from inside its container
//	ftwcloudd health https://host/healthz      check /healthz over TCP and HTTP/3
//	ftwcloudd [flags]                          serve
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/srcfl/ftw-cloud/internal/apns"
	"github.com/srcfl/ftw-cloud/internal/appsession"
	"github.com/srcfl/ftw-cloud/internal/keys"
	"github.com/srcfl/ftw-cloud/internal/mcp"
	"github.com/srcfl/ftw-cloud/internal/metrics"
	"github.com/srcfl/ftw-cloud/internal/oauth"
	"github.com/srcfl/ftw-cloud/internal/push"
	"github.com/srcfl/ftw-cloud/internal/quicdoor"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/server"
	"github.com/srcfl/ftw-cloud/internal/shard"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw-cloud/internal/token"
	"github.com/srcfl/ftw-cloud/internal/uplink"
	"github.com/srcfl/ftw/go/protocol/appwire"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
	"golang.org/x/crypto/acme/autocert"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "keygen" || os.Args[1] == "health") {
		run := keygen
		if os.Args[1] == "health" {
			run = health
		}
		if err := run(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "metrics" {
		if err := printMetrics(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := serve(os.Args[1:]); err != nil {
		slog.Error("ftwcloudd stopped", "err", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("ftwcloudd", flag.ExitOnError)
	listen := fs.String("listen", ":443", "address to listen on")
	domain := fs.String("domain", "cloud.ftw.energy", "name to get a certificate for")
	stateDir := fs.String("state", "/state", "directory for the registry and certificates")
	keyPath := fs.String("service-key", "/run/secrets/ftw-cloud-service.key", "service key, PEM")
	noisePath := fs.String("noise-key", "/run/secrets/ftw-cloud-noise.key", "Noise key phones dial, PEM; without it /v1/app is off")
	certFile := fs.String("tls-cert", "", "certificate file, instead of ACME (local tests)")
	keyFile := fs.String("tls-key", "", "certificate key file, with -tls-cert")
	email := fs.String("acme-email", "", "contact for the certificate authority")
	apnsDir := fs.String("apns-dir", "/run/secrets/apns", "directory with Apple's key.p8, key-id and team-id; without it no alert is sent")
	apnsTopic := fs.String("apns-topic", "energy.ftw.app", "the iPhone app's bundle id")
	apnsWatch := fs.String("apns-watch-topic", "energy.ftw.app.watchkitapp", "the watch app's bundle id")
	devPush := fs.String("dev-push-listen", "", "loopback address for registering a token by hand (development builds only)")
	devCapture := fs.String("dev-apns-capture", "", "write each alert to this directory instead of sending it to Apple (development builds only)")
	keysSocket := fs.String("keys-socket", "/run/ftw-cloud-keys/keys.sock", "ftwkeysd's socket; assistants can connect only while it answers")
	shardsPath := fs.String("shards", "", "shard directory, JSON; without it this instance holds every home")
	metricsAddr := fs.String("metrics-listen", defaultMetricsAddr, "loopback address for /metrics; empty turns it off")
	restartRate := fs.Int("restart-rate", defaultRestartRate, "sockets a second the next instance can take after a restart; sets the spread of the redial")
	restartMin := fs.Duration("restart-spread-min", 15*time.Second, "the shortest spread: longer than the port stays closed while the next container starts")
	h3 := fs.Bool("h3", true, "also serve HTTP/3 on the same address over UDP, and say so in Alt-Svc")
	quicSessions := fs.Bool("quic-sessions", true, "also serve /v1/box and /v1/app over QUIC on the same address over UDP")
	_ = fs.Parse(args)

	harden()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	key, err := loadServiceKey(*keyPath)
	if err != nil {
		return err
	}
	// Phones read through /v1/app only with a Noise key. A host without one
	// still serves boxes, and the app reads through the relay meanwhile.
	noise, err := loadNoiseKey(*noisePath)
	noiseOn := err == nil
	if errors.Is(err, os.ErrNotExist) {
		log.Warn("no Noise key: phones cannot read from FTW Cloud until one is installed", "path", *noisePath)
	} else if err != nil {
		return err
	}
	shards := shard.Single(*domain)
	if *shardsPath != "" {
		if shards, err = shard.Load(*shardsPath); err != nil {
			return err
		}
		if shards.Host() != *domain {
			return fmt.Errorf("shards: this instance is %s at %s, but -domain is %s", shards.Self(), shards.Host(), *domain)
		}
	}
	reg, err := registry.Open(filepath.Join(*stateDir, "registry.db"))
	if err != nil {
		return err
	}
	defer reg.Close()

	st := store.New(nil)
	st.UseSuspensions(reg.Suspended)
	up := uplink.New(st, reg, key, log)
	up.Shards = shards
	// A restart is a deploy, and commands ride through here: phones are
	// admitted by the rosters their boxes signed before, without waiting
	// for every box to reconnect.
	restoreStart := time.Now()
	if n, err := up.Restore(); err != nil {
		return err
	} else if n > 0 {
		log.Info("rosters restored from the registry", "homes", n, "took", time.Since(restoreStart).Round(time.Millisecond))
	}
	tokens := token.New(st, reg, log)
	tokens.Shards = shards
	srv := &server.Server{Store: st, Registry: reg, Uplink: up, Tokens: tokens, Log: log}

	// Assistants: the authorization server, with agent keys in ftwkeysd.
	agentKeys := keys.Dial(*keysSocket)
	defer agentKeys.Close()
	auth, err := oauth.New(filepath.Join(*stateDir, "oauth.db"), agentKeys, log)
	if err != nil {
		return err
	}
	defer auth.Close()
	srv.OAuth = auth
	// Each agent's session goes to its box through the door, as tun, to the
	// Noise key the box names in the roster it signs. A box that names none
	// takes no agents yet, and the tools say so.
	agents := mcp.NewPool(st, up, agentKeys, mcp.RosterBoxKey(reg), log)
	auth.OnRevoke = agents.Drop
	srv.MCP = mcp.New(auth, agents, log)

	// Alerts: the box's signed events to its phones through Apple, and
	// box.unreachable when a box is away. Widgets: a push with no data when
	// prices or a car change. Without a key the service keeps registrations
	// and sends nothing.
	var sender push.Sender
	switch client, err := loadAPNs(*apnsDir, *apnsTopic); {
	case err != nil:
		return err
	case *devCapture != "":
		if sender, err = captureSender(*devCapture); err != nil {
			return err
		}
	case client == nil:
		log.Warn("APNs off: no key in " + *apnsDir)
	default:
		sender = client
	}
	pushSvc := push.New(reg, sender, log)
	pushSvc.WatchApp = *apnsWatch
	pushSvc.Owns = shards.Ours
	up.OnHeld = pushSvc.Held
	up.OnNotice = pushSvc.Notice
	up.OnRoster = func(home string, r *cloudwire.Roster) {
		pushSvc.Roster(home, r)
		tokens.Roster(home, r)
		auth.Roster(home, r)
	}
	up.OnGone = pushSvc.BoxGone
	// A purged home's agents, their tokens and keys, and its consents go.
	up.OnPurge = auth.DropHome

	// Phones register their tokens over their app session, so without a
	// Noise key only the development route registers one.
	if noiseOn {
		srv.App = appsession.New(st, reg, up, noise, log)
		srv.App.Push = pushSvc
		srv.App.Tokens = tokens
		srv.App.Tunnel = up
		srv.App.Shards = shards
	}
	app := srv.App
	up.OnConnect = func(home string, conn uint64) {
		if app != nil {
			app.BoxConnected(home)
		}
		pushSvc.BoxConnected(home, conn)
	}

	// TLS ends here and nowhere else: each box binds its handshake to this
	// TLS session, so a terminating proxy in front would break it. A plain
	// TCP load balancer is fine.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}}
	if *certFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			return err
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	} else {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(*domain),
			Cache:      autocert.DirCache(filepath.Join(*stateDir, "acme")),
			Email:      *email,
		}
		tlsConfig.GetCertificate = m.GetCertificate
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "acme-tls/1")
	}

	// QUIC on UDP, beside TCP: HTTP/3 for the plain HTTPS routes, and the
	// uplink and the app session with the handlers their WebSockets have.
	// The UDP port is bound before Alt-Svc says it is there, and a port that
	// will not bind leaves TCP serving alone: QUIC is the fast path, never
	// the only one.
	var door *quicdoor.Door
	var udp net.PacketConn
	if *h3 || *quicSessions {
		port, err := quicdoor.PortOf(*listen)
		if err != nil {
			return err
		}
		if udp, err = net.ListenPacket("udp", *listen); err != nil {
			log.Error("QUIC is off: UDP did not bind; TCP serves alone", "err", err)
		} else {
			var h3Handler http.Handler
			if *h3 {
				srv.AltSvc = quicdoor.AltSvc(port)
				h3Handler = srv.Handler()
			}
			door = quicdoor.New(h3Handler, log)
			if *quicSessions {
				door.Box = func(c *quicdoor.Conn, ekm []byte) { up.ServeConn(c, ekm) }
				if srv.App != nil {
					door.App = func(c *quicdoor.Conn, home string) { srv.App.ServeConn(c, home) }
				}
			}
			if door.ResetKey, err = quicdoor.ResetKeyFile(filepath.Join(*stateDir, "quic-reset.key")); err != nil {
				log.Warn("no stateless resets: a client waits out its idle timeout after a restart", "err", err)
			}
		}
	}

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 10 * time.Second,
		// Go's server logs "TLS handshake error from <address>". An address
		// beside a time is what links a household to its traffic, so the
		// server's own log goes nowhere.
		ErrorLog: log0(),
	}

	metrics.Default.GaugeFunc("ftwcloud_homes", "Homes held in memory.", func() int64 { return int64(st.Homes()) })
	metrics.Default.GaugeFunc("ftwcloud_homes_connected", "Homes whose box is connected.", func() int64 { return int64(up.Boxes()) })
	metrics.Runtime()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go srv.Upkeep(ctx, time.Minute)
	// Push outlives the signal until the queued alerts are out.
	pushCtx, stopPush := context.WithCancel(context.Background())
	defer stopPush()
	go pushSvc.Run(pushCtx)
	go auth.Run(ctx)
	go agents.Run(ctx)
	if err := pushSvc.Resume(); err != nil {
		log.Warn("could not restart the dead man's switch", "err", err)
	}
	if *devPush != "" {
		if err := serveDevPush(ctx, *devPush, reg, pushSvc, sender, log); err != nil {
			return err
		}
	}
	if *metricsAddr != "" {
		if err := serveMetrics(ctx, *metricsAddr); err != nil {
			return err
		}
	}
	go metrics.Default.Summarise(ctx, os.Stdout, shards.Self(), time.Minute)

	// A deploy: stop accepting, tell every box and phone to come back within
	// a spread the next instance can take, let the queued alerts go, then
	// exit. A box closed this way starts no box.unreachable. Every part
	// that holds sockets is a drainer, so an agent's sessions are closed and
	// counted in the spread too once that part adds itself here.
	drainers := []drainer{up}
	if app != nil {
		drainers = append(drainers, app)
	}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go func() { _ = httpSrv.Shutdown(shutdown) }()
		sockets := 0
		for _, d := range drainers {
			sockets += d.Sockets()
		}
		spread := restartSpread(sockets, *restartRate, *restartMin)
		reason := strconv.FormatInt(spread.Milliseconds(), 10)
		for _, d := range drainers {
			d.Drain(reason)
		}
		// Each socket waits for its client's answer to the close, so the
		// client reads 4503 and the spread rather than a reset.
		left := 0
		deadline := time.Now().Add(drainWait)
		for _, d := range drainers {
			left += d.WaitClosed(time.Until(deadline))
		}
		log.Info("drained for a restart", "sockets", sockets, "still_open", left, "spread", spread)
		if left := pushSvc.Flush(3 * time.Second); left > 0 {
			log.Warn("alerts queued or waiting to go again at exit; they are lost", "count", left)
		}
		stopPush()
	}()
	if door != nil {
		// On the way out the live QUIC sessions end with 1001. Silence would
		// leave each client to its idle timeout.
		defer door.Close()
		go func() {
			if err := door.Serve(ctx, udp, tlsConfig); err != nil {
				log.Error("QUIC stopped; TCP serves on", "err", err)
			}
		}()
	}

	pub, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	log.Info("ftwcloudd listening", "addr", *listen, "h3", srv.AltSvc != "", "quic_sessions", door != nil && door.Box != nil,
		"shard", shards.Self(), "shards", shards.Shards(),
		"service_key", base64.RawURLEncoding.EncodeToString(pub), "noise_key", base64.RawURLEncoding.EncodeToString(noise.Public()))
	err = httpSrv.ListenAndServeTLS("", "")
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-drained
	return nil
}

// drainer is a part that holds sockets and closes them before a restart.
type drainer interface {
	// Sockets is how many sockets it holds, handshakes included.
	Sockets() int
	// Drain closes them with 4503 and reason, and turns away new ones.
	Drain(reason string)
	// WaitClosed waits at most d for their clients' answers and returns how
	// many are still open.
	WaitClosed(d time.Duration) int
}

// drainWait bounds the wait for the clients' answers to the drain's close.
const drainWait = 2 * time.Second

// defaultRestartRate is how many sockets a second one instance takes on
// the host, with room to spare: deploy/README.md, "Load", has the numbers.
const defaultRestartRate = 500

// restartSpread is how long sockets wait at most before they redial: their
// number at rate a second, at least floor, which covers the next instance's
// start, and at most cloudwire.RestartSpreadMaxMs.
func restartSpread(sockets, rate int, floor time.Duration) time.Duration {
	if rate <= 0 {
		rate = defaultRestartRate
	}
	d := time.Duration(sockets) * time.Second / time.Duration(rate)
	return min(max(d, floor), time.Duration(cloudwire.RestartSpreadMaxMs)*time.Millisecond)
}

// defaultMetricsAddr is inside the container only; an operator reads it
// with docker exec and ftwcloudd metrics.
const defaultMetricsAddr = "127.0.0.1:9464"

// serveMetrics answers /metrics on a loopback address until ctx ends.
func serveMetrics(ctx context.Context, addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("metrics-listen: %w", err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("metrics-listen: %s is not a loopback address", addr)
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	m := &http.Server{Handler: metrics.Default, ReadHeaderTimeout: 5 * time.Second, ErrorLog: log0()}
	go func() { _ = m.Serve(ln) }()
	go func() {
		<-ctx.Done()
		_ = m.Close()
	}()
	return nil
}

// printMetrics prints the running service's /metrics.
func printMetrics(args []string) error {
	fs := flag.NewFlagSet("metrics", flag.ExitOnError)
	addr := fs.String("addr", defaultMetricsAddr, "where the service answers /metrics")
	_ = fs.Parse(args)
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + *addr + "/metrics")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(os.Stdout, resp.Body)
	return err
}

func log0() *log.Logger { return log.New(io.Discard, "", 0) }

// loadAPNs reads Apple's key from dir: key.p8, key-id and team-id, as the
// host writes them from SSM Parameter Store at boot. No directory or no key
// is no sender; a key that is there and wrong is an error.
func loadAPNs(dir, topic string) (*apns.Client, error) {
	p8, err := os.ReadFile(filepath.Join(dir, "key.p8"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("apns key: %w", err)
	}
	read := func(name string) (string, error) {
		b, err := os.ReadFile(filepath.Join(dir, name))
		return strings.TrimSpace(string(b)), err
	}
	keyID, err := read("key-id")
	if err != nil {
		return nil, fmt.Errorf("apns key id: %w", err)
	}
	teamID, err := read("team-id")
	if err != nil {
		return nil, fmt.Errorf("apns team id: %w", err)
	}
	return apns.New(apns.Config{Key: p8, KeyID: keyID, TeamID: teamID, Topic: topic})
}

func loadServiceKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("service key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("service key: %s is not an EC private key", path)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("service key: %w", err)
	}
	if key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("service key: %s is not P-256", path)
	}
	return key, nil
}

// loadNoiseKey reads the X25519 key phones run Noise IK against, PKCS #8 PEM.
func loadNoiseKey(path string) (appwire.KeyPair, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return appwire.KeyPair{}, fmt.Errorf("noise key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "PRIVATE KEY" {
		return appwire.KeyPair{}, fmt.Errorf("noise key: %s is not a PKCS #8 private key", path)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return appwire.KeyPair{}, fmt.Errorf("noise key: %w", err)
	}
	x, ok := parsed.(*ecdh.PrivateKey)
	if !ok || x.Curve() != ecdh.X25519() {
		return appwire.KeyPair{}, fmt.Errorf("noise key: %s is not an X25519 key", path)
	}
	return appwire.KeyPairFromSecret(x.Bytes())
}

// keygen writes a new key and prints its public half. The service key's goes
// into Core's cloudlink.ServiceKeys; with -noise, the Noise key's goes into
// the app.
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "file to write the key to")
	noise := fs.Bool("noise", false, "make the X25519 key phones dial instead of the P-256 service key")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("keygen: -out is required")
	}
	if *noise {
		x, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalPKCS8PrivateKey(x)
		if err != nil {
			return err
		}
		if err := writePEM(*out, "PRIVATE KEY", der); err != nil {
			return err
		}
		fmt.Println(base64.RawURLEncoding.EncodeToString(x.PublicKey().Bytes()))
		return nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := writePEM(*out, "EC PRIVATE KEY", der); err != nil {
		return err
	}
	pub, err := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	if err != nil {
		return err
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(pub))
	return nil
}

// writePEM writes a new key file that only its owner can read, and never over
// an existing one.
func writePEM(path, kind string, der []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: kind, Bytes: der}); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
