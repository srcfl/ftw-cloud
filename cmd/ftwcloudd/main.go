// Command ftwcloudd is FTW Cloud: it keeps a signed, readable copy of each
// home that turned it on, in memory, and serves it to that home's phones. It
// reads and never controls. See README.md.
//
//	ftwcloudd keygen -out service.key          make the service key; prints its public half
//	ftwcloudd keygen -noise -out noise.key     make the Noise key phones dial; prints its public half
//	ftwcloudd metrics                          print the running service's counts, from inside its container
//	ftwcloudd move -shards f -shard s2 -to f   copy the registry rows of the homes the directory gives s2
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
	"github.com/srcfl/ftw-cloud/internal/metrics"
	"github.com/srcfl/ftw-cloud/internal/push"
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
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		if err := keygen(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "move" {
		if err := move(os.Args[2:]); err != nil {
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
	shardsPath := fs.String("shards", "", "shard directory, JSON; without it this instance holds every home")
	metricsAddr := fs.String("metrics-listen", defaultMetricsAddr, "loopback address for /metrics; empty turns it off")
	restartRate := fs.Int("restart-rate", defaultRestartRate, "sockets a second the next instance can take after a restart; sets the spread of the redial")
	restartMin := fs.Duration("restart-spread-min", 5*time.Second, "the shortest spread: about how long the next instance takes to start")
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
	up.OnRoster = func(home string, r *cloudwire.Roster) {
		pushSvc.Roster(home, r)
		tokens.Roster(home, r)
	}
	up.OnGone = pushSvc.BoxGone

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
	// exit. A box closed this way starts no box.unreachable.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		go func() { _ = httpSrv.Shutdown(shutdown) }()
		phones := 0
		if app != nil {
			phones = app.Sockets()
		}
		spread := restartSpread(up.Boxes()+phones, *restartRate, *restartMin)
		reason := strconv.FormatInt(spread.Milliseconds(), 10)
		// The phones first: their sessions close on their own goroutines
		// while the boxes' closes go out here.
		if app != nil {
			app.Drain(reason)
		}
		boxes := up.Drain(reason)
		if app != nil {
			if left := app.WaitClosed(2 * time.Second); left > 0 {
				log.Warn("app sessions still open at exit", "count", left)
			}
		}
		log.Info("drained for a restart", "boxes", boxes, "phones", phones, "spread", spread)
		if left := pushSvc.Flush(3 * time.Second); left > 0 {
			log.Warn("alerts queued or waiting to go again at exit; they are lost", "count", left)
		}
		stopPush()
	}()

	pub, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	log.Info("ftwcloudd listening", "addr", *listen, "shard", shards.Self(), "shards", shards.Shards(),
		"service_key", base64.RawURLEncoding.EncodeToString(pub), "noise_key", base64.RawURLEncoding.EncodeToString(noise.Public()))
	err = httpSrv.ListenAndServeTLS("", "")
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-drained
	return nil
}

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

// move copies the registry rows of every home a directory gives one shard
// into that shard's registry file, and with -drop deletes them here. See
// deploy/README.md, "Shards".
func move(args []string) error {
	fs := flag.NewFlagSet("move", flag.ExitOnError)
	from := fs.String("registry", "/state/registry.db", "this shard's registry")
	to := fs.String("to", "", "the registry file of the shard the homes move to")
	dir := fs.String("shards", "", "the directory that gives the homes their new shard")
	name := fs.String("shard", "", "the shard the homes move to")
	drop := fs.Bool("drop", false, "delete the moved homes here once copied; only after this shard has stopped holding them")
	_ = fs.Parse(args)
	if *to == "" || *dir == "" || *name == "" {
		return errors.New("move: -to, -shards and -shard are required")
	}
	d, err := shard.Load(*dir)
	if err != nil {
		return err
	}
	if *drop && d.Self() == *name {
		return fmt.Errorf("move: -drop deletes the homes from %s, the shard they move to", *name)
	}
	reg, err := registry.Open(*from)
	if err != nil {
		return err
	}
	defer reg.Close()
	n, err := reg.MoveTo(*to, func(home string) bool { return d.Of(home) == *name }, *drop)
	if err != nil {
		return err
	}
	fmt.Printf("moved %d homes to %s\n", n, *name)
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
