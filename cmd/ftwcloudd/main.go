// Command ftwcloudd is FTW Cloud: it keeps a signed, readable copy of each
// home that turned it on, in memory, and serves it to that home's phones. It
// reads and never controls. See README.md.
//
//	ftwcloudd keygen -out service.key   make the service key; prints its public half
//	ftwcloudd [flags]                   serve
package main

import (
	"context"
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
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/srcfl/ftw-cloud/internal/apns"
	"github.com/srcfl/ftw-cloud/internal/push"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/server"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw-cloud/internal/uplink"
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
	certFile := fs.String("tls-cert", "", "certificate file, instead of ACME (local tests)")
	keyFile := fs.String("tls-key", "", "certificate key file, with -tls-cert")
	email := fs.String("acme-email", "", "contact for the certificate authority")
	apnsDir := fs.String("apns-dir", "/run/secrets/apns", "directory with Apple's key.p8, key-id and team-id; without it no alert is sent")
	apnsTopic := fs.String("apns-topic", "energy.ftw.app", "the app's bundle id")
	devPush := fs.String("dev-push-listen", "", "loopback address for registering a token by hand (development builds only)")
	devCapture := fs.String("dev-apns-capture", "", "write each alert to this directory instead of sending it to Apple (development builds only)")
	_ = fs.Parse(args)

	harden()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	key, err := loadServiceKey(*keyPath)
	if err != nil {
		return err
	}
	reg, err := registry.Open(filepath.Join(*stateDir, "registry.db"))
	if err != nil {
		return err
	}
	defer reg.Close()

	st := store.New(nil)
	up := uplink.New(st, reg, key, log)
	srv := &server.Server{Store: st, Registry: reg, Uplink: up, Log: log}

	// Alerts: the box's signed events to its phones through Apple, and
	// box.unreachable when a box is away. Without a key the service keeps
	// registrations and sends nothing.
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
	up.OnConnect = pushSvc.BoxConnected
	up.OnEvent = pushSvc.Event
	up.OnRoster = pushSvc.Roster
	up.OnGone = pushSvc.BoxGone

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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go srv.Upkeep(ctx, time.Minute)
	go pushSvc.Run(ctx)
	if *devPush != "" {
		if err := serveDevPush(ctx, *devPush, reg, pushSvc, log); err != nil {
			return err
		}
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdown)
	}()

	pub, _ := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	log.Info("ftwcloudd listening", "addr", *listen, "service_key", base64.RawURLEncoding.EncodeToString(pub))
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
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

// keygen writes a new service key and prints its public half, which Core
// carries in cloudlink.ServiceKeys.
func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "file to write the key to")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("keygen: -out is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	pub, err := cloudwire.PublicKeyBytesOf(&key.PublicKey)
	if err != nil {
		return err
	}
	fmt.Println(base64.RawURLEncoding.EncodeToString(pub))
	return nil
}
