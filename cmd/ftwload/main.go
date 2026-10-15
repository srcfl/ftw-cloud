// Command ftwload drives a local ftwcloudd with simulated boxes and phones
// and measures what the service costs: connects, handshakes, tun round trips,
// box-to-phone live latency, and the service's CPU and memory.
//
// It speaks only the wire (go/protocol), starts ftwcloudd itself as a child
// process on 127.0.0.1 with fresh keys and a self-signed certificate in a
// temporary directory, and exits by itself. Build the service first:
//
//	go build -o /tmp/ftwload/ftwcloudd ./cmd/ftwcloudd
//	go run ./cmd/ftwload -ftwcloudd /tmp/ftwload/ftwcloudd -homes 100 -duration 60s
//
// Timeline: box connects spread over the first half of -ramp, phone
// connects over the second half; the steady phase of -duration starts when
// all are up (or at the latest 10 s after the ramp). -storm-at and
// -sigterm-at count from the start of the steady phase. Tun and live
// latencies count only what was sent during the steady phase.
//
// The harness runs with -procs cores and the service with -server-procs
// (GOMAXPROCS, default 2, as on a 2-vCPU t4g.small). On macOS one source
// address reaches about 16k sockets (the ephemeral port range); beyond that
// add loopback aliases (sudo ifconfig lo0 alias 127.0.0.2) and pass -src.
//
// On a shared laptop: check that no heavy build runs first (pgrep -fl
// 'xcodebuild|swift-build|go test|go build'), keep load at or below twice the
// cores, and leave -max set. Whatever happens, the child is killed at -max:
// by the harness, on SIGINT or SIGTERM, and by a watchdog shell that outlives
// a crashed harness. Check with pgrep -fl ftwcloudd afterwards.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

type config struct {
	bin                  string
	serverProcs, procs   int
	max                  time.Duration
	homes, phones        int
	ramp, duration       time.Duration
	copy                 bool
	live, cmd            time.Duration
	stormAt, stormJitter time.Duration
	sigtermAt            time.Duration
	jsonPath, src        string
}

func parseFlags() config {
	var c config
	flag.StringVar(&c.bin, "ftwcloudd", "", "path to a built ftwcloudd (go build -o <tmp>/ftwcloudd ./cmd/ftwcloudd)")
	flag.IntVar(&c.serverProcs, "server-procs", 2, "GOMAXPROCS for ftwcloudd")
	flag.IntVar(&c.procs, "procs", 6, "GOMAXPROCS for the harness")
	flag.DurationVar(&c.max, "max", 150*time.Second, "hard deadline for the whole run; ftwcloudd is killed then")
	flag.IntVar(&c.homes, "homes", 100, "homes, one box each")
	flag.IntVar(&c.phones, "phones", 1, "phones per home")
	flag.DurationVar(&c.ramp, "ramp", 10*time.Second, "boxes connect over the first half, phones over the second")
	flag.DurationVar(&c.duration, "duration", 60*time.Second, "steady phase")
	flag.BoolVar(&c.copy, "copy", true, "readable copy on: the service forwards each box's live to its phones")
	flag.DurationVar(&c.live, "live", time.Second, "how often each box sends live")
	flag.DurationVar(&c.cmd, "cmd", time.Second, "how often each phone sends a tun the box echoes")
	flag.DurationVar(&c.stormAt, "storm-at", 0, "close every box socket at once this far into the steady phase (0 off)")
	flag.DurationVar(&c.stormJitter, "storm-jitter", 0, "after the storm, each box redials within this delay")
	flag.DurationVar(&c.sigtermAt, "sigterm-at", 0, "send ftwcloudd SIGTERM this far into the steady phase (0 off)")
	flag.StringVar(&c.jsonPath, "json", "", "also write the summary as JSON to this file")
	flag.StringVar(&c.src, "src", "", "comma-separated local IPs to dial from, round robin")
	flag.Parse()
	return c
}

func main() { os.Exit(run()) }

func run() int {
	cfg := parseFlags()
	if cfg.bin == "" || cfg.homes < 1 || cfg.phones < 0 || cfg.live <= 0 || cfg.cmd <= 0 || cfg.max < 10*time.Second {
		fmt.Fprintln(os.Stderr, "ftwload: need -ftwcloudd, -homes >= 1, -phones >= 0, positive -live and -cmd, -max >= 10s")
		return 2
	}
	runtime.GOMAXPROCS(cfg.procs)
	dir, err := os.MkdirTemp("", "ftwload-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "ftwload:", err)
		return 1
	}

	// Every way out goes through cleanup: kill the child, drop the keys.
	var child atomic.Pointer[server]
	var cleanOnce sync.Once
	cleanup := func() {
		cleanOnce.Do(func() {
			if s := child.Load(); s != nil {
				s.kill()
			}
			_ = os.RemoveAll(dir)
		})
	}
	defer cleanup()
	hard := time.AfterFunc(cfg.max, func() {
		fmt.Fprintln(os.Stderr, "ftwload: hard deadline; ftwcloudd killed")
		cleanup()
		os.Exit(3)
	})
	defer hard.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.max-4*time.Second)
	defer cancel()
	sigc := make(chan os.Signal, 2)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigc // the first ends the run with a summary, the second at once
		cancel()
		<-sigc
		cleanup()
		os.Exit(130)
	}()

	srv, err := startServer(ctx, cfg, dir, &child)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ftwload:", err)
		return 1
	}
	dialer, err := newDialer(srv.pool, cfg.src)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ftwload:", err)
		return 2
	}
	h := &harness{cfg: cfg, url: "wss://" + srv.addr, dialer: dialer, service: srv.service, noise: srv.noise,
		stats: newStats(), wantBoxes: int64(cfg.homes), wantPhones: int64(cfg.homes * cfg.phones)}
	// One sample of the idle service before any load, then one a second.
	samp := &sampler{}
	samp.take(srv.cmd.Process.Pid)
	go samp.run(ctx, srv.cmd.Process.Pid, srv.exited)

	boxes := make([]*box, cfg.homes)
	for i := range boxes {
		boxes[i] = newBox(h)
	}
	clients, stopClients := context.WithCancel(ctx)
	defer stopClients()
	var wg sync.WaitGroup
	h.t0 = time.Now()
	half := cfg.ramp / 2
	for i, b := range boxes {
		wg.Go(func() { b.run(clients, spread(half, i, cfg.homes)) })
	}
	for i, b := range boxes {
		for j, key := range b.phones {
			at := h.t0.Add(half + spread(cfg.ramp-half, i*cfg.phones+j, cfg.homes*cfg.phones))
			p := &phone{b: b, key: key}
			wg.Go(func() { p.run(clients, at) })
		}
	}

	// Ramp, then the steady phase once everyone is up.
	allBy := h.t0.Add(cfg.ramp + 10*time.Second)
	for ctx.Err() == nil && time.Now().Before(allBy) &&
		(h.allBoxesAt.Load() == 0 || (h.wantPhones > 0 && h.allPhonesAt.Load() == 0) || time.Since(h.t0) < cfg.ramp) {
		time.Sleep(20 * time.Millisecond)
	}
	steadyStart := time.Now()
	h.measuring.Store(true)
	var stormC, sigC <-chan time.Time
	if cfg.stormAt > 0 {
		stormC = time.After(cfg.stormAt)
	}
	if cfg.sigtermAt > 0 {
		sigC = time.After(cfg.sigtermAt)
	}
	end := time.After(cfg.duration)
	var stormAt, sigAt time.Time
	diedEarly := false
steady:
	for {
		select {
		case <-ctx.Done():
			break steady
		case <-end:
			break steady
		case <-stormC:
			stormAt = time.Now()
			h.storm(boxes)
		case <-sigC:
			sigAt = time.Now()
			h.stopping.Store(true)
			_ = srv.cmd.Process.Signal(syscall.SIGTERM)
			break steady
		case <-srv.exited:
			diedEarly = true
			break steady
		}
	}
	steadyEnd := time.Now()
	h.measuring.Store(false)
	h.quiet.Store(true)
	boxesUp, phonesUp := h.boxesUp.Load(), h.phonesUp.Load()

	var exitedAt time.Time
	if !sigAt.IsZero() {
		// The service drains: wait for it to exit, then for the sockets
		// to report how they ended.
		select {
		case <-srv.exited:
			exitedAt = time.Now()
		case <-ctx.Done():
		case <-time.After(65 * time.Second):
		}
		sleep(ctx, 500*time.Millisecond)
	} else {
		// Let the last echoes come back, at most 5 s, and a storm finish.
		for drain := time.Now().Add(5 * time.Second); ctx.Err() == nil && time.Now().Before(drain) && h.stats.outstanding() > 0; {
			time.Sleep(20 * time.Millisecond)
		}
		for wait := time.Now().Add(30 * time.Second); !stormAt.IsZero() && h.stormDone.Load() == 0 &&
			ctx.Err() == nil && time.Now().Before(wait); {
			time.Sleep(50 * time.Millisecond)
		}
	}
	stopClients()
	waited := make(chan struct{})
	go func() { wg.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
	}
	srv.kill()

	rep := h.report(samp, steadyStart, steadyEnd, stormAt, sigAt, exitedAt, boxesUp, phonesUp)
	rep.ServerLog = scanLog(srv.logPath)
	if diedEarly {
		rep.Notes = append(rep.Notes, "ftwcloudd exited during the steady phase")
	}
	if ctx.Err() != nil {
		rep.Notes = append(rep.Notes, "the run ended early (deadline or signal)")
	}
	rep.print(os.Stdout)
	if cfg.jsonPath != "" {
		if err := rep.writeJSON(cfg.jsonPath); err != nil {
			fmt.Fprintln(os.Stderr, "ftwload:", err)
			return 1
		}
	}
	return 0
}

// spread is the i-th of n start offsets evenly over d.
func spread(d time.Duration, i, n int) time.Duration {
	if n <= 0 {
		return 0
	}
	return d * time.Duration(i) / time.Duration(n)
}

// harness is what boxes and phones share.
type harness struct {
	cfg     config
	url     string
	dialer  *websocket.Dialer
	service *ecdsa.PublicKey
	noise   []byte
	stats   *stats
	t0      time.Time

	// measuring is on during the steady phase; quiet stops phones sending
	// after it; stopping stops every redial once the service was told to
	// stop.
	measuring, quiet, stopping atomic.Bool

	wantBoxes, wantPhones     int64
	boxesUp, phonesUp         atomic.Int64
	allBoxesAt, allPhonesAt   atomic.Int64 // ns after t0, 0 until reached
	stormStart                atomic.Int64 // unix ns
	stormRecovered, stormDone atomic.Int64 // count; unix ns when all were back
}

func (h *harness) up(n *atomic.Int64, want int64, at *atomic.Int64) {
	if n.Add(1) == want {
		at.CompareAndSwap(0, int64(time.Since(h.t0)))
	}
}

// storm closes every box socket at once, from the client side, without a
// close frame. Each box redials within -storm-jitter.
func (h *harness) storm(boxes []*box) {
	h.stormStart.Store(time.Now().UnixNano())
	for _, b := range boxes {
		b.stormed.Store(true)
	}
	for _, b := range boxes {
		if c := b.conn.Load(); c != nil {
			_ = c.Close()
		}
	}
}

func (h *harness) recovered(hs time.Duration) {
	h.stats.stormHS.add(hs)
	if h.stormRecovered.Add(1) == h.wantBoxes {
		h.stormDone.CompareAndSwap(0, time.Now().UnixNano())
	}
}

// redial counts why a socket ended or failed to open and waits before the
// next dial. False means do not dial again.
func (h *harness) redial(ctx context.Context, label string, err error, attempt *int) bool {
	if ctx.Err() != nil {
		return false
	}
	delay := backoff(*attempt)
	*attempt++
	var ce *websocket.CloseError
	if errors.As(err, &ce) {
		h.stats.fail(fmt.Sprintf("%s.close.%d", label, ce.Code))
		switch ce.Code {
		case cloudwire.CloseRestart:
			h.stats.restart(label, ce.Text)
			delay = jitter(time.Duration(cloudwire.RestartSpreadMs(ce.Text)) * time.Millisecond)
			*attempt = 0
		case cloudwire.CloseWrongShard:
			// No second host here: note where it pointed and dial again.
			h.stats.wrongShard(ce.Text)
		}
	} else {
		h.stats.fail(label + ".error")
	}
	if h.stopping.Load() {
		h.stats.afterStop(ce != nil && ce.Code == cloudwire.CloseRestart)
		return false
	}
	return sleep(ctx, delay)
}

// backoff is full jitter between 0 and 0.5 s doubled per attempt, up to 60 s.
func backoff(attempt int) time.Duration {
	return jitter(min(60*time.Second, 500*time.Millisecond<<min(attempt, 7)))
}

func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return time.Duration(randN(int64(d)))
}

func sleep(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func newDialer(pool *x509.CertPool, src string) (*websocket.Dialer, error) {
	d := &websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13},
		HandshakeTimeout: handshakeTimeout, WriteBufferPool: &sync.Pool{}}
	if src == "" {
		return d, nil
	}
	var addrs []*net.TCPAddr
	for _, s := range strings.Split(src, ",") {
		ip := net.ParseIP(strings.TrimSpace(s))
		if ip == nil {
			return nil, fmt.Errorf("-src: %q is not an IP", s)
		}
		addrs = append(addrs, &net.TCPAddr{IP: ip})
	}
	var next atomic.Uint64
	d.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		nd := net.Dialer{LocalAddr: addrs[next.Add(1)%uint64(len(addrs))]}
		return nd.DialContext(ctx, network, addr)
	}
	return d, nil
}

// --------------------------------------------------------------------------
// The child process
// --------------------------------------------------------------------------

type server struct {
	cmd      *exec.Cmd
	exited   chan struct{}
	dog      *exec.Cmd
	logPath  string
	addr     string
	service  *ecdsa.PublicKey
	noise    []byte
	pool     *x509.CertPool
	killOnce sync.Once
}

// startServer makes keys and a certificate in dir, starts ftwcloudd on a
// free loopback port and waits for /healthz.
func startServer(ctx context.Context, cfg config, dir string, slot *atomic.Pointer[server]) (*server, error) {
	s := &server{logPath: filepath.Join(dir, "server.log"), exited: make(chan struct{})}
	servicePath, noisePath := filepath.Join(dir, "service.key"), filepath.Join(dir, "noise.key")
	pk, err := keygen(ctx, cfg.bin, servicePath)
	if err != nil {
		return nil, err
	}
	if s.service, err = cloudwire.ParsePublicKey(pk); err != nil {
		return nil, err
	}
	if s.noise, err = keygen(ctx, cfg.bin, noisePath, "-noise"); err != nil {
		return nil, err
	}
	certPath, keyPath := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if s.pool, err = selfSigned(certPath, keyPath); err != nil {
		return nil, err
	}
	state := filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		return nil, err
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s.addr = l.Addr().String()
	_ = l.Close()
	logf, err := os.Create(s.logPath)
	if err != nil {
		return nil, err
	}
	s.cmd = exec.Command(cfg.bin, "-listen", s.addr, "-state", state, "-service-key", servicePath,
		"-noise-key", noisePath, "-tls-cert", certPath, "-tls-key", keyPath, "-apns-dir", filepath.Join(dir, "no-apns"))
	s.cmd.Env = append(withoutEnv(os.Environ(), "GOMAXPROCS"), "GOMAXPROCS="+strconv.Itoa(cfg.serverProcs))
	s.cmd.Stdout, s.cmd.Stderr = logf, logf
	if err := s.cmd.Start(); err != nil {
		_ = logf.Close()
		return nil, err
	}
	slot.Store(s)
	go func() {
		_ = s.cmd.Wait()
		_ = logf.Close()
		close(s.exited)
	}()
	s.watchdog(cfg.bin, cfg.max+5*time.Second)
	return s, s.waitHealthy(ctx)
}

// watchdog kills the child at the deadline even if the harness itself is
// gone. It runs in its own process group so kill can take its sleep too.
func (s *server) watchdog(bin string, after time.Duration) {
	name := filepath.Base(bin)
	if len(name) > 15 {
		name = name[:15] // Linux truncates comm
	}
	pid := strconv.Itoa(s.cmd.Process.Pid)
	dog := exec.Command("/bin/sh", "-c", `sleep "$1"; ps -p "$2" -o comm= | grep -qF -- "$3" && kill -9 "$2"`,
		"ftwload-watchdog", strconv.Itoa(int(after.Seconds())+1), pid, name)
	dog.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if dog.Start() == nil {
		s.dog = dog
		go func() { _ = dog.Wait() }()
	}
}

func (s *server) kill() {
	s.killOnce.Do(func() {
		_ = s.cmd.Process.Kill()
		select {
		case <-s.exited:
		case <-time.After(3 * time.Second):
		}
		if s.dog != nil {
			_ = syscall.Kill(-s.dog.Process.Pid, syscall.SIGKILL)
		}
	})
}

func (s *server) waitHealthy(ctx context.Context) error {
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: s.pool, MinVersion: tls.VersionTLS13}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 2 * time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-s.exited:
			return fmt.Errorf("ftwcloudd exited at start:\n%s", tail(s.logPath, 20))
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		if resp, err := client.Get("https://" + s.addr + "/healthz"); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
	}
	return fmt.Errorf("ftwcloudd did not answer /healthz in 15 s:\n%s", tail(s.logPath, 20))
}

// keygen runs ftwcloudd keygen and returns the public half it prints.
func keygen(ctx context.Context, bin, out string, extra ...string) ([]byte, error) {
	args := append([]string{"keygen"}, extra...)
	raw, err := exec.CommandContext(ctx, bin, append(args, "-out", out)...).Output()
	if err != nil {
		return nil, fmt.Errorf("ftwcloudd keygen: %w", err)
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(raw)))
}

// selfSigned writes an ECDSA certificate for 127.0.0.1 and returns a pool
// that trusts it.
func selfSigned(certPath, keyPath string) (*x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ftwload"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool, nil
}

func withoutEnv(env []string, name string) []string {
	out := env[:0:0]
	for _, kv := range env {
		if !strings.HasPrefix(kv, name+"=") {
			out = append(out, kv)
		}
	}
	return out
}

func tail(path string, n int) string {
	b, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}
