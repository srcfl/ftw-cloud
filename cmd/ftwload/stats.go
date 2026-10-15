package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// maxSamples bounds each latency series; past it, reservoir sampling.
const maxSamples = 200_000

// series keeps latencies for percentiles.
type series struct {
	mu      sync.Mutex
	n       int64
	max     time.Duration
	samples []time.Duration
}

func (s *series) add(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.n++
	s.max = max(s.max, d)
	if len(s.samples) < maxSamples {
		s.samples = append(s.samples, d)
	} else if j := randN(s.n); j < maxSamples {
		s.samples[j] = d
	}
}

type latency struct {
	Count int64   `json:"count"`
	P50   float64 `json:"p50Ms"`
	P95   float64 `json:"p95Ms"`
	P99   float64 `json:"p99Ms"`
	Max   float64 `json:"maxMs"`
}

func (s *series) summary() latency {
	s.mu.Lock()
	sorted := slices.Clone(s.samples)
	l := latency{Count: s.n, Max: ms(s.max)}
	s.mu.Unlock()
	if len(sorted) == 0 {
		return l
	}
	slices.Sort(sorted)
	at := func(q float64) float64 {
		return ms(sorted[max(0, int(math.Ceil(q*float64(len(sorted))))-1)])
	}
	l.P50, l.P95, l.P99 = at(0.50), at(0.95), at(0.99)
	return l
}

func (l latency) String() string {
	if l.Count == 0 {
		return "none"
	}
	return fmt.Sprintf("p50 %.2f  p95 %.2f  p99 %.2f  max %.2f ms  (n %d)", l.P50, l.P95, l.P99, l.Max, l.Count)
}

func ms(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }

// stats is every count the clients keep.
type stats struct {
	boxHS, phoneHS, stormHS, tunRTT, live series

	tunSent, tunEchoed, tunLost, tunLate, tunEnded atomic.Int64

	mu         sync.Mutex
	errors     map[string]int64
	reasons    map[string]int64 // 4503 reasons
	shards     map[string]int64 // 4421 reasons
	restartBy  map[string]int64 // 4503 by socket kind
	stopped    struct{ restart, other int64 }
	lastStopAt time.Time
}

func newStats() *stats {
	return &stats{errors: map[string]int64{}, reasons: map[string]int64{}, shards: map[string]int64{},
		restartBy: map[string]int64{}}
}

func (s *stats) outstanding() int64 { return s.tunSent.Load() - s.tunEchoed.Load() - s.tunLost.Load() }

func (s *stats) fail(kind string) {
	s.mu.Lock()
	s.errors[kind]++
	s.mu.Unlock()
}

func (s *stats) restart(label, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.restartBy[strings.SplitN(label, ".", 2)[0]]++
	bump(s.reasons, reason)
}

func (s *stats) wrongShard(host string) {
	s.mu.Lock()
	bump(s.shards, host)
	s.mu.Unlock()
}

// afterStop counts a socket that ended after the service was sent SIGTERM.
func (s *stats) afterStop(restart bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if restart {
		s.stopped.restart++
	} else {
		s.stopped.other++
	}
	s.lastStopAt = time.Now()
}

// bump counts a value, keeping at most 20 distinct ones.
func bump(m map[string]int64, v string) {
	if _, ok := m[v]; !ok && len(m) >= 20 {
		v = "(other)"
	}
	m[v]++
}

// --------------------------------------------------------------------------
// The service's CPU and memory
// --------------------------------------------------------------------------

type sample struct {
	at     time.Time
	rssKiB int64
	cpu    time.Duration
}

type sampler struct {
	mu sync.Mutex
	s  []sample
}

// run reads ps for the child once a second until it exits.
func (m *sampler) run(ctx context.Context, pid int, exited <-chan struct{}) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-exited:
			return
		case <-t.C:
		}
		m.take(pid)
	}
}

func (m *sampler) take(pid int) {
	out, err := exec.Command("ps", "-o", "rss=,time=", "-p", strconv.Itoa(pid)).Output()
	if err != nil {
		return
	}
	f := strings.Fields(string(out))
	if len(f) < 2 {
		return
	}
	rss, err1 := strconv.ParseInt(f[0], 10, 64)
	cpu, err2 := parseCPUTime(f[1])
	if err1 != nil || err2 != nil {
		return
	}
	m.mu.Lock()
	m.s = append(m.s, sample{at: time.Now(), rssKiB: rss, cpu: cpu})
	m.mu.Unlock()
}

// parseCPUTime reads ps time: [dd-][hh:]mm:ss[.ss], as macOS and Linux
// print it.
func parseCPUTime(s string) (time.Duration, error) {
	var days float64
	if d, rest, ok := strings.Cut(s, "-"); ok {
		v, err := strconv.ParseFloat(d, 64)
		if err != nil {
			return 0, err
		}
		days, s = v, rest
	}
	var secs float64
	for _, part := range strings.Split(s, ":") {
		v, err := strconv.ParseFloat(part, 64)
		if err != nil {
			return 0, err
		}
		secs = secs*60 + v
	}
	return time.Duration((days*86400 + secs) * float64(time.Second)), nil
}

func (m *sampler) samples() []sample {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.s)
}

// within is the samples taken in [a, b].
func within(all []sample, a, b time.Time) []sample {
	var out []sample
	for _, s := range all {
		if !s.at.Before(a) && !s.at.After(b) {
			out = append(out, s)
		}
	}
	return out
}

// cpuPct is the average CPU over the samples, 100 = one core.
func cpuPct(s []sample) float64 {
	if len(s) < 2 {
		return 0
	}
	first, last := s[0], s[len(s)-1]
	return 100 * float64(last.cpu-first.cpu) / float64(last.at.Sub(first.at))
}

// peakCPUPct is the highest CPU between two neighbouring samples.
func peakCPUPct(s []sample) float64 {
	var peak float64
	for i := 1; i < len(s); i++ {
		peak = max(peak, cpuPct(s[i-1:i+1]))
	}
	return peak
}

func mib(kib int64) float64 { return float64(kib) / 1024 }

// --------------------------------------------------------------------------
// The report
// --------------------------------------------------------------------------

type report struct {
	Config struct {
		Homes         int     `json:"homes"`
		PhonesPerHome int     `json:"phonesPerHome"`
		Copy          bool    `json:"copy"`
		LiveS         float64 `json:"liveS"`
		CmdS          float64 `json:"cmdS"`
		ServerProcs   int     `json:"serverProcs"`
		HarnessProcs  int     `json:"harnessProcs"`
		SteadyS       float64 `json:"steadyS"`
	} `json:"config"`
	Connects struct {
		BoxesUp      int64   `json:"boxesUp"`
		BoxesWanted  int64   `json:"boxesWanted"`
		PhonesUp     int64   `json:"phonesUp"`
		PhonesWanted int64   `json:"phonesWanted"`
		AllBoxesS    float64 `json:"allBoxesS"`  // -1: never
		AllPhonesS   float64 `json:"allPhonesS"` // -1: never
	} `json:"connects"`
	Handshake struct {
		Box   latency `json:"box"`
		Phone latency `json:"phone"`
	} `json:"handshake"`
	Tun struct {
		RoundTrip latency `json:"roundTrip"`
		Sent      int64   `json:"sent"`
		Echoed    int64   `json:"echoed"`
		Lost      int64   `json:"lost"`
		Late      int64   `json:"late"`
		Ended     int64   `json:"ended"`
	} `json:"tun"`
	Live   latency          `json:"live"`
	Errors map[string]int64 `json:"errors"`
	Server struct {
		CPUPct         float64          `json:"cpuPct"`
		PeakRSSMiB     float64          `json:"peakRssMiB"`
		SteadyRSSMiB   float64          `json:"steadyRssMiB"`
		IdleRSSMiB     float64          `json:"idleRssMiB"`
		CPUPctPer1k    float64          `json:"cpuPctPer1kHomes"`
		MiBPer1k       float64          `json:"miBPer1kHomes"` // steady minus idle
		Samples        int              `json:"samples"`
		WrongShardSeen map[string]int64 `json:"wrongShardSeen,omitempty"`
	} `json:"server"`
	Storm     *stormReport   `json:"storm,omitempty"`
	Sigterm   *sigtermReport `json:"sigterm,omitempty"`
	ServerLog logReport      `json:"serverLog"`
	Notes     []string       `json:"notes,omitempty"`
}

type stormReport struct {
	Recovered  int64   `json:"recovered"`
	Wanted     int64   `json:"wanted"`
	RecoveryS  float64 `json:"recoveryS"` // -1: not all came back
	Handshake  latency `json:"handshake"`
	PeakCPUPct float64 `json:"peakCpuPct"`
	AvgCPUPct  float64 `json:"avgCpuPct"`
}

type sigtermReport struct {
	SocketsUp  int64            `json:"socketsUp"`
	Restart    map[string]int64 `json:"restart4503"`
	Reasons    map[string]int64 `json:"reasons"`
	OtherEnds  int64            `json:"otherEnds"`
	LastEndS   float64          `json:"lastEndS"`
	ChildExitS float64          `json:"childExitS"` // -1: did not exit
}

func (h *harness) report(samp *sampler, start, end, stormAt, sigAt, exitedAt time.Time, boxesUp, phonesUp int64) *report {
	r := &report{}
	c := h.cfg
	r.Config.Homes, r.Config.PhonesPerHome, r.Config.Copy = c.homes, c.phones, c.copy
	r.Config.LiveS, r.Config.CmdS = c.live.Seconds(), c.cmd.Seconds()
	r.Config.ServerProcs, r.Config.HarnessProcs, r.Config.SteadyS = c.serverProcs, c.procs, end.Sub(start).Seconds()

	r.Connects.BoxesUp, r.Connects.BoxesWanted = boxesUp, h.wantBoxes
	r.Connects.PhonesUp, r.Connects.PhonesWanted = phonesUp, h.wantPhones
	since := func(ns int64) float64 {
		if ns == 0 {
			return -1
		}
		return time.Duration(ns).Seconds()
	}
	r.Connects.AllBoxesS, r.Connects.AllPhonesS = since(h.allBoxesAt.Load()), since(h.allPhonesAt.Load())
	if h.wantPhones == 0 {
		r.Connects.AllPhonesS = 0
	}

	st := h.stats
	r.Handshake.Box, r.Handshake.Phone = st.boxHS.summary(), st.phoneHS.summary()
	r.Tun.RoundTrip = st.tunRTT.summary()
	r.Tun.Sent, r.Tun.Echoed, r.Tun.Lost = st.tunSent.Load(), st.tunEchoed.Load(), st.tunLost.Load()
	r.Tun.Late, r.Tun.Ended = st.tunLate.Load(), st.tunEnded.Load()
	r.Live = st.live.summary()

	all := samp.samples()
	steady := within(all, start, end)
	r.Server.Samples = len(steady)
	r.Server.CPUPct = cpuPct(steady)
	var sum int64
	for _, s := range steady {
		sum += s.rssKiB
	}
	if len(steady) > 0 {
		r.Server.SteadyRSSMiB = mib(sum / int64(len(steady)))
	}
	for _, s := range all {
		r.Server.PeakRSSMiB = max(r.Server.PeakRSSMiB, mib(s.rssKiB))
		if s.at.Before(h.t0) {
			r.Server.IdleRSSMiB = mib(s.rssKiB)
		}
	}
	r.Server.CPUPctPer1k = r.Server.CPUPct / float64(c.homes) * 1000
	r.Server.MiBPer1k = (r.Server.SteadyRSSMiB - r.Server.IdleRSSMiB) / float64(c.homes) * 1000

	st.mu.Lock()
	defer st.mu.Unlock()
	r.Errors = st.errors
	if len(st.shards) > 0 {
		r.Server.WrongShardSeen = st.shards
	}
	if !stormAt.IsZero() {
		sr := &stormReport{Recovered: h.stormRecovered.Load(), Wanted: h.wantBoxes, RecoveryS: -1, Handshake: st.stormHS.summary()}
		stormEnd := end
		if done := h.stormDone.Load(); done != 0 {
			stormEnd = time.Unix(0, done)
			sr.RecoveryS = stormEnd.Sub(stormAt).Seconds()
		}
		// Whole-second samples: widen the window by one on each side.
		win := within(all, stormAt.Add(-time.Second), stormEnd.Add(time.Second))
		sr.PeakCPUPct, sr.AvgCPUPct = peakCPUPct(win), cpuPct(win)
		r.Storm = sr
	}
	if !sigAt.IsZero() {
		sr := &sigtermReport{SocketsUp: boxesUp + phonesUp, Restart: st.restartBy, Reasons: st.reasons,
			OtherEnds: st.stopped.other, LastEndS: -1, ChildExitS: -1}
		if !st.lastStopAt.IsZero() {
			sr.LastEndS = st.lastStopAt.Sub(sigAt).Seconds()
		}
		if !exitedAt.IsZero() {
			sr.ChildExitS = exitedAt.Sub(sigAt).Seconds()
		}
		r.Sigterm = sr
	}
	return r
}

func (r *report) print(w io.Writer) {
	c := r.Config
	copyOn := "off"
	if c.Copy {
		copyOn = "on"
	}
	fmt.Fprintf(w, "ftwload: %d homes x %d phones, copy %s, live %gs, cmd %gs, server GOMAXPROCS %d, steady %.1fs\n",
		c.Homes, c.PhonesPerHome, copyOn, c.LiveS, c.CmdS, c.ServerProcs, c.SteadyS)
	cn := r.Connects
	fmt.Fprintf(w, "connects   boxes %d/%d (all at %s)  phones %d/%d (all at %s)\n",
		cn.BoxesUp, cn.BoxesWanted, secs(cn.AllBoxesS), cn.PhonesUp, cn.PhonesWanted, secs(cn.AllPhonesS))
	fmt.Fprintf(w, "handshake  box    %s\n", r.Handshake.Box)
	fmt.Fprintf(w, "           phone  %s\n", r.Handshake.Phone)
	fmt.Fprintf(w, "tun        %s\n", r.Tun.RoundTrip)
	fmt.Fprintf(w, "           sent %d  echoed %d  lost %d  late %d  ended by service %d\n",
		r.Tun.Sent, r.Tun.Echoed, r.Tun.Lost, r.Tun.Late, r.Tun.Ended)
	fmt.Fprintf(w, "live       %s\n", r.Live)
	s := r.Server
	fmt.Fprintf(w, "server     cpu %.1f%% (100 = one core, %d samples)  rss peak %.1f MiB, steady %.1f MiB, idle %.1f MiB\n",
		s.CPUPct, s.Samples, s.PeakRSSMiB, s.SteadyRSSMiB, s.IdleRSSMiB)
	fmt.Fprintf(w, "           per 1k homes: cpu %.1f%%, %.1f MiB above idle\n", s.CPUPctPer1k, s.MiBPer1k)
	if st := r.Storm; st != nil {
		fmt.Fprintf(w, "storm      back %d/%d in %s, server cpu peak %.0f%% avg %.0f%%\n",
			st.Recovered, st.Wanted, secs(st.RecoveryS), st.PeakCPUPct, st.AvgCPUPct)
		fmt.Fprintf(w, "           handshake  %s\n", st.Handshake)
	}
	if sg := r.Sigterm; sg != nil {
		fmt.Fprintf(w, "sigterm    %d sockets up; 4503 box %d phone %d; other ends %d; last end %s; child exit %s\n",
			sg.SocketsUp, sg.Restart["box"], sg.Restart["phone"], sg.OtherEnds, secs(sg.LastEndS), secs(sg.ChildExitS))
		if len(sg.Reasons) > 0 {
			fmt.Fprintf(w, "           reasons %s\n", counts(sg.Reasons))
		}
	}
	if len(s.WrongShardSeen) > 0 {
		fmt.Fprintf(w, "4421       %s\n", counts(s.WrongShardSeen))
	}
	if len(r.Errors) == 0 {
		fmt.Fprintln(w, "errors     none")
	} else {
		fmt.Fprintf(w, "errors     %s\n", counts(r.Errors))
	}
	fmt.Fprintf(w, "server log %d warn, %d error\n", r.ServerLog.Warn, r.ServerLog.Error)
	for _, l := range r.ServerLog.Lines {
		fmt.Fprintf(w, "           %s\n", l)
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "note       %s\n", n)
	}
}

func secs(s float64) string {
	if s < 0 {
		return "never"
	}
	return fmt.Sprintf("%.3fs", s)
}

func counts(m map[string]int64) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%q=%d", k, m[k])
	}
	return strings.Join(parts, " ")
}

func (r *report) writeJSON(path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

// logReport is what ftwcloudd logged at WARN and ERROR, a few lines of it.
type logReport struct {
	Warn  int      `json:"warn"`
	Error int      `json:"error"`
	Lines []string `json:"lines,omitempty"`
}

func scanLog(path string) logReport {
	var r logReport
	f, err := os.Open(path)
	if err != nil {
		return r
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.Contains(line, "level=WARN"):
			r.Warn++
		case strings.Contains(line, "level=ERROR"), strings.HasPrefix(line, "panic"), strings.HasPrefix(line, "fatal"):
			r.Error++
		default:
			continue
		}
		if len(r.Lines) < 5 {
			r.Lines = append(r.Lines, line)
		}
	}
	return r
}
