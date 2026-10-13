//go:build ftwclouddev

package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/srcfl/ftw-cloud/internal/apns"
	"github.com/srcfl/ftw-cloud/internal/push"
	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw/go/protocol/cloudwire"
)

// serveDevPush listens on loopback for two routes. Release builds have
// neither.
//
//   - POST /dev/push/register registers an APNs token for a device in a
//     home's signed roster, as the app's session will, so an end-to-end test
//     can run before the app session can.
//   - POST /dev/push/raw {home, payload} sends a payload as it is to the
//     home's registered phones, so a test can put a forged one through Apple
//     and see the phone refuse it.
func serveDevPush(ctx context.Context, addr string, reg *registry.Registry, svc *push.Service, sender push.Sender, log *slog.Logger) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return errors.New("-dev-push-listen must be a loopback address")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /dev/push/register", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Home        string `json:"home"`
			DeviceID    string `json:"deviceId"`
			Token       string `json:"apnsToken"`
			Environment string `json:"environment"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		token, err := hex.DecodeString(req.Token)
		if err != nil {
			http.Error(w, "apnsToken is hex", http.StatusBadRequest)
			return
		}
		dev, scopes, ok := rosterDevice(reg, req.Home, req.DeviceID)
		if !ok {
			http.Error(w, "no such device in the home's roster", http.StatusNotFound)
			return
		}
		if err := svc.Register(req.Home, dev, scopes, cloudwire.PushRegister{
			APNsToken: token, Environment: req.Environment, Kind: cloudwire.PushKindAlert}); err != nil {
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /dev/push/raw", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Home    string          `json:"home"`
			Payload json.RawMessage `json:"payload"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Payload) == 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		if sender == nil {
			http.Error(w, "no APNs key", http.StatusServiceUnavailable)
			return
		}
		regs, err := reg.PushRegs(req.Home, cloudwire.PushKindAlert)
		if err != nil || len(regs) == 0 {
			http.Error(w, "no phone registered for that home", http.StatusNotFound)
			return
		}
		var out []string
		for _, x := range regs {
			res, err := sender.Send(r.Context(), apns.Notification{Environment: x.Environment, DeviceToken: x.Token,
				Payload: req.Payload, Expiration: time.Now().Add(10 * time.Minute)})
			out = append(out, fmt.Sprintf("%d %s %v", res.Status, res.Reason, err))
		}
		_ = json.NewEncoder(w).Encode(out)
	})
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Warn("dev push route stopped", "err", err)
		}
	}()
	log.Warn("development build: tokens can be registered by hand", "addr", addr)
	return nil
}

// captureSender writes each alert to dir as <n>.json, {environment,
// deviceToken, payload}, and tells the service Apple took it. A test hands
// the payload to a simulator with xcrun simctl push.
func captureSender(dir string) (push.Sender, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &capture{dir: dir}, nil
}

type capture struct {
	mu  sync.Mutex
	dir string
	n   int
}

func (c *capture) Send(_ context.Context, n apns.Notification) (apns.Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	raw, err := json.Marshal(map[string]any{"environment": n.Environment,
		"deviceToken": hex.EncodeToString(n.DeviceToken), "payload": json.RawMessage(n.Payload)})
	if err != nil {
		return apns.Result{}, err
	}
	name := filepath.Join(c.dir, fmt.Sprintf("%04d.json", c.n))
	if err := os.WriteFile(name+".tmp", raw, 0o600); err != nil {
		return apns.Result{}, err
	}
	return apns.Result{Status: http.StatusOK}, os.Rename(name+".tmp", name)
}

// rosterDevice finds a device in the roster the box last signed, with its
// effective scope.
func rosterDevice(reg *registry.Registry, home, id string) (cloudwire.Device, []string, bool) {
	h, ok, err := reg.Get(home)
	if err != nil || !ok || h.Roster == nil {
		return cloudwire.Device{}, nil, false
	}
	env, err := cloudwire.DecodeEnvelope(h.Roster)
	if err != nil {
		return cloudwire.Device{}, nil, false
	}
	var r cloudwire.Roster
	if cloudwire.Unmarshal(env.B, &r) != nil {
		return cloudwire.Device{}, nil, false
	}
	for _, d := range r.Devices {
		if d.ID != id {
			continue
		}
		var scopes []string
		for _, s := range d.Scopes {
			if slices.Contains(r.Grant.Scopes, s) {
				scopes = append(scopes, s)
			}
		}
		return d, scopes, true
	}
	return cloudwire.Device{}, nil, false
}
