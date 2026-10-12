// Package server is ftwcloudd's HTTP surface. It is small on purpose: every
// route is listed in Routes, and TestNoRouteReadsAHome holds the list.
//
//	/v1/box   a box's uplink (package uplink)
//	/v1/app   the app's Noise session to the service: C3, not built yet
//	/v1/now   an extension's token read: C5, not built yet
//	/source   the source of the running service, as AGPL-3.0 asks
//	/healthz  liveness, and nothing about any home
//
// There is no route for staff. Reading a home needs its box's key or a
// phone in its roster.
package server

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/srcfl/ftw-cloud/internal/registry"
	"github.com/srcfl/ftw-cloud/internal/store"
	"github.com/srcfl/ftw-cloud/internal/uplink"
)

// SourceArchive is where the image keeps the source it was built from.
const SourceArchive = "/usr/share/ftw-cloud/source.tar.gz"

// Routes are every path the service answers.
var Routes = []string{"/v1/box", "/v1/app", "/v1/now", "/source", "/healthz"}

// devRoutes adds a local inspection route in binaries built with
// -tags ftwclouddev. It is nil in every other build.
var devRoutes func(mux *http.ServeMux, s *Server)

// Server wires the store, the registry and the routes.
type Server struct {
	Store    *store.Store
	Registry *registry.Registry
	Uplink   *uplink.Uplink
	Log      *slog.Logger
}

// Handler is the whole HTTP surface.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/v1/box", s.Uplink)
	// C3: the app opens a WebSocket here and runs Noise IK to the service's
	// static key, with prologue "ftw.cloud.v1:" and the home id. The
	// service admits a phone only through store.For with a Device
	// principal, and forwards the box's envelopes unchanged.
	mux.HandleFunc("/v1/app", notYet)
	// C5: widgets read the newest live, prices and hb here with a 7-day
	// token bound to one roster entry.
	mux.HandleFunc("/v1/now", notYet)
	mux.HandleFunc("/source", source)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})
	if devRoutes != nil {
		devRoutes(mux, s)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", `</source>; rel="copyright"; title="AGPL-3.0 source"`)
		mux.ServeHTTP(w, r)
	})
}

func notYet(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not available yet", http.StatusNotImplemented)
}

// source serves the archive the image was built from. A development build
// has none and says where the source lives.
func source(w http.ResponseWriter, r *http.Request) {
	if rev := revision(); rev != "" {
		w.Header().Set("X-Source-Revision", rev)
	}
	f, err := os.Open(SourceArchive)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("Development build: matching source must be supplied by the operator. https://github.com/srcfl/ftw-cloud\n"))
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", `attachment; filename="ftw-cloud-source.tar.gz"`)
	http.ServeContent(w, r, "ftw-cloud-source.tar.gz", time.Time{}, f)
}

// revision is the commit this binary was built from, when the build recorded
// one.
func revision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	rev, dirty := "", false
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if rev != "" && dirty {
		rev += "+modified"
	}
	return rev
}

// Upkeep applies the retention rules until ctx ends: readings go an hour
// after the box does, homes without a roster go after 24 hours or 90 days,
// and old tombstones go.
func (s *Server) Upkeep(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.Store.Sweep()
			gone, err := s.Registry.Expire(time.Now())
			if err != nil {
				s.Log.Warn("registry upkeep failed", "err", err)
				continue
			}
			for _, h := range gone {
				s.Store.Forget(h)
			}
			if len(gone) > 0 {
				s.Log.Info("homes expired", "count", len(gone))
			}
		}
	}
}
