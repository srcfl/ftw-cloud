//go:build ftwclouddev

package server

import (
	"encoding/json"
	"net"
	"net/http"
)

// A local test binary answers /dev/held?home=<id> from loopback with the
// envelopes the store holds. Release builds do not compile this file.
func init() {
	devRoutes = func(mux *http.ServeMux, s *Server) {
		mux.HandleFunc("/dev/held", func(w http.ResponseWriter, r *http.Request) {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				http.NotFound(w, r)
				return
			}
			latest, online, ok := s.Store.Inspect(r.URL.Query().Get("home"))
			if !ok {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"online": online, "envelopes": latest})
		})
	}
}
