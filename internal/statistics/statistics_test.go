package statistics

import (
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/srcfl/ftw-cloud/internal/registry"
)

func TestCollectionOffByDefaultCannotLookLikeZeroUsage(t *testing.T) {
	r, err := registry.Open(filepath.Join(t.TempDir(), "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s, err := New(r)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/v1/stats", nil))
	if w.Code != 503 || w.Header().Get("FTW-Statistics-State") != "disabled" {
		t.Fatalf("disabled collection pretended to be zero usage: %d", w.Code)
	}
	s.Enabled = true
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest("GET", "/v1/stats", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}
