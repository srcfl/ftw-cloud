package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/srcfl/ftw/go/protocol/ohttp"
)

// keygen prints the configuration Core pins, and ftwcloudd loads the same
// key back from the file under the same id.
func TestAGatewayKeyLoadsAsThePinSays(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ohttp.key")
	pin := captureStdout(t, func() error { return keygenOHTTP(path) })
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(pin))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ohttp.ParseKeyConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	gw, err := loadOHTTPKeys(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := gw.Configs(); len(got) != 1 || !bytes.Equal(got[0].Marshal(), raw) || cfg.ID != ohttpKeyID(cfg.PublicKey) {
		t.Fatalf("loaded %+v, pinned %+v", got, cfg)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v", info.Mode())
	}
	if err := keygenOHTTP(path); err == nil {
		t.Fatal("keygen wrote over a key")
	}

	// A rotation is a second block in the same file.
	second := filepath.Join(dir, "second.key")
	captureStdout(t, func() error { return keygenOHTTP(second) })
	a, _ := os.ReadFile(path)
	b, _ := os.ReadFile(second)
	both := filepath.Join(dir, "both.key")
	if err := os.WriteFile(both, append(a, b...), 0o600); err != nil {
		t.Fatal(err)
	}
	if gw, err := loadOHTTPKeys(both); err != nil && !strings.Contains(err.Error(), "one id") || err == nil && len(gw.Configs()) != 2 {
		t.Fatalf("two keys: %v", err)
	}
	if pins := ohttpPins(nil); pins != "" {
		t.Fatal(pins)
	}

	// A second block cut short, as a rotation pasted in part leaves it, is
	// refused rather than quietly left unloaded.
	for name, data := range map[string][]byte{
		"cut after a whole key":  append(append([]byte{}, a...), b[:len(b)/2]...),
		"cut before a whole key": append(append([]byte{}, b[:len(b)/2]...), a...),
		"text between keys":      append(append(append([]byte{}, a...), []byte("note\n")...), b...),
	} {
		cut := filepath.Join(dir, "cut.key")
		if err := os.WriteFile(cut, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadOHTTPKeys(cut); err == nil || !strings.Contains(err.Error(), "not a whole PKCS #8 key") {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestOnlyX25519GatewayKeysLoad(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadOHTTPKeys(filepath.Join(dir, "missing.key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	service := filepath.Join(dir, "service.key")
	captureStdout(t, func() error { return keygen([]string{"-out", service}) })
	empty := filepath.Join(dir, "empty.key")
	_ = os.WriteFile(empty, []byte("no key here\n"), 0o600)
	for _, p := range []string{service, empty} {
		if _, err := loadOHTTPKeys(p); err == nil {
			t.Fatalf("%s loaded", p)
		}
	}
}

func captureStdout(t *testing.T, f func() error) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := f()
	os.Stdout = old
	_ = w.Close()
	out, _ := io.ReadAll(r)
	if runErr != nil {
		t.Fatal(runErr)
	}
	return string(out)
}
