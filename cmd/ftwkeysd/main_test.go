package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A production build has no file key and no local offer key: both keys must
// be in KMS.
func TestAProductionBuildNeedsBothKeysInKMS(t *testing.T) {
	if devBuild {
		t.Skip("a development build")
	}
	parse := func(args ...string) (keyFlags, error) {
		fs := flag.NewFlagSet("ftwkeysd", flag.ContinueOnError)
		fs.SetOutput(io.Discard)
		kf := addKeyFlags(fs)
		return kf, fs.Parse(args)
	}
	if _, err := parse("-file-key=dev.key"); err == nil {
		t.Fatal("a production build takes -file-key")
	}
	if devCommand("filekey", []string{"-out", filepath.Join(t.TempDir(), "k")}) {
		t.Fatal("a production build makes file keys")
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	kf, _ := parse()
	if _, _, err := kf.options(context.Background(), log); err == nil || !strings.Contains(err.Error(), "-kms-key") {
		t.Fatalf("no sealer: %v", err)
	}
	kf, _ = parse("-kms-key=alias/ftw-cloud-agent-keys")
	if _, _, err := kf.options(context.Background(), log); err == nil || !strings.Contains(err.Error(), "-offer-kms-key") {
		t.Fatalf("no offer key: %v", err)
	}
}

// The keys role's credentials come from the file the host renews, and
// expire when it says.
func TestCredentialsComeFromTheHostsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	exp := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	body := `{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"s","SessionToken":"t","Expiration":"` + exp.Format("2006-01-02T15:04:05+00:00") + `"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := fileCredentials(path).Retrieve(context.Background())
	if err != nil || c.AccessKeyID != "ASIAEXAMPLE" || !c.CanExpire || !c.Expires.Equal(exp) {
		t.Fatalf("%+v %v", c, err)
	}
	_ = os.WriteFile(path, []byte(`{"AccessKeyId":"x"}`), 0o600)
	if _, err := fileCredentials(path).Retrieve(context.Background()); err == nil {
		t.Fatal("a file without an expiry was taken")
	}
}
