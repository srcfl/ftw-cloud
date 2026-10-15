// Command ftwkeysd is FTW Cloud's keys part: the one process that can open an
// agent's Noise session to a box. It runs beside ftwcloudd on the same host,
// as another user, and answers only on a local unix socket. See
// internal/keys and deploy/keys.md.
//
//	ftwkeysd filekey -out dev.key       make a development file key
//	ftwkeysd [flags]                    serve
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/srcfl/ftw-cloud/internal/keys"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "filekey" {
		fs := flag.NewFlagSet("filekey", flag.ExitOnError)
		out := fs.String("out", "", "file to write the key to")
		_ = fs.Parse(os.Args[2:])
		if *out == "" {
			fmt.Fprintln(os.Stderr, "filekey: -out is required")
			os.Exit(1)
		}
		if err := keys.MakeFileKey(*out); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := serve(os.Args[1:]); err != nil {
		slog.Error("ftwkeysd stopped", "err", err)
		os.Exit(1)
	}
}

func serve(args []string) error {
	fs := flag.NewFlagSet("ftwkeysd", flag.ExitOnError)
	socket := fs.String("socket", "/run/ftw-cloud-keys/keys.sock", "unix socket to answer on")
	state := fs.String("state", "/state/keys", "directory for the sealed keys")
	kmsKey := fs.String("kms-key", "", "AWS KMS key id, ARN or alias that wraps the data keys")
	region := fs.String("region", "eu-north-1", "AWS region of the KMS key")
	fileKey := fs.String("file-key", "", "a local file key instead of KMS (development only)")
	peerUID := fs.Int("peer-uid", -1, "the one user allowed to connect; -1 is this process's own")
	socketMode := fs.Uint("socket-mode", 0o660, "permissions of the socket file")
	_ = fs.Parse(args)

	harden()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	var sealer keys.Sealer
	switch {
	case *kmsKey != "" && *fileKey != "":
		return errors.New("choose -kms-key or -file-key, not both")
	case *kmsKey != "":
		cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion(*region))
		if err != nil {
			return fmt.Errorf("aws config: %w", err)
		}
		sealer = keys.KMSSealer{KMS: kmsClient{kms.NewFromConfig(cfg)}, KeyID: *kmsKey}
	case *fileKey != "":
		s, err := keys.NewFileSealer(*fileKey)
		if err != nil {
			return err
		}
		log.Warn("agent keys sealed with a local file key; for development only")
		sealer = s
	default:
		return errors.New("no sealer: set -kms-key, or -file-key in development")
	}

	srv, err := keys.NewServer(*state, sealer, log)
	if err != nil {
		return err
	}
	srv.PeerUID = *peerUID

	// A socket left by an earlier run is removed; nothing else may sit at
	// the path.
	if fi, err := os.Lstat(*socket); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("%s exists and is not a socket", *socket)
		}
		_ = os.Remove(*socket)
	}
	if err := os.MkdirAll(filepath.Dir(*socket), 0o750); err != nil {
		return err
	}
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(*socket, os.FileMode(*socketMode)); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				_ = ln.Close()
				return
			case <-t.C:
				srv.Sweep()
			}
		}
	}()
	log.Info("ftwkeysd listening", "socket", *socket)
	return srv.Serve(ln)
}

// kmsClient adapts the AWS SDK to keys.KMS.
type kmsClient struct{ c *kms.Client }

func (k kmsClient) GenerateDataKey(ctx context.Context, keyID string, ec map[string]string) ([]byte, []byte, error) {
	out, err := k.c.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId: aws.String(keyID), KeySpec: types.DataKeySpecAes256, EncryptionContext: ec,
	})
	if err != nil {
		return nil, nil, err
	}
	return out.Plaintext, out.CiphertextBlob, nil
}

func (k kmsClient) Decrypt(ctx context.Context, keyID string, blob []byte, ec map[string]string) ([]byte, error) {
	out, err := k.c.Decrypt(ctx, &kms.DecryptInput{
		KeyId: aws.String(keyID), CiphertextBlob: blob, EncryptionContext: ec,
	})
	if err != nil {
		return nil, err
	}
	return out.Plaintext, nil
}
