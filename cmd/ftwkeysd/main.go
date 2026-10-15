// Command ftwkeysd is FTW Cloud's keys part: the one process that can open an
// agent's Noise session to a box. It runs beside ftwcloudd on the same host,
// as another user, and answers only on a local unix socket. See
// internal/keys and deploy/keys.md.
//
//	ftwkeysd offerkey [flags]           print the offer key's kid and public half
//	ftwkeysd [flags]                    serve
//
// A development build (-tags ftwclouddev) also takes -file-key and has
// "ftwkeysd filekey -out dev.key"; a production build has neither.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	if len(os.Args) > 1 && devCommand(os.Args[1], os.Args[2:]) {
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "offerkey" {
		if err := offerKey(os.Args[2:]); err != nil {
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

// keyFlags are the flags that choose where keys are sealed and what signs
// offers.
type keyFlags struct {
	state, kmsKey, offerKMSKey, region, awsCreds, fileKey *string
}

func addKeyFlags(fs *flag.FlagSet) keyFlags {
	return keyFlags{
		state:       fs.String("state", "/state/keys", "directory for the sealed keys"),
		kmsKey:      fs.String("kms-key", "", "AWS KMS key id, ARN or alias that wraps the data keys"),
		offerKMSKey: fs.String("offer-kms-key", "", "AWS KMS key id, ARN or alias of the offer key (ECC_NIST_P256, SIGN_VERIFY)"),
		region:      fs.String("region", "eu-north-1", "AWS region of the KMS keys"),
		awsCreds: fs.String("aws-credentials", "",
			"a JSON file of the keys role's short-lived credentials, as aws sts assume-role answers them; the host refreshes it"),
		fileKey: addFileKeyFlag(fs),
	}
}

// aws is the SDK's configuration, made once.
func (f keyFlags) aws(ctx context.Context) (aws.Config, error) {
	opts := []func(*config.LoadOptions) error{config.WithRegion(*f.region)}
	if *f.awsCreds != "" {
		opts = append(opts, config.WithCredentialsProvider(aws.NewCredentialsCache(fileCredentials(*f.awsCreds),
			func(o *aws.CredentialsCacheOptions) { o.ExpiryWindow = 5 * time.Minute })))
	}
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("aws config: %w", err)
	}
	return cfg, nil
}

// options builds the sealer and the offer key. A production build needs both
// in KMS.
func (f keyFlags) options(ctx context.Context, log *slog.Logger) (keys.Sealer, []keys.Option, error) {
	var cfg *aws.Config
	awsCfg := func() (aws.Config, error) {
		if cfg == nil {
			c, err := f.aws(ctx)
			if err != nil {
				return aws.Config{}, err
			}
			cfg = &c
		}
		return *cfg, nil
	}

	var sealer keys.Sealer
	switch {
	case *f.kmsKey != "" && *f.fileKey != "":
		return nil, nil, errors.New("choose -kms-key or -file-key, not both")
	case *f.kmsKey != "":
		c, err := awsCfg()
		if err != nil {
			return nil, nil, err
		}
		sealer = keys.KMSSealer{KMS: kmsClient{kms.NewFromConfig(c)}, KeyID: *f.kmsKey}
	case *f.fileKey != "":
		s, err := keys.NewFileSealer(*f.fileKey)
		if err != nil {
			return nil, nil, err
		}
		log.Warn("agent keys sealed with a local file key; for development only")
		sealer = s
	default:
		return nil, nil, errors.New("no sealer: set -kms-key")
	}

	var opts []keys.Option
	switch {
	case *f.offerKMSKey != "":
		c, err := awsCfg()
		if err != nil {
			return nil, nil, err
		}
		tctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		k, err := keys.NewKMSOfferKey(tctx, kmsClient{kms.NewFromConfig(c)}, *f.offerKMSKey)
		if err != nil {
			return nil, nil, err
		}
		opts = append(opts, keys.WithOfferKey(k))
	case devBuild:
		log.Warn("offers signed by a local key; for development only")
	default:
		return nil, nil, errors.New("no offer key: set -offer-kms-key")
	}
	return sealer, opts, nil
}

// offerKey prints the offer key's kid and SEC1 public half, base64url, for
// Core and the apps to pin. Run it on the host (deploy/keys.md), so that what
// is pinned comes from KMS and not from a public endpoint. A development
// build prints its local key instead.
func offerKey(args []string) error {
	fs := flag.NewFlagSet("offerkey", flag.ExitOnError)
	kf := addKeyFlags(fs)
	_ = fs.Parse(args)
	ctx := context.Background()
	var pub []byte
	if *kf.offerKMSKey != "" {
		cfg, err := kf.aws(ctx)
		if err != nil {
			return err
		}
		k, err := keys.NewKMSOfferKey(ctx, kmsClient{kms.NewFromConfig(cfg)}, *kf.offerKMSKey)
		if err != nil {
			return err
		}
		pub = k.Public()
	} else {
		log := slog.New(slog.NewTextHandler(os.Stderr, nil))
		sealer, opts, err := kf.options(ctx, log)
		if err != nil {
			return err
		}
		srv, err := keys.NewServer(*kf.state, sealer, log, opts...)
		if err != nil {
			return err
		}
		if pub, err = srv.Local().OfferKey(ctx); err != nil {
			return err
		}
	}
	fmt.Printf("kid %s\npub %s\n", keys.OfferKid(pub), base64.RawURLEncoding.EncodeToString(pub))
	return nil
}

func serve(args []string) error {
	fs := flag.NewFlagSet("ftwkeysd", flag.ExitOnError)
	socket := fs.String("socket", "/run/ftw-cloud-keys/keys.sock", "unix socket to answer on")
	kf := addKeyFlags(fs)
	peerUID := fs.Int("peer-uid", -1, "the one user allowed to connect; -1 is this process's own")
	socketMode := fs.Uint("socket-mode", 0o660, "permissions of the socket file")
	_ = fs.Parse(args)

	harden()
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	sealer, opts, err := kf.options(context.Background(), log)
	if err != nil {
		return err
	}

	srv, err := keys.NewServer(*kf.state, sealer, log, opts...)
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
	pub, _ := srv.Local().OfferKey(ctx)
	log.Info("ftwkeysd listening", "socket", *socket, "offer_kid", keys.OfferKid(pub))
	return srv.Serve(ln)
}

// fileCredentials reads the keys role's credentials from the file the host
// refreshes, each time the SDK's cache runs out.
type fileCredentials string

func (p fileCredentials) Retrieve(context.Context) (aws.Credentials, error) {
	raw, err := os.ReadFile(string(p))
	if err != nil {
		return aws.Credentials{}, fmt.Errorf("aws credentials: %w", err)
	}
	var c struct {
		AccessKeyID     string    `json:"AccessKeyId"`
		SecretAccessKey string    `json:"SecretAccessKey"`
		SessionToken    string    `json:"SessionToken"`
		Expiration      time.Time `json:"Expiration"`
	}
	if err := json.Unmarshal(raw, &c); err != nil || c.AccessKeyID == "" || c.SecretAccessKey == "" || c.Expiration.IsZero() {
		return aws.Credentials{}, errors.New("aws credentials: the file is not an assume-role answer")
	}
	return aws.Credentials{
		AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken,
		Source: "ftwkeysd-file", CanExpire: true, Expires: c.Expiration,
	}, nil
}

// kmsClient adapts the AWS SDK to keys.KMS and keys.KMSSigner.
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

func (k kmsClient) PublicKey(ctx context.Context, keyID string) ([]byte, error) {
	out, err := k.c.GetPublicKey(ctx, &kms.GetPublicKeyInput{KeyId: aws.String(keyID)})
	if err != nil {
		return nil, err
	}
	if out.KeySpec != types.KeySpecEccNistP256 || out.KeyUsage != types.KeyUsageTypeSignVerify {
		return nil, fmt.Errorf("the offer key is %s for %s, want ECC_NIST_P256 for SIGN_VERIFY", out.KeySpec, out.KeyUsage)
	}
	return out.PublicKey, nil
}

func (k kmsClient) Sign(ctx context.Context, keyID string, digest []byte) ([]byte, error) {
	out, err := k.c.Sign(ctx, &kms.SignInput{
		KeyId: aws.String(keyID), Message: digest,
		MessageType: types.MessageTypeDigest, SigningAlgorithm: types.SigningAlgorithmSpecEcdsaSha256,
	})
	if err != nil {
		return nil, err
	}
	return out.Signature, nil
}
