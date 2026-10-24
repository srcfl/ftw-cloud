package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/srcfl/ftw/go/protocol/ohttp"
)

// The Oblivious HTTP gateway's keys (deploy/ohttp.md). Core pins the public
// half of each as a key configuration, so a key here that no release pins
// opens nothing.

// ohttpKeyID is the first byte of SHA-256 of the public key, so a key's id
// needs no second file.
func ohttpKeyID(pub []byte) uint8 {
	sum := sha256.Sum256(pub)
	return sum[0]
}

// loadOHTTPKeys reads the gateway's X25519 keys: PKCS #8 PEM, one block per
// key. A second block lets a key rotate across a Core release.
func loadOHTTPKeys(path string) (*ohttp.Gateway, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ohttp key: %w", err)
	}
	var keys []ohttp.Key
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			break
		}
		if block.Type != "PRIVATE KEY" {
			return nil, fmt.Errorf("ohttp key: %s holds a %s, not a PKCS #8 private key", path, block.Type)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("ohttp key: %w", err)
		}
		x, ok := parsed.(*ecdh.PrivateKey)
		if !ok || x.Curve() != ecdh.X25519() {
			return nil, fmt.Errorf("ohttp key: %s holds a key that is not X25519", path)
		}
		keys = append(keys, ohttp.Key{ID: ohttpKeyID(x.PublicKey().Bytes()), Private: x})
	}
	// A block cut short, as a rotation pasted in part would leave it, must
	// not leave the new key quietly unloaded.
	if len(bytes.TrimSpace(raw)) > 0 {
		return nil, fmt.Errorf("ohttp key: %s has data after its last whole key", path)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("ohttp key: %s holds no key", path)
	}
	gw, err := ohttp.NewGateway(keys...)
	if err != nil {
		return nil, fmt.Errorf("ohttp key: %s holds two keys under one id; make a new one", path)
	}
	return gw, nil
}

// ohttpPins is each key configuration as Core pins it, comma separated, for
// the start line. Empty when the gateway is off.
func ohttpPins(gw *ohttp.Gateway) string {
	if gw == nil {
		return ""
	}
	var pins []string
	for _, c := range gw.Configs() {
		pins = append(pins, base64.RawURLEncoding.EncodeToString(c.Marshal()))
	}
	return strings.Join(pins, ",")
}

// keygenOHTTP writes a new gateway key, never over an existing file, and
// prints its configuration: the string statsrelay.GatewayKey in srcfl/ftw
// pins. For a rotation, put the new block after the old one in the same
// parameter; ftwcloudd refuses two keys under one id, and then a new key is
// needed.
func keygenOHTTP(path string) error {
	x, err := ecdh.X25519().GenerateKey(nil)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(x)
	if err != nil {
		return err
	}
	if err := writePEM(path, "PRIVATE KEY", der); err != nil {
		return err
	}
	gw, err := ohttp.NewGateway(ohttp.Key{ID: ohttpKeyID(x.PublicKey().Bytes()), Private: x})
	if err != nil {
		return err
	}
	fmt.Println(ohttpPins(gw))
	return nil
}
