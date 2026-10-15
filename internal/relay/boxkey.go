package relay

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"net/http"
	"strconv"
)

// BoxKeys is the registry's answer to one question: does this P-256 key
// belong to a home that has turned FTW Cloud on? The command path never
// asks it for a reading, a roster or a home id.
type BoxKeys interface {
	RecognizesBoxKey(pk []byte) bool
}

// boxProofInput is what a box signs to prove its cloud key on a join.
//
// Existing clients send no proof. A join without one is admitted on the
// rendezvous handle, which is the capability those clients already present
// and what an endpoint-only switch requires. A join that does send one is
// admitted only when the signature verifies. The handle stays in the path
// either way: the proof does not name the room.
func boxProofInput(epoch int64, handle, role string) []byte {
	return []byte("ftw.cloud.relay.v1\n" + strconv.FormatInt(epoch, 10) + "\n" + handle + "\n" + role)
}

// proofResult is the outcome of looking at the two optional headers.
type proofResult int

const (
	proofAbsent proofResult = iota
	proofOK
	proofBad
)

// checkBoxProof verifies X-FTW-Box-Key and X-FTW-Box-Sig when the box sends
// them. App joins never carry a cloud key; the headers are ignored there.
func checkBoxProof(r *http.Request, keys BoxKeys, epoch int64, handle, role string) proofResult {
	if role == roleApp {
		return proofAbsent
	}
	keyHdr := r.Header.Get("X-FTW-Box-Key")
	sigHdr := r.Header.Get("X-FTW-Box-Sig")
	if keyHdr == "" && sigHdr == "" {
		return proofAbsent
	}
	if keyHdr == "" || sigHdr == "" {
		return proofBad
	}
	pk, err := base64.RawURLEncoding.DecodeString(keyHdr)
	if err != nil {
		return proofBad
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigHdr)
	if err != nil || len(sig) != 64 {
		return proofBad
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pk)
	if err != nil {
		return proofBad
	}
	sum := sha256.Sum256(boxProofInput(epoch, handle, role))
	if !ecdsa.Verify(pub, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return proofBad
	}
	if keys != nil && !keys.RecognizesBoxKey(pk) {
		return proofBad
	}
	return proofOK
}

// signBoxProof is the client half, used by tests and available to a later
// box build. It returns the two header values.
func signBoxProof(key *ecdsa.PrivateKey, epoch int64, handle, role string) (keyHdr, sigHdr string, err error) {
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(boxProofInput(epoch, handle, role))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		return "", "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return base64.RawURLEncoding.EncodeToString(pub), base64.RawURLEncoding.EncodeToString(sig), nil
}

// boxKeyReason is the close reason for a proof the service will not accept.
func boxKeyReason() string { return "box key" }
