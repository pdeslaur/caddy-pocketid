package pocketid

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestGeneratePKCE(t *testing.T) {
	verifier, challenge, err := generatePKCE()
	if err != nil {
		t.Fatalf("generatePKCE: %v", err)
	}

	vBytes, err := base64.RawURLEncoding.DecodeString(verifier)
	if err != nil {
		t.Fatalf("verifier not valid base64url: %v", err)
	}
	if len(vBytes) != 32 {
		t.Fatalf("verifier decoded length = %d, want 32", len(vBytes))
	}

	sum := sha256.Sum256([]byte(verifier))
	wantChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if challenge != wantChallenge {
		t.Errorf("challenge = %q, want %q", challenge, wantChallenge)
	}
}

func TestGeneratePKCEUnique(t *testing.T) {
	v1, _, err := generatePKCE()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	v2, _, err := generatePKCE()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if v1 == v2 {
		t.Error("two generatePKCE calls returned identical verifiers")
	}
}
