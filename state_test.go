package pocketid

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestStateRoundTrip(t *testing.T) {
	cases := []struct {
		name   string
		url    string
		secret string
	}{
		{"simple", "/dashboard", "secret"},
		{"with query", "/page?foo=bar&baz=1", "s3cr3t"},
		{"unicode path", "/path/with/unicöde", "key"},
		{"root", "/", "k"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := encodeState("nonce", tc.url, tc.secret)
			got, err := verifyState(state, tc.secret)
			if err != nil {
				t.Fatalf("verifyState: %v", err)
			}
			if got.ReturnURL != tc.url {
				t.Errorf("ReturnURL = %q, want %q", got.ReturnURL, tc.url)
			}
			if got.Nonce != "nonce" {
				t.Errorf("Nonce = %q, want nonce", got.Nonce)
			}
		})
	}
}

func TestGenerateNonceUnique(t *testing.T) {
	a, err := generateNonce()
	if err != nil {
		t.Fatalf("generateNonce: %v", err)
	}
	b, err := generateNonce()
	if err != nil {
		t.Fatalf("generateNonce: %v", err)
	}
	if a == b {
		t.Error("two calls returned the same nonce")
	}
}

func TestStateWrongSecret(t *testing.T) {
	state := encodeState("nonce", "/foo", "secret")
	_, err := verifyState(state, "wrong")
	if err == nil {
		t.Error("expected error with wrong secret, got nil")
	}
}

func TestStateTamperedSignature(t *testing.T) {
	state := encodeState("nonce", "/foo", "secret")
	dot := strings.Index(state, ".")
	tampered := state[:dot+1] + "invalidsig"
	_, err := verifyState(tampered, "secret")
	if err == nil {
		t.Error("expected error with tampered signature, got nil")
	}
}

func TestStateInvalidFormat(t *testing.T) {
	_, err := verifyState("nodothere", "secret")
	if err == nil {
		t.Error("expected error for missing dot separator, got nil")
	}
}

func TestStateInvalidBase64Payload(t *testing.T) {
	_, err := verifyState("!!!."+signState("!!!", "secret"), "secret")
	if err == nil {
		t.Error("expected error for invalid base64 payload, got nil")
	}
}

func TestStateMissingNonce(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(`{"r":"/foo"}`))
	_, err := verifyState(encoded+"."+signState(encoded, "secret"), "secret")
	if err == nil {
		t.Error("expected error for state without nonce, got nil")
	}
}
