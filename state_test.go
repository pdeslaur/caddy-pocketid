package pocketid

import (
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
			state := encodeState(tc.url, tc.secret)
			got, err := verifyState(state, tc.secret)
			if err != nil {
				t.Fatalf("verifyState: %v", err)
			}
			if got != tc.url {
				t.Errorf("got %q, want %q", got, tc.url)
			}
		})
	}
}

func TestStateWrongSecret(t *testing.T) {
	state := encodeState("/foo", "secret")
	_, err := verifyState(state, "wrong")
	if err == nil {
		t.Error("expected error with wrong secret, got nil")
	}
}

func TestStateTamperedSignature(t *testing.T) {
	state := encodeState("/foo", "secret")
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
	_, err := verifyState("!!!.sig", "secret")
	if err == nil {
		t.Error("expected error for invalid base64 payload, got nil")
	}
}
