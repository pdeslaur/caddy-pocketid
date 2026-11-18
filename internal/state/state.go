// Package state signs and verifies the OAuth2 state parameter.
package state

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Payload is the signed content of the OAuth2 state parameter.
// Nonce identifies the login flow and names its PKCE verifier cookie, so
// concurrent flows in the same browser don't overwrite each other's verifier.
type Payload struct {
	Nonce     string `json:"n"`
	ReturnURL string `json:"r"`
}

// NewNonce returns a random URL-safe nonce.
func NewNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Encode produces a tamper-evident state token for the OAuth2 redirect.
// Format: base64url(json(payload)) + "." + base64url(HMAC-SHA256(base64url(json(payload)), secret))
func Encode(nonce, returnURL, secret string) string {
	data, _ := json.Marshal(Payload{Nonce: nonce, ReturnURL: returnURL})
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return encoded + "." + sign(encoded, secret)
}

// Verify checks the signature of a state token and returns its payload.
func Verify(state, secret string) (Payload, error) {
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return Payload{}, fmt.Errorf("invalid state format")
	}

	if !hmac.Equal([]byte(parts[1]), []byte(sign(parts[0], secret))) {
		return Payload{}, fmt.Errorf("state signature mismatch")
	}

	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Payload{}, fmt.Errorf("decoding state payload: %w", err)
	}
	var payload Payload
	if err := json.Unmarshal(data, &payload); err != nil {
		return Payload{}, fmt.Errorf("parsing state payload: %w", err)
	}
	if payload.Nonce == "" {
		return Payload{}, fmt.Errorf("state missing nonce")
	}
	return payload, nil
}

func sign(encoded, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
