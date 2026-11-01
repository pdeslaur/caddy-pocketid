package pocketid

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// statePayload is the signed content of the OAuth2 state parameter.
// Nonce identifies the login flow and names its PKCE verifier cookie, so
// concurrent flows in the same browser don't overwrite each other's verifier.
type statePayload struct {
	Nonce     string `json:"n"`
	ReturnURL string `json:"r"`
}

func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// encodeState produces a tamper-evident state token for the OAuth2 redirect.
// Format: base64url(json(payload)) + "." + base64url(HMAC-SHA256(base64url(json(payload)), secret))
func encodeState(nonce, returnURL, secret string) string {
	data, _ := json.Marshal(statePayload{Nonce: nonce, ReturnURL: returnURL})
	encoded := base64.RawURLEncoding.EncodeToString(data)
	return encoded + "." + signState(encoded, secret)
}

func verifyState(state, secret string) (statePayload, error) {
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return statePayload{}, fmt.Errorf("invalid state format")
	}

	if !hmac.Equal([]byte(parts[1]), []byte(signState(parts[0], secret))) {
		return statePayload{}, fmt.Errorf("state signature mismatch")
	}

	data, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return statePayload{}, fmt.Errorf("decoding state payload: %w", err)
	}
	var payload statePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return statePayload{}, fmt.Errorf("parsing state payload: %w", err)
	}
	if payload.Nonce == "" {
		return statePayload{}, fmt.Errorf("state missing nonce")
	}
	return payload, nil
}

func signState(encoded, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(encoded))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
