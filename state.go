package pocketid

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// encodeState produces a tamper-evident state token for the OAuth2 redirect.
// Format: base64url(returnURL) + "." + base64url(HMAC-SHA256(returnURL, secret))
func encodeState(returnURL, secret string) string {
	encoded := base64.RawURLEncoding.EncodeToString([]byte(returnURL))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(returnURL))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + sig
}

func verifyState(state, secret string) (string, error) {
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid state format")
	}

	urlBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", fmt.Errorf("decoding state payload: %w", err)
	}
	returnURL := string(urlBytes)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(returnURL))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[1]), []byte(expected)) {
		return "", fmt.Errorf("state signature mismatch")
	}
	return returnURL, nil
}
