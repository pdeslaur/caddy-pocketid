package pocketid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

type oidcProvider struct {
	issuer        string
	authEndpoint  string
	tokenEndpoint string
	jwksURI       string

	mu   sync.RWMutex
	keys jwk.Set
}

type discoveryDoc struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

func newOIDCProvider(issuer string) (*oidcProvider, error) {
	discoveryURL := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	resp, err := http.Get(discoveryURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("fetching discovery document: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery document returned status %d", resp.StatusCode)
	}

	var doc discoveryDoc
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decoding discovery document: %w", err)
	}

	p := &oidcProvider{
		issuer:        issuer,
		authEndpoint:  doc.AuthorizationEndpoint,
		tokenEndpoint: doc.TokenEndpoint,
		jwksURI:       doc.JWKSURI,
	}

	if err := p.fetchKeys(); err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}

	return p, nil
}

func (p *oidcProvider) fetchKeys() error {
	keys, err := jwk.Fetch(context.Background(), p.jwksURI)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.keys = keys
	p.mu.Unlock()
	return nil
}

func (p *oidcProvider) keyFunc(token *jwt.Token) (interface{}, error) {
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, fmt.Errorf("missing kid in token header")
	}

	key, found := p.lookupKey(kid)
	if !found {
		// Re-fetch once to handle key rotation.
		if err := p.fetchKeys(); err != nil {
			return nil, fmt.Errorf("re-fetching JWKS: %w", err)
		}
		key, found = p.lookupKey(kid)
		if !found {
			return nil, fmt.Errorf("unknown key id: %s", kid)
		}
	}

	var raw interface{}
	if err := key.Raw(&raw); err != nil {
		return nil, fmt.Errorf("extracting raw key: %w", err)
	}
	return raw, nil
}

func (p *oidcProvider) lookupKey(kid string) (jwk.Key, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.keys.LookupKeyID(kid)
}

func (p *oidcProvider) validateToken(tokenStr, clientID string) (jwt.MapClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, p.keyFunc,
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer(p.issuer),
		jwt.WithAudience(clientID),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}
	return claims, nil
}

type tokenResponse struct {
	IDToken string `json:"id_token"`
}

func (p *oidcProvider) exchangeCode(ctx context.Context, code, verifier, redirectURI, clientID, clientSecret string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code_verifier": {verifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token exchange request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token exchange returned status %d: %s", resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}
	if tr.IDToken == "" {
		return "", fmt.Errorf("no id_token in response")
	}
	return tr.IDToken, nil
}

func (p *oidcProvider) authURL(clientID, redirectURI, state, challenge string) string {
	v := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid"},
		"state":                 {state},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	return p.authEndpoint + "?" + v.Encode()
}
