// Package issuer talks to the OIDC issuer: discovery, id_token validation,
// authorization URLs and token requests.
package issuer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// httpClient sends every request to the issuer.
var httpClient = &http.Client{Timeout: 10 * time.Second}

// Provider performs OIDC discovery lazily on first use, so Caddy can start
// even when the issuer is unreachable (e.g. PocketID is served by the same
// Caddy instance). Failed discovery is retried on the next call.
type Provider struct {
	issuer string

	mu       sync.Mutex
	provider *oidc.Provider
}

// New returns a Provider for issuer, which discovers it on first use.
func New(issuer string) *Provider {
	return &Provider{issuer: issuer}
}

// Discover returns the discovered issuer, discovering it if it hasn't been yet.
func (p *Provider) Discover(ctx context.Context) (*oidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.provider != nil {
		return p.provider, nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, httpClient), p.issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	p.provider = provider
	return provider, nil
}

// ValidateToken verifies an id_token for clientID and returns its claims.
func (p *Provider) ValidateToken(ctx context.Context, tokenStr, clientID string) (map[string]any, error) {
	provider, err := p.Discover(ctx)
	if err != nil {
		return nil, err
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(oidc.ClientContext(ctx, httpClient), tokenStr)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extracting claims: %w", err)
	}
	return claims, nil
}

// Tokens is what the token endpoint returns. RefreshToken is empty when the
// issuer doesn't issue one.
type Tokens struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

// Credentials are how the client authenticates to the token endpoint: with
// Secret, or with SPIFFE, a JWT-SVID for the issuer as its audience, when it
// has no secret; with neither, it is a public client.
type Credentials struct {
	ClientID string
	Secret   string
	SPIFFE   bool
}

// ErrClientAssertion is returned, wrapped, when the client assertion can't be
// fetched; no token request is sent then.
var ErrClientAssertion = errors.New("client assertion unavailable")

// ExchangeCode redeems an authorization code for tokens.
func (p *Provider) ExchangeCode(ctx context.Context, code, verifier, redirectURI string, creds Credentials) (Tokens, error) {
	return p.requestTokens(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	}, creds)
}

// Refresh redeems a refresh token for tokens.
func (p *Provider) Refresh(ctx context.Context, refreshToken string, creds Credentials) (Tokens, error) {
	return p.requestTokens(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}, creds)
}

// requestTokens posts form to the token endpoint and returns the tokens,
// which always include an id_token.
func (p *Provider) requestTokens(ctx context.Context, form url.Values, creds Credentials) (Tokens, error) {
	provider, err := p.Discover(ctx)
	if err != nil {
		return Tokens{}, err
	}
	if creds.Secret == "" {
		// Only client_id goes in the body, never an empty Basic password.
		form.Set("client_id", creds.ClientID)
	}
	if creds.SPIFFE {
		svid, err := fetchSVID(ctx, p.issuer)
		if err != nil {
			return Tokens{}, fmt.Errorf("%w: %w", ErrClientAssertion, err)
		}
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", svid)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.Endpoint().TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return Tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if creds.Secret != "" {
		// RFC 6749 section 2.3.1: both are form-encoded before Basic encoding.
		req.SetBasicAuth(url.QueryEscape(creds.ClientID), url.QueryEscape(creds.Secret))
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return Tokens{}, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Tokens{}, fmt.Errorf("reading token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var oauthErr struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &oauthErr)
		return Tokens{}, fmt.Errorf("token request: %s: %s %s", resp.Status, oauthErr.Error, oauthErr.Description)
	}

	var t Tokens
	if err := json.Unmarshal(body, &t); err != nil {
		return Tokens{}, fmt.Errorf("parsing token response: %w", err)
	}
	if t.IDToken == "" {
		return Tokens{}, fmt.Errorf("no id_token in token response")
	}
	return t, nil
}

// AuthURL returns the authorization URL starting a login with PKCE.
func (p *Provider) AuthURL(ctx context.Context, clientID, redirectURI, state, challenge, prompt string) (string, error) {
	provider, err := p.Discover(ctx)
	if err != nil {
		return "", err
	}
	cfg := &oauth2.Config{
		ClientID:    clientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: redirectURI,
		Scopes:      []string{oidc.ScopeOpenID, "email", "profile"},
	}
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if prompt != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", prompt))
	}
	return cfg.AuthCodeURL(state, opts...), nil
}
