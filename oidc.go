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
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var oidcHTTPClient = &http.Client{Timeout: 10 * time.Second}

// oidcProvider performs OIDC discovery lazily on first use, so Caddy can start
// even when the issuer is unreachable (e.g. PocketID is served by the same
// Caddy instance). Failed discovery is retried on the next call.
type oidcProvider struct {
	issuer string

	mu       sync.Mutex
	provider *oidc.Provider
}

func newOIDCProvider(issuer string) *oidcProvider {
	return &oidcProvider{issuer: issuer}
}

func (p *oidcProvider) get(ctx context.Context) (*oidc.Provider, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.provider != nil {
		return p.provider, nil
	}
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, oidcHTTPClient), p.issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	p.provider = provider
	return provider, nil
}

func (p *oidcProvider) validateToken(ctx context.Context, tokenStr, clientID string) (map[string]any, error) {
	provider, err := p.get(ctx)
	if err != nil {
		return nil, err
	}
	verifier := provider.Verifier(&oidc.Config{ClientID: clientID})
	idToken, err := verifier.Verify(oidc.ClientContext(ctx, oidcHTTPClient), tokenStr)
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("extracting claims: %w", err)
	}
	return claims, nil
}

// tokens is what the token endpoint returns. RefreshToken is empty when the
// issuer doesn't issue one.
type tokens struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
}

// clientAuth is how the client authenticates to the token endpoint: with its
// secret, or with assertion, a JWT, when it has no secret; with neither, it is
// a public client.
type clientAuth struct {
	clientID  string
	secret    string
	assertion string
}

// exchangeCode redeems an authorization code for tokens.
func (p *oidcProvider) exchangeCode(ctx context.Context, code, verifier, redirectURI string, auth clientAuth) (tokens, error) {
	return p.requestTokens(ctx, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	}, auth)
}

// refresh redeems a refresh token for tokens.
func (p *oidcProvider) refresh(ctx context.Context, refreshToken string, auth clientAuth) (tokens, error) {
	return p.requestTokens(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}, auth)
}

// requestTokens posts form to the token endpoint and returns the tokens,
// which always include an id_token.
func (p *oidcProvider) requestTokens(ctx context.Context, form url.Values, auth clientAuth) (tokens, error) {
	provider, err := p.get(ctx)
	if err != nil {
		return tokens{}, err
	}
	if auth.secret == "" {
		// Only client_id goes in the body, never an empty Basic password.
		form.Set("client_id", auth.clientID)
	}
	if auth.assertion != "" {
		form.Set("client_assertion_type", clientAssertionType)
		form.Set("client_assertion", auth.assertion)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, provider.Endpoint().TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return tokens{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if auth.secret != "" {
		// RFC 6749 section 2.3.1: both are form-encoded before Basic encoding.
		req.SetBasicAuth(url.QueryEscape(auth.clientID), url.QueryEscape(auth.secret))
	}

	resp, err := oidcHTTPClient.Do(req)
	if err != nil {
		return tokens{}, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tokens{}, fmt.Errorf("reading token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var oauthErr struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &oauthErr)
		return tokens{}, fmt.Errorf("token request: %s: %s %s", resp.Status, oauthErr.Error, oauthErr.Description)
	}

	var t tokens
	if err := json.Unmarshal(body, &t); err != nil {
		return tokens{}, fmt.Errorf("parsing token response: %w", err)
	}
	if t.IDToken == "" {
		return tokens{}, fmt.Errorf("no id_token in token response")
	}
	return t, nil
}

func (p *oidcProvider) authURL(ctx context.Context, clientID, redirectURI, state, challenge, prompt string) (string, error) {
	provider, err := p.get(ctx)
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
