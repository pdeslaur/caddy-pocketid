package pocketid

import (
	"context"
	"fmt"
	"net/http"
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

func (p *oidcProvider) exchangeCode(ctx context.Context, code, verifier, redirectURI, clientID, clientSecret string) (string, error) {
	provider, err := p.get(ctx)
	if err != nil {
		return "", err
	}
	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     provider.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	token, err := cfg.Exchange(
		oidc.ClientContext(ctx, oidcHTTPClient),
		code,
		oauth2.SetAuthURLParam("code_verifier", verifier),
	)
	if err != nil {
		return "", fmt.Errorf("token exchange: %w", err)
	}
	raw, ok := token.Extra("id_token").(string)
	if !ok || raw == "" {
		return "", fmt.Errorf("no id_token in token response")
	}
	return raw, nil
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
