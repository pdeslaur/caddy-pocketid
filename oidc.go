package pocketid

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var oidcHTTPClient = &http.Client{Timeout: 10 * time.Second}

type oidcProvider struct {
	provider *oidc.Provider
}

func newOIDCProvider(ctx context.Context, issuer string) (*oidcProvider, error) {
	provider, err := oidc.NewProvider(oidc.ClientContext(ctx, oidcHTTPClient), issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery: %w", err)
	}
	return &oidcProvider{provider: provider}, nil
}

func (p *oidcProvider) validateToken(ctx context.Context, tokenStr, clientID string) error {
	verifier := p.provider.Verifier(&oidc.Config{ClientID: clientID})
	_, err := verifier.Verify(oidc.ClientContext(ctx, oidcHTTPClient), tokenStr)
	return err
}

func (p *oidcProvider) exchangeCode(ctx context.Context, code, verifier, redirectURI, clientID, clientSecret string) (string, error) {
	cfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     p.provider.Endpoint(),
		RedirectURL:  redirectURI,
		Scopes:       []string{oidc.ScopeOpenID},
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

func (p *oidcProvider) authURL(clientID, redirectURI, state, challenge string) string {
	cfg := &oauth2.Config{
		ClientID:    clientID,
		Endpoint:    p.provider.Endpoint(),
		RedirectURL: redirectURI,
		Scopes:      []string{oidc.ScopeOpenID},
	}
	return cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}
