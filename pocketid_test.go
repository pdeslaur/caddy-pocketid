package pocketid

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"chainguard.dev/go-oidctest/pkg/oidctest"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-jose/go-jose/v4/jwt"
)

// newTestMiddleware provisions a Middleware against a fake OIDC issuer
// using the same Provision path as production.
func newTestMiddleware(t *testing.T, issuerURL string) *Middleware {
	t.Helper()
	m := &Middleware{
		Issuer:       issuerURL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	if err := m.Provision(ctx); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return m
}

// serveMiddleware wraps Middleware as a plain http.Handler for use with httptest.
func serveMiddleware(m *Middleware, backend func(http.ResponseWriter, *http.Request)) http.Handler {
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		backend(w, r)
		return nil
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := m.ServeHTTP(w, r, next); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

var nopNext = caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error { return nil })

// TestOIDCFullFlow exercises the complete authorization code + PKCE flow end-to-end:
// unauthenticated request → verify redirect to OIDC issuer → complete flow → session cookie set → backend reached.
func TestOIDCFullFlow(t *testing.T) {
	_, issuerURL := oidctest.NewIssuer(t)
	m := newTestMiddleware(t, issuerURL)

	var backendHit bool
	srv := httptest.NewTLSServer(serveMiddleware(m, func(w http.ResponseWriter, r *http.Request) {
		backendHit = true
		_, _ = fmt.Fprintln(w, "ok")
	}))
	t.Cleanup(srv.Close)

	// Phase 1: unauthenticated request must redirect to the OIDC issuer, not serve the backend.
	noFollowClient := srv.Client()
	noFollowClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := noFollowClient.Get(srv.URL + "/dashboard")
	if err != nil {
		t.Fatalf("initial request: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("unauthenticated request: got status %d, want 302", resp.StatusCode)
	}
	location := resp.Header.Get("Location")
	if !strings.Contains(location, issuerURL) {
		t.Errorf("redirect location %q does not point to OIDC issuer %q", location, issuerURL)
	}

	// Phase 2: complete the OIDC flow and verify the backend is reached with a session cookie.
	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar
	client.CheckRedirect = nil

	resp, err = client.Get(srv.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("after OIDC flow: got status %d, want 200", resp.StatusCode)
	}
	if !backendHit {
		t.Error("backend handler not reached after OIDC flow")
	}

	srvURL, _ := url.Parse(srv.URL)
	var hasSessionCookie bool
	for _, c := range jar.Cookies(srvURL) {
		if c.Name == cookieName {
			hasSessionCookie = true
			break
		}
	}
	if !hasSessionCookie {
		t.Error("session cookie not set: OIDC flow did not complete")
	}
}

// TestOIDCFullFlowPreservesReturnURL checks that after the OIDC dance the user
// lands on the original URL (including query string), not just /.
func TestOIDCFullFlowPreservesReturnURL(t *testing.T) {
	_, issuerURL := oidctest.NewIssuer(t)
	m := newTestMiddleware(t, issuerURL)

	var gotPath string
	srv := httptest.NewTLSServer(serveMiddleware(m, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.RequestURI()
		_, _ = fmt.Fprintln(w, "ok")
	}))
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar

	resp, err := client.Get(srv.URL + "/app/page?ref=123")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if gotPath != "/app/page?ref=123" {
		t.Errorf("landed on %q, want /app/page?ref=123", gotPath)
	}
}

// TestOIDCAlreadyAuthenticated checks that a request carrying a valid session
// cookie reaches the backend without triggering a redirect.
func TestOIDCAlreadyAuthenticated(t *testing.T) {
	signer, issuerURL := oidctest.NewIssuer(t)
	m := newTestMiddleware(t, issuerURL)

	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   issuerURL,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  "test-subject",
		Audience: jwt.Audience{"test-client"},
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	var backendHit bool
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		backendHit = true
		w.WriteHeader(http.StatusOK)
		return nil
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: token})

	if err := m.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if !backendHit {
		t.Error("backend not reached with valid session cookie")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// TestOIDCExpiredToken checks that an expired session cookie triggers a redirect
// to re-authenticate rather than passing through.
func TestOIDCExpiredToken(t *testing.T) {
	signer, issuerURL := oidctest.NewIssuer(t)
	m := newTestMiddleware(t, issuerURL)

	expired, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   issuerURL,
		IssuedAt: jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		Expiry:   jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
		Subject:  "test-subject",
		Audience: jwt.Audience{"test-client"},
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Error("backend should not be reached with expired token")
		return nil
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: cookieName, Value: expired})

	if err := m.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
}

// TestOIDCCallbackAuthError checks that a provider error in the callback
// (e.g. user denied consent) returns 401.
func TestOIDCCallbackAuthError(t *testing.T) {
	_, issuerURL := oidctest.NewIssuer(t)
	m := newTestMiddleware(t, issuerURL)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?error=access_denied&error_description=user+denied", nil)

	if err := m.ServeHTTP(w, r, nopNext); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", w.Code)
	}
}

// TestOIDCCallbackInvalidState checks that a tampered or missing state returns 400.
func TestOIDCCallbackInvalidState(t *testing.T) {
	_, issuerURL := oidctest.NewIssuer(t)
	m := newTestMiddleware(t, issuerURL)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state=tampered.invalidsig", nil)

	if err := m.ServeHTTP(w, r, nopNext); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

// TestOIDCCallbackMissingPKCECookie checks that a callback with a valid state
// but no PKCE verifier cookie returns 400.
func TestOIDCCallbackMissingPKCECookie(t *testing.T) {
	_, issuerURL := oidctest.NewIssuer(t)
	m := newTestMiddleware(t, issuerURL)

	state := encodeState("/dashboard", m.ClientSecret)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+state, nil)

	if err := m.ServeHTTP(w, r, nopNext); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestCallbackURIScheme(t *testing.T) {
	m := &Middleware{CallbackPath: "/auth/callback"}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "example.com"
	if got := m.callbackURI(r); got != "http://example.com/auth/callback" {
		t.Errorf("plain request: got %q", got)
	}

	r.TLS = &tls.ConnectionState{}
	if got := m.callbackURI(r); got != "https://example.com/auth/callback" {
		t.Errorf("TLS request: got %q", got)
	}
}
