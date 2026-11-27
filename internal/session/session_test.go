package session

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"chainguard.dev/go-oidctest/pkg/oidctest"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/pdeslaur/caddy-pocketid/internal/issuer"
	"github.com/pdeslaur/caddy-pocketid/internal/state"
)

const testCallbackPath = "/auth/callback"

// newTestManager returns a Manager for a client with a secret against
// issuerURL, after applying opts to its Config.
func newTestManager(t *testing.T, issuerURL string, opts ...func(*Config)) *Manager {
	t.Helper()
	cfg := Config{
		Issuer:       issuerURL,
		Credentials:  issuer.Credentials{ClientID: "test-client", Secret: "test-secret"},
		CallbackPath: testCallbackPath,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	m, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// serve wraps Manager.Handle as an http.Handler for use with httptest.
func serve(m *Manager, backend func(w http.ResponseWriter, r *http.Request, claims map[string]any)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := m.Handle(w, r, func(w http.ResponseWriter, r *http.Request, claims map[string]any) error {
			backend(w, r, claims)
			return nil
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})
}

func okBackend(w http.ResponseWriter, r *http.Request, claims map[string]any) {
	_, _ = fmt.Fprintln(w, "ok")
}

func failNext(t *testing.T) Next {
	return func(w http.ResponseWriter, r *http.Request, claims map[string]any) error {
		t.Error("backend reached")
		return nil
	}
}

// signedToken returns an id_token for test-client from issuerURL expiring at
// expiry.
func signedToken(t *testing.T, signer jose.Signer, issuerURL string, expiry time.Time) string {
	t.Helper()
	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   issuerURL,
		IssuedAt: jwt.NewNumericDate(expiry.Add(-time.Hour)),
		Expiry:   jwt.NewNumericDate(expiry),
		Subject:  "test-subject",
		Audience: jwt.Audience{"test-client"},
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	return token
}

func responseCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestFullFlow exercises the complete authorization code + PKCE flow end-to-end:
// unauthenticated request → verify redirect to OIDC issuer → complete flow → session cookie set → backend reached.
func TestFullFlow(t *testing.T) {
	_, issuerURL := oidctest.NewIssuer(t)
	m := newTestManager(t, issuerURL)

	var gotSub any
	srv := httptest.NewTLSServer(serve(m, func(w http.ResponseWriter, r *http.Request, claims map[string]any) {
		gotSub = claims["sub"]
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
	if gotSub != "test-subject" {
		t.Errorf("backend got sub %v, want test-subject", gotSub)
	}

	srvURL, _ := url.Parse(srv.URL)
	var hasSessionCookie bool
	for _, c := range jar.Cookies(srvURL) {
		if c.Name == TokenCookie {
			hasSessionCookie = true
			break
		}
	}
	if !hasSessionCookie {
		t.Error("session cookie not set: OIDC flow did not complete")
	}
}

// TestFullFlowPreservesReturnURL checks that after the OIDC dance the user
// lands on the original URL (including query string), not just /.
func TestFullFlowPreservesReturnURL(t *testing.T) {
	_, issuerURL := oidctest.NewIssuer(t)
	m := newTestManager(t, issuerURL)

	var gotPath string
	srv := httptest.NewTLSServer(serve(m, func(w http.ResponseWriter, r *http.Request, claims map[string]any) {
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

// TestFullFlowClearsPKCECookie checks that the PKCE verifier cookie is
// removed once the callback completes.
func TestFullFlowClearsPKCECookie(t *testing.T) {
	_, issuerURL := oidctest.NewIssuer(t)
	m := newTestManager(t, issuerURL)

	srv := httptest.NewTLSServer(serve(m, okBackend))
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar

	resp, err := client.Get(srv.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	callbackURL, _ := url.Parse(srv.URL + testCallbackPath)
	for _, c := range jar.Cookies(callbackURL) {
		if strings.HasPrefix(c.Name, pkceCookiePrefix) {
			t.Errorf("PKCE cookie %q still present after callback", c.Name)
		}
	}
}

// TestConcurrentFlows checks that starting a second login flow in the same
// browser does not break one already in progress.
func TestConcurrentFlows(t *testing.T) {
	_, issuerURL := oidctest.NewIssuer(t)
	m := newTestManager(t, issuerURL)

	var gotPath string
	srv := httptest.NewTLSServer(serve(m, func(w http.ResponseWriter, r *http.Request, claims map[string]any) {
		gotPath = r.URL.RequestURI()
		_, _ = fmt.Fprintln(w, "ok")
	}))
	t.Cleanup(srv.Close)

	jar, _ := cookiejar.New(nil)
	noFollowClient := srv.Client()
	noFollowClient.Jar = jar
	noFollowClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	startFlow := func(path string) string {
		t.Helper()
		resp, err := noFollowClient.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("GET %s: status = %d, want 302", path, resp.StatusCode)
		}
		return resp.Header.Get("Location")
	}
	first := startFlow("/first")
	second := startFlow("/second")

	client := srv.Client()
	client.Jar = jar
	client.CheckRedirect = nil
	for _, tc := range []struct{ authURL, wantPath string }{
		{first, "/first"},
		{second, "/second"},
	} {
		resp, err := client.Get(tc.authURL)
		if err != nil {
			t.Fatalf("completing flow for %s: %v", tc.wantPath, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("flow for %s: status = %d, want 200", tc.wantPath, resp.StatusCode)
		}
		if gotPath != tc.wantPath {
			t.Errorf("flow for %s: landed on %q", tc.wantPath, gotPath)
		}
	}
}

// TestAlreadyAuthenticated checks that a request carrying a valid session
// cookie reaches the backend without triggering a redirect.
func TestAlreadyAuthenticated(t *testing.T) {
	signer, issuerURL := oidctest.NewIssuer(t)
	m := newTestManager(t, issuerURL)

	var backendHit bool
	next := func(w http.ResponseWriter, r *http.Request, claims map[string]any) error {
		backendHit = true
		w.WriteHeader(http.StatusOK)
		return nil
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: TokenCookie, Value: signedToken(t, signer, issuerURL, time.Now().Add(30*time.Minute))})

	if err := m.Handle(w, r, next); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !backendHit {
		t.Error("backend not reached with valid session cookie")
	}
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}

// TestExpiredToken checks that an expired session cookie triggers a redirect
// to re-authenticate rather than passing through.
func TestExpiredToken(t *testing.T) {
	signer, issuerURL := oidctest.NewIssuer(t)
	m := newTestManager(t, issuerURL)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: TokenCookie, Value: signedToken(t, signer, issuerURL, time.Now().Add(-time.Hour))})

	if err := m.Handle(w, r, failNext(t)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
}

// TestCallbackErrors checks the responses to callbacks that can't complete a
// login.
func TestCallbackErrors(t *testing.T) {
	_, issuerURL := oidctest.NewIssuer(t)
	m := newTestManager(t, issuerURL)

	for _, tt := range []struct {
		name  string
		query string
		want  int
	}{
		// e.g. the user denied consent
		{"provider error", "error=access_denied&error_description=user+denied", http.StatusUnauthorized},
		{"invalid state", "code=abc&state=tampered.invalidsig", http.StatusBadRequest},
		{"missing PKCE cookie", "code=abc&state=" + state.Encode("nonce", "/dashboard", m.stateKey), http.StatusBadRequest},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, testCallbackPath+"?"+tt.query, nil)

			if err := m.Handle(w, r, failNext(t)); err != nil {
				t.Fatalf("Handle: %v", err)
			}
			if w.Code != tt.want {
				t.Errorf("status = %d, want %d", w.Code, tt.want)
			}
		})
	}
}

// TestCallbackClientAssertionUnavailable checks that a login fails with 502
// when the Workload API can't be reached.
func TestCallbackClientAssertionUnavailable(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix://"+filepath.Join(t.TempDir(), "missing.sock"))
	_, issuerURL := oidctest.NewIssuer(t)
	m := newTestManager(t, issuerURL, func(c *Config) {
		c.Credentials = issuer.Credentials{ClientID: "test-client", SPIFFE: true}
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, testCallbackPath+"?code=abc&state="+state.Encode("nonce", "/", m.stateKey), nil)
	r.AddCookie(&http.Cookie{Name: pkceCookiePrefix + "nonce", Value: "verifier"})

	if err := m.Handle(w, r, failNext(t)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if w.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want 502", w.Code)
	}
}

func TestAbsoluteURLScheme(t *testing.T) {
	m := &Manager{}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "example.com"
	if got := m.absoluteURL(r, testCallbackPath); got != "http://example.com/auth/callback" {
		t.Errorf("plain request: got %q", got)
	}

	r.TLS = &tls.ConnectionState{}
	if got := m.absoluteURL(r, testCallbackPath); got != "https://example.com/auth/callback" {
		t.Errorf("TLS request: got %q", got)
	}
}

// TestIssuerUnavailable checks that requests fail with ErrIssuerUnavailable
// while the issuer is unreachable, and that discovery is retried once the
// issuer comes up.
func TestIssuerUnavailable(t *testing.T) {
	var available atomic.Bool
	var iss *httptest.Server
	iss = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !available.Load() {
			http.Error(w, "starting up", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			iss.URL, iss.URL+"/authorize", iss.URL+"/token", iss.URL+"/keys")
	}))
	t.Cleanup(iss.Close)

	m := newTestManager(t, iss.URL)

	err := m.Handle(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/dashboard", nil), failNext(t))
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("Handle with issuer down: got %v, want ErrIssuerUnavailable", err)
	}

	available.Store(true)

	w := httptest.NewRecorder()
	if err := m.Handle(w, httptest.NewRequest(http.MethodGet, "/dashboard", nil), failNext(t)); err != nil {
		t.Fatalf("Handle with issuer up: %v", err)
	}
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, iss.URL+"/authorize") {
		t.Errorf("Location = %q, want prefix %s/authorize", loc, iss.URL)
	}
}

// TestStateKeyWithoutSecret checks that a client without a secret still
// signs its state, with a key no other instance shares.
func TestStateKeyWithoutSecret(t *testing.T) {
	creds := func(c *Config) { c.Credentials = issuer.Credentials{ClientID: "c", SPIFFE: true} }
	a := newTestManager(t, "https://id.example.com", creds)
	b := newTestManager(t, "https://id.example.com", creds)
	if a.stateKey == "" || a.stateKey == b.stateKey {
		t.Fatalf("state keys %q and %q: want distinct and non-empty", a.stateKey, b.stateKey)
	}
	st := state.Encode("nonce", "/", a.stateKey)
	if _, err := state.Verify(st, b.stateKey); err == nil {
		t.Error("state signed by one instance verified by another")
	}
}

func TestStripCookies(t *testing.T) {
	h := http.Header{}
	h.Add("Cookie", "theme=dark; "+TokenCookie+"=id; lang=fr")
	h.Add("Cookie", RefreshCookie+"=refresh")

	StripCookies(h)

	if got, want := h.Values("Cookie"), []string{"theme=dark; lang=fr"}; strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("Cookie = %q, want %q", got, want)
	}
}
