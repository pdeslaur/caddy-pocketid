package pocketid

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"chainguard.dev/go-oidctest/pkg/oidctest"
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/pdeslaur/caddy-pocketid/internal/session"
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
		if c.Name == session.TokenCookie {
			hasSessionCookie = true
			break
		}
	}
	if !hasSessionCookie {
		t.Error("session cookie not set: OIDC flow did not complete")
	}
}

// TestSetHeader checks that static headers are injected into authenticated requests.
func TestSetHeader(t *testing.T) {
	signer, issuerURL := oidctest.NewIssuer(t)
	m := newTestMiddleware(t, issuerURL)
	m.Headers = []HeaderPair{
		{Key: "Authorization", Value: "Basic dXNlcjpwYXNz"},
		{Key: "X-Auth-Source", Value: "pocketid"},
	}

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

	var gotAuth, gotSource string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotAuth = r.Header.Get("Authorization")
		gotSource = r.Header.Get("X-Auth-Source")
		return nil
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: session.TokenCookie, Value: token})

	if err := m.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if gotAuth != "Basic dXNlcjpwYXNz" {
		t.Errorf("Authorization = %q, want Basic dXNlcjpwYXNz", gotAuth)
	}
	if gotSource != "pocketid" {
		t.Errorf("X-Auth-Source = %q, want pocketid", gotSource)
	}
}

// TestForwardClaim checks that JWT claims are forwarded as request headers.
func TestForwardClaim(t *testing.T) {
	signer, issuerURL := oidctest.NewIssuer(t)
	m := newTestMiddleware(t, issuerURL)
	m.ClaimHeaders = []ClaimHeader{
		{Claim: "sub", Header: "X-Remote-User"},
		{Claim: "email", Header: "X-Remote-Email"},
	}

	type customClaims struct {
		jwt.Claims
		Email string `json:"email"`
	}
	token, err := jwt.Signed(signer).Claims(customClaims{
		Claims: jwt.Claims{
			Issuer:   issuerURL,
			IssuedAt: jwt.NewNumericDate(time.Now()),
			Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			Subject:  "user-123",
			Audience: jwt.Audience{"test-client"},
		},
		Email: "alice@example.com",
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	var gotUser, gotEmail string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotUser = r.Header.Get("X-Remote-User")
		gotEmail = r.Header.Get("X-Remote-Email")
		return nil
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: session.TokenCookie, Value: token})

	if err := m.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if gotUser != "user-123" {
		t.Errorf("X-Remote-User = %q, want user-123", gotUser)
	}
	if gotEmail != "alice@example.com" {
		t.Errorf("X-Remote-Email = %q, want alice@example.com", gotEmail)
	}
}

// TestHeadersNotInjectedWhenUnauthenticated checks headers are not leaked on redirect.
func TestHeadersNotInjectedWhenUnauthenticated(t *testing.T) {
	_, issuerURL := oidctest.NewIssuer(t)
	m := newTestMiddleware(t, issuerURL)
	m.Headers = []HeaderPair{{Key: "Authorization", Value: "Basic dXNlcjpwYXNz"}}

	var gotAuth string
	var backendHit bool
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotAuth = r.Header.Get("Authorization")
		backendHit = true
		return nil
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)

	if err := m.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if backendHit {
		t.Error("backend reached on unauthenticated request")
	}
	if gotAuth != "" {
		t.Errorf("Authorization = %q, want empty", gotAuth)
	}
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
}

// TestForwardClaimStripsClientHeader checks that a client-supplied header named
// by forward_claim never reaches the backend when the token lacks that claim.
func TestForwardClaimStripsClientHeader(t *testing.T) {
	signer, issuerURL := oidctest.NewIssuer(t)
	m := newTestMiddleware(t, issuerURL)
	m.ClaimHeaders = []ClaimHeader{{Claim: "email", Header: "X-Remote-Email"}}

	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   issuerURL,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  "user-123",
		Audience: jwt.Audience{"test-client"},
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	var gotEmail []string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotEmail = r.Header.Values("X-Remote-Email")
		return nil
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Set("X-Remote-Email", "admin@example.com")
	r.AddCookie(&http.Cookie{Name: session.TokenCookie, Value: token})

	if err := m.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if len(gotEmail) != 0 {
		t.Errorf("X-Remote-Email = %q, want absent", gotEmail)
	}
}

// TestProvisionIssuerUnavailable checks that Provision succeeds while the
// issuer is unreachable, requests fail with 502, and discovery is retried
// once the issuer comes up.
func TestProvisionIssuerUnavailable(t *testing.T) {
	var available atomic.Bool
	var issuer *httptest.Server
	issuer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !available.Load() {
			http.Error(w, "starting up", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			issuer.URL, issuer.URL+"/authorize", issuer.URL+"/token", issuer.URL+"/keys")
	}))
	t.Cleanup(issuer.Close)

	m := newTestMiddleware(t, issuer.URL)

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	err := m.ServeHTTP(httptest.NewRecorder(), r, nopNext)
	var herr caddyhttp.HandlerError
	if !errors.As(err, &herr) || herr.StatusCode != http.StatusBadGateway {
		t.Fatalf("ServeHTTP with issuer down: got %v, want 502 HandlerError", err)
	}

	available.Store(true)

	w := httptest.NewRecorder()
	if err := m.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dashboard", nil), nopNext); err != nil {
		t.Fatalf("ServeHTTP with issuer up: %v", err)
	}
	if w.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", w.Code)
	}
	if loc := w.Header().Get("Location"); !strings.HasPrefix(loc, issuer.URL+"/authorize") {
		t.Errorf("Location = %q, want prefix %s/authorize", loc, issuer.URL)
	}
}

// TestSessionCookiesNotForwarded checks that the backend never sees the
// session cookies, and sees every other cookie as it was sent.
func TestSessionCookiesNotForwarded(t *testing.T) {
	signer, issuerURL := oidctest.NewIssuer(t)
	m := newTestMiddleware(t, issuerURL)

	token, err := jwt.Signed(signer).Claims(jwt.Claims{
		Issuer:   issuerURL,
		IssuedAt: jwt.NewNumericDate(time.Now()),
		Expiry:   jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
		Subject:  "user-123",
		Audience: jwt.Audience{"test-client"},
	}).Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	var gotCookies []string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotCookies = r.Header.Values("Cookie")
		return nil
	})

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Add("Cookie", "theme=dark; "+session.TokenCookie+"="+token+"; lang=fr")
	r.Header.Add("Cookie", session.RefreshCookie+"=refresh")

	if err := m.ServeHTTP(httptest.NewRecorder(), r, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if want := []string{"theme=dark; lang=fr"}; strings.Join(gotCookies, "|") != strings.Join(want, "|") {
		t.Errorf("Cookie = %q, want %q", gotCookies, want)
	}
}

func TestProvisionClientAuthentication(t *testing.T) {
	for _, tt := range []struct {
		name      string
		secret    string
		assertion string
		wantErr   bool
	}{
		{name: "secret", secret: "s"},
		{name: "spiffe", assertion: "spiffe"},
		{name: "public"},
		{name: "both", secret: "s", assertion: "spiffe", wantErr: true},
		{name: "unknown assertion", assertion: "kerberos", wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m := &Middleware{
				Issuer:          "https://id.example.com",
				ClientID:        "test-client",
				ClientSecret:    tt.secret,
				ClientAssertion: tt.assertion,
			}
			ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
			t.Cleanup(cancel)
			if err := m.Provision(ctx); (err != nil) != tt.wantErr {
				t.Errorf("Provision: %v, want error: %v", err, tt.wantErr)
			}
		})
	}
}

func TestUnmarshalCaddyfile(t *testing.T) {
	var m Middleware
	d := caddyfile.NewTestDispenser(`pocketid_auth {
		issuer https://id.example.com
		client_id test-client
		client_secret test-secret
		client_assertion spiffe
		cookie_domain example.com
		callback_path /cb
		logout_path /logout
		post_logout_redirect /bye
		prompt login
		refresh
		set_header X-Auth-Source pocketid
		forward_claim email X-Remote-Email
	}`)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	want := Middleware{
		Issuer:             "https://id.example.com",
		ClientID:           "test-client",
		ClientSecret:       "test-secret",
		ClientAssertion:    "spiffe",
		CookieDomain:       "example.com",
		CallbackPath:       "/cb",
		LogoutPath:         "/logout",
		PostLogoutRedirect: "/bye",
		Prompt:             "login",
		Refresh:            true,
		Headers:            []HeaderPair{{Key: "X-Auth-Source", Value: "pocketid"}},
		ClaimHeaders:       []ClaimHeader{{Claim: "email", Header: "X-Remote-Email"}},
	}
	if !reflect.DeepEqual(m, want) {
		t.Errorf("got %+v, want %+v", m, want)
	}

	for _, bad := range []string{
		"refresh yes",
		"issuer",
		"logout_path",
		"post_logout_redirect",
		"set_header X-Only-Key",
		"forward_claim email",
		"unknown value",
	} {
		d := caddyfile.NewTestDispenser("pocketid_auth {\n" + bad + "\n}")
		if err := (&Middleware{}).UnmarshalCaddyfile(d); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

func TestValidateLogout(t *testing.T) {
	for _, tt := range []struct {
		logoutPath, postLogoutRedirect string
		ok                             bool
	}{
		{"", "", true},
		{"/logout", "/", true},
		{"/logout", "/signed-out", true},
		{"logout", "/", false},
		{"/auth/callback", "/", false},
		{"/logout", "https://example.com/", false},
		{"", "/", false},
	} {
		m := Middleware{
			Issuer:             "https://id.example.com",
			CallbackPath:       "/auth/callback",
			LogoutPath:         tt.logoutPath,
			PostLogoutRedirect: tt.postLogoutRedirect,
		}
		if err := m.Validate(); (err == nil) != tt.ok {
			t.Errorf("logout_path %q, post_logout_redirect %q: Validate() = %v, want ok %v", tt.logoutPath, tt.postLogoutRedirect, err, tt.ok)
		}
	}
}
