package pocketid

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/pdeslaur/caddy-pocketid/internal/state"
)

// refreshIssuer is a fake OIDC issuer whose token endpoint redeems any
// authorization code and rotates refresh tokens, like PocketID: each refresh
// token can be redeemed once.
type refreshIssuer struct {
	*httptest.Server
	signer jose.Signer

	mu     sync.Mutex
	active map[string]bool
	issued int
}

func newRefreshIssuer(t *testing.T) *refreshIssuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	iss := &refreshIssuer{signer: signer, active: map[string]bool{}}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q,"id_token_signing_alg_values_supported":["RS256"]}`,
			iss.URL, iss.URL+"/authorize", iss.URL+"/token", iss.URL+"/keys")
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", iss.token)
	iss.Server = httptest.NewServer(mux)
	t.Cleanup(iss.Close)
	return iss
}

func (iss *refreshIssuer) token(w http.ResponseWriter, r *http.Request) {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	switch r.FormValue("grant_type") {
	case "authorization_code":
	case "refresh_token":
		if !iss.active[r.FormValue("refresh_token")] {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		delete(iss.active, r.FormValue("refresh_token"))
	default:
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		return
	}
	iss.issued++
	refreshToken := fmt.Sprintf("refresh-%d", iss.issued)
	iss.active[refreshToken] = true
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id_token":      iss.idToken(time.Now().Add(time.Hour)),
		"refresh_token": refreshToken,
		"access_token":  "unused",
		"token_type":    "Bearer",
	})
}

// idToken returns an id_token for test-client expiring at expiry.
func (iss *refreshIssuer) idToken(expiry time.Time) string {
	token, err := jwt.Signed(iss.signer).Claims(jwt.Claims{
		Issuer:   iss.URL,
		IssuedAt: jwt.NewNumericDate(expiry.Add(-time.Hour)),
		Expiry:   jwt.NewNumericDate(expiry),
		Subject:  "test-subject",
		Audience: jwt.Audience{"test-client"},
	}).Serialize()
	if err != nil {
		panic(err)
	}
	return token
}

// issueRefreshToken returns a refresh token the issuer will redeem.
func (iss *refreshIssuer) issueRefreshToken() string {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	iss.issued++
	token := fmt.Sprintf("refresh-%d", iss.issued)
	iss.active[token] = true
	return token
}

func newRefreshMiddleware(t *testing.T, iss *refreshIssuer) *Middleware {
	t.Helper()
	m := newTestMiddleware(t, iss.URL)
	m.Refresh = true
	return m
}

func responseCookie(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// TestRefreshRenewsSession checks that a session whose id_token has expired,
// or whose id_token cookie is gone, is renewed from the refresh token without
// a redirect, and that both cookies are set again.
func TestRefreshRenewsSession(t *testing.T) {
	for _, tt := range []struct {
		name          string
		idTokenCookie bool
	}{
		{name: "expired id_token", idTokenCookie: true},
		{name: "no id_token cookie"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			iss := newRefreshIssuer(t)
			m := newRefreshMiddleware(t, iss)
			requests := recordTokenRequests(t)
			refreshToken := iss.issueRefreshToken()

			var gotSub string
			m.ClaimHeaders = []ClaimHeader{{Claim: "sub", Header: "X-Remote-User"}}
			next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
				gotSub = r.Header.Get("X-Remote-User")
				return nil
			})

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
			if tt.idTokenCookie {
				r.AddCookie(&http.Cookie{Name: cookieName, Value: iss.idToken(time.Now().Add(-time.Minute))})
			}
			r.AddCookie(&http.Cookie{Name: refreshCookieName, Value: refreshToken})

			if err := m.ServeHTTP(w, r, next); err != nil {
				t.Fatalf("ServeHTTP: %v", err)
			}
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			if gotSub != "test-subject" {
				t.Errorf("X-Remote-User = %q, want test-subject", gotSub)
			}

			got := requests()
			if len(got) != 1 {
				t.Fatalf("got %d token requests, want 1", len(got))
			}
			if g := got[0].form.Get("grant_type"); g != "refresh_token" {
				t.Errorf("grant_type = %q, want refresh_token", g)
			}
			if g := got[0].form.Get("refresh_token"); g != refreshToken {
				t.Errorf("refresh_token = %q, want %q", g, refreshToken)
			}
			if !strings.HasPrefix(got[0].authorization, "Basic ") {
				t.Errorf("refresh not authenticated with the client secret")
			}

			idCookie := responseCookie(w, cookieName)
			if idCookie == nil {
				t.Fatal("id_token cookie not set")
			}
			if _, err := m.issuer.ValidateToken(t.Context(), idCookie.Value, m.ClientID); err != nil {
				t.Errorf("id_token cookie invalid: %v", err)
			}
			refreshCookie := responseCookie(w, refreshCookieName)
			if refreshCookie == nil {
				t.Fatal("refresh cookie not set")
			}
			if refreshCookie.Value == refreshToken {
				t.Error("refresh cookie not rotated")
			}
			if want := int(refreshCookieMaxAge.Seconds()); refreshCookie.MaxAge != want {
				t.Errorf("refresh cookie MaxAge = %d, want %d", refreshCookie.MaxAge, want)
			}
		})
	}
}

// TestRefreshRejected checks that a refresh token the issuer rejects leads to
// a login redirect and is cleared.
func TestRefreshRejected(t *testing.T) {
	iss := newRefreshIssuer(t)
	m := newRefreshMiddleware(t, iss)

	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		t.Error("backend reached with a rejected refresh token")
		return nil
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: refreshCookieName, Value: "revoked"})

	if err := m.ServeHTTP(w, r, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	c := responseCookie(w, refreshCookieName)
	if c == nil || c.MaxAge >= 0 {
		t.Errorf("refresh cookie not cleared: %v", c)
	}
}

// TestRefreshDisabled checks that without refresh, a refresh token cookie is
// ignored.
func TestRefreshDisabled(t *testing.T) {
	iss := newRefreshIssuer(t)
	m := newTestMiddleware(t, iss.URL)
	requests := recordTokenRequests(t)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: refreshCookieName, Value: iss.issueRefreshToken()})

	if err := m.ServeHTTP(w, r, nopNext); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	if got := requests(); len(got) != 0 {
		t.Errorf("got %d token requests, want none", len(got))
	}
}

// TestCallbackStoresRefreshToken checks that the callback stores the refresh
// token only with refresh.
func TestCallbackStoresRefreshToken(t *testing.T) {
	for _, refresh := range []bool{true, false} {
		t.Run(fmt.Sprintf("refresh=%v", refresh), func(t *testing.T) {
			iss := newRefreshIssuer(t)
			m := newTestMiddleware(t, iss.URL)
			m.Refresh = refresh

			st := state.Encode("nonce", "/dashboard", m.stateKey)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/auth/callback?code=abc&state="+st, nil)
			r.AddCookie(&http.Cookie{Name: pkceCookiePrefix + "nonce", Value: "verifier"})

			if err := m.ServeHTTP(w, r, nopNext); err != nil {
				t.Fatalf("ServeHTTP: %v", err)
			}
			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", w.Code)
			}
			if responseCookie(w, cookieName) == nil {
				t.Error("id_token cookie not set")
			}
			if got := responseCookie(w, refreshCookieName) != nil; got != refresh {
				t.Errorf("refresh cookie set: %v, want %v", got, refresh)
			}
		})
	}
}

// TestSessionCookiesNotForwarded checks that the backend never sees the
// session cookies, and sees every other cookie as it was sent.
func TestSessionCookiesNotForwarded(t *testing.T) {
	iss := newRefreshIssuer(t)
	m := newRefreshMiddleware(t, iss)

	var gotCookies []string
	next := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		gotCookies = r.Header.Values("Cookie")
		return nil
	})

	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.Header.Add("Cookie", "theme=dark; "+cookieName+"="+iss.idToken(time.Now().Add(time.Hour))+"; lang=fr")
	r.Header.Add("Cookie", refreshCookieName+"="+iss.issueRefreshToken())

	if err := m.ServeHTTP(httptest.NewRecorder(), r, next); err != nil {
		t.Fatalf("ServeHTTP: %v", err)
	}
	if want := []string{"theme=dark; lang=fr"}; strings.Join(gotCookies, "|") != strings.Join(want, "|") {
		t.Errorf("Cookie = %q, want %q", gotCookies, want)
	}
}

func TestUnmarshalCaddyfileRefresh(t *testing.T) {
	var m Middleware
	d := caddyfile.NewTestDispenser(`pocketid_auth {
		issuer https://id.example.com
		client_id test-client
		refresh
	}`)
	if err := m.UnmarshalCaddyfile(d); err != nil {
		t.Fatalf("UnmarshalCaddyfile: %v", err)
	}
	if !m.Refresh {
		t.Error("refresh not enabled")
	}

	d = caddyfile.NewTestDispenser(`pocketid_auth {
		refresh yes
	}`)
	if err := (&Middleware{}).UnmarshalCaddyfile(d); err == nil {
		t.Error("refresh with an argument: want error")
	}
}
