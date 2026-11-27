package session

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/pdeslaur/caddy-pocketid/internal/state"
)

// tokenRequest is what a client sent to the token endpoint.
type tokenRequest struct {
	form          url.Values
	authorization string
}

// refreshIssuer is a fake OIDC issuer whose token endpoint redeems any
// authorization code and rotates refresh tokens, like PocketID: each refresh
// token can be redeemed once. It records the token requests it receives, and
// advertises an end_session_endpoint, which nothing serves.
type refreshIssuer struct {
	*httptest.Server
	signer jose.Signer

	mu       sync.Mutex
	active   map[string]bool
	issued   int
	requests []tokenRequest
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
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"end_session_endpoint":%q,"jwks_uri":%q,"id_token_signing_alg_values_supported":["RS256"]}`,
			iss.URL, iss.URL+"/authorize", iss.URL+"/token", iss.URL+"/end-session?ui=1", iss.URL+"/keys")
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
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	iss.mu.Lock()
	defer iss.mu.Unlock()
	iss.requests = append(iss.requests, tokenRequest{form: r.PostForm, authorization: r.Header.Get("Authorization")})
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
	case "refresh_token":
		if !iss.active[r.PostForm.Get("refresh_token")] {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"error":"invalid_grant"}`)
			return
		}
		delete(iss.active, r.PostForm.Get("refresh_token"))
	default:
		http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"id_token":      iss.idToken(time.Now().Add(time.Hour)),
		"refresh_token": iss.newRefreshTokenLocked(),
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
	return iss.newRefreshTokenLocked()
}

func (iss *refreshIssuer) newRefreshTokenLocked() string {
	iss.issued++
	token := fmt.Sprintf("refresh-%d", iss.issued)
	iss.active[token] = true
	return token
}

func (iss *refreshIssuer) received() []tokenRequest {
	iss.mu.Lock()
	defer iss.mu.Unlock()
	return slices.Clone(iss.requests)
}

func withRefresh(c *Config) { c.Refresh = true }

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
			m := newTestManager(t, iss.URL, withRefresh)
			refreshToken := iss.issueRefreshToken()

			var gotSub any
			next := func(w http.ResponseWriter, r *http.Request, claims map[string]any) error {
				gotSub = claims["sub"]
				return nil
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
			if tt.idTokenCookie {
				r.AddCookie(&http.Cookie{Name: TokenCookie, Value: iss.idToken(time.Now().Add(-time.Minute))})
			}
			r.AddCookie(&http.Cookie{Name: RefreshCookie, Value: refreshToken})

			if err := m.Handle(w, r, next); err != nil {
				t.Fatalf("Handle: %v", err)
			}
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			if gotSub != "test-subject" {
				t.Errorf("backend got sub %v, want test-subject", gotSub)
			}

			got := iss.received()
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

			idCookie := responseCookie(w, TokenCookie)
			if idCookie == nil {
				t.Fatal("id_token cookie not set")
			}
			if _, err := m.issuer.ValidateToken(t.Context(), idCookie.Value, "test-client"); err != nil {
				t.Errorf("id_token cookie invalid: %v", err)
			}
			refreshCookie := responseCookie(w, RefreshCookie)
			if refreshCookie == nil {
				t.Fatal("refresh cookie not set")
			}
			if refreshCookie.Value == refreshToken {
				t.Error("refresh cookie not rotated")
			}
			if want := int(RefreshCookieMaxAge.Seconds()); refreshCookie.MaxAge != want {
				t.Errorf("refresh cookie MaxAge = %d, want %d", refreshCookie.MaxAge, want)
			}
		})
	}
}

// TestRefreshRejected checks that a refresh token the issuer rejects leads to
// a login redirect and is cleared.
func TestRefreshRejected(t *testing.T) {
	iss := newRefreshIssuer(t)
	m := newTestManager(t, iss.URL, withRefresh)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: RefreshCookie, Value: "revoked"})

	if err := m.Handle(w, r, failNext(t)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	c := responseCookie(w, RefreshCookie)
	if c == nil || c.MaxAge >= 0 {
		t.Errorf("refresh cookie not cleared: %v", c)
	}
}

// TestRefreshDisabled checks that without Refresh, a refresh token cookie is
// ignored.
func TestRefreshDisabled(t *testing.T) {
	iss := newRefreshIssuer(t)
	m := newTestManager(t, iss.URL)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	r.AddCookie(&http.Cookie{Name: RefreshCookie, Value: iss.issueRefreshToken()})

	if err := m.Handle(w, r, failNext(t)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if w.Code != http.StatusFound {
		t.Errorf("status = %d, want 302", w.Code)
	}
	if got := iss.received(); len(got) != 0 {
		t.Errorf("got %d token requests, want none", len(got))
	}
}

// TestCallbackStoresRefreshToken checks that the callback stores the refresh
// token only with Refresh.
func TestCallbackStoresRefreshToken(t *testing.T) {
	for _, refresh := range []bool{true, false} {
		t.Run(fmt.Sprintf("refresh=%v", refresh), func(t *testing.T) {
			iss := newRefreshIssuer(t)
			m := newTestManager(t, iss.URL, func(c *Config) { c.Refresh = refresh })

			st := state.Encode("nonce", "/dashboard", m.stateKey)
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, testCallbackPath+"?code=abc&state="+st, nil)
			r.AddCookie(&http.Cookie{Name: pkceCookiePrefix + "nonce", Value: "verifier"})

			if err := m.Handle(w, r, failNext(t)); err != nil {
				t.Fatalf("Handle: %v", err)
			}
			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", w.Code)
			}
			if responseCookie(w, TokenCookie) == nil {
				t.Error("id_token cookie not set")
			}
			if got := responseCookie(w, RefreshCookie) != nil; got != refresh {
				t.Errorf("refresh cookie set: %v, want %v", got, refresh)
			}
		})
	}
}
