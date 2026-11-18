package issuer

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// tokenRequest is what a client sent to the token endpoint.
type tokenRequest struct {
	form          url.Values
	authorization string
}

// tokenEndpoint is a fake issuer whose token endpoint records each request and
// answers with response.
type tokenEndpoint struct {
	*httptest.Server

	mu       sync.Mutex
	requests []tokenRequest
	status   int
	response string
}

func newTokenEndpoint(t *testing.T) *tokenEndpoint {
	t.Helper()
	e := &tokenEndpoint{
		status:   http.StatusOK,
		response: `{"id_token":"id","refresh_token":"refresh","token_type":"Bearer"}`,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"authorization_endpoint":%q,"token_endpoint":%q,"jwks_uri":%q}`,
			e.URL, e.URL+"/authorize", e.URL+"/token", e.URL+"/keys")
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		e.mu.Lock()
		defer e.mu.Unlock()
		e.requests = append(e.requests, tokenRequest{form: r.PostForm, authorization: r.Header.Get("Authorization")})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(e.status)
		_, _ = fmt.Fprint(w, e.response)
	})
	e.Server = httptest.NewServer(mux)
	t.Cleanup(e.Close)
	return e
}

func (e *tokenEndpoint) received() []tokenRequest {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.requests)
}

// redeemers redeem a token at the token endpoint, once for each grant.
var redeemers = []struct {
	grant  string
	redeem func(p *Provider, t *testing.T, creds Credentials) (Tokens, error)
}{
	{"authorization_code", func(p *Provider, t *testing.T, creds Credentials) (Tokens, error) {
		return p.ExchangeCode(t.Context(), "code", "verifier", "https://app.example.com/auth/callback", creds)
	}},
	{"refresh_token", func(p *Provider, t *testing.T, creds Credentials) (Tokens, error) {
		return p.Refresh(t.Context(), "refresh", creds)
	}},
}

// TestGrants checks the parameters each grant sends.
func TestGrants(t *testing.T) {
	want := map[string]url.Values{
		"authorization_code": {
			"grant_type":    {"authorization_code"},
			"code":          {"code"},
			"code_verifier": {"verifier"},
			"redirect_uri":  {"https://app.example.com/auth/callback"},
		},
		"refresh_token": {
			"grant_type":    {"refresh_token"},
			"refresh_token": {"refresh"},
		},
	}
	for _, r := range redeemers {
		t.Run(r.grant, func(t *testing.T) {
			e := newTokenEndpoint(t)
			got, err := r.redeem(New(e.URL), t, Credentials{ClientID: "test-client", Secret: "test-secret"})
			if err != nil {
				t.Fatalf("redeem: %v", err)
			}
			if got != (Tokens{IDToken: "id", RefreshToken: "refresh"}) {
				t.Errorf("tokens = %+v", got)
			}
			reqs := e.received()
			if len(reqs) != 1 {
				t.Fatalf("got %d token requests, want 1", len(reqs))
			}
			if form := reqs[0].form; !equalForms(form, want[r.grant]) {
				t.Errorf("form = %v, want %v", form, want[r.grant])
			}
		})
	}
}

func equalForms(a, b url.Values) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !slices.Equal(v, b[k]) {
			return false
		}
	}
	return true
}

// TestClientAuthentication checks how the client authenticates each grant:
// with its secret, with a JWT-SVID, or as a public client.
func TestClientAuthentication(t *testing.T) {
	for _, tt := range []struct {
		name          string
		creds         Credentials
		wantBasicAuth string
		wantSVID      bool
	}{
		{
			name:  "secret",
			creds: Credentials{ClientID: "test-client", Secret: "s3cr:t&"},
			// RFC 6749 section 2.3.1: form-encoded before Basic encoding.
			wantBasicAuth: "test-client:s3cr%3At%26",
		},
		{name: "spiffe", creds: Credentials{ClientID: "test-client", SPIFFE: true}, wantSVID: true},
		{name: "public", creds: Credentials{ClientID: "test-client"}},
	} {
		for _, r := range redeemers {
			t.Run(tt.name+"/"+r.grant, func(t *testing.T) {
				serveWorkloadAPI(t)
				e := newTokenEndpoint(t)
				if _, err := r.redeem(New(e.URL), t, tt.creds); err != nil {
					t.Fatalf("redeem: %v", err)
				}
				reqs := e.received()
				if len(reqs) != 1 {
					t.Fatalf("got %d token requests, want 1", len(reqs))
				}
				req := reqs[0]

				user, pass, gotBasic := (&http.Request{Header: http.Header{"Authorization": {req.authorization}}}).BasicAuth()
				if tt.wantBasicAuth == "" && gotBasic {
					t.Errorf("Basic auth sent")
				}
				if tt.wantBasicAuth != "" && user+":"+pass != tt.wantBasicAuth {
					t.Errorf("Basic auth = %q, want %q", user+":"+pass, tt.wantBasicAuth)
				}
				if req.form.Has("client_secret") {
					t.Errorf("client_secret sent in the body")
				}
				if tt.wantBasicAuth == "" && req.form.Get("client_id") != "test-client" {
					t.Errorf("client_id = %q, want test-client", req.form.Get("client_id"))
				}
				if !tt.wantSVID {
					if req.form.Has("client_assertion") || req.form.Has("client_assertion_type") {
						t.Errorf("client assertion sent: %v", req.form)
					}
					return
				}
				if got := req.form.Get("client_assertion_type"); got != clientAssertionType {
					t.Errorf("client_assertion_type = %q, want %q", got, clientAssertionType)
				}
				tok, err := jwt.ParseSigned(req.form.Get("client_assertion"), []jose.SignatureAlgorithm{jose.ES256})
				if err != nil {
					t.Fatalf("parsing client_assertion: %v", err)
				}
				var claims jwt.Claims
				if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
					t.Fatalf("claims: %v", err)
				}
				if claims.Subject != testSPIFFEID {
					t.Errorf("sub = %q, want %q", claims.Subject, testSPIFFEID)
				}
				if !slices.Equal([]string(claims.Audience), []string{e.URL}) {
					t.Errorf("aud = %v, want [%s]", claims.Audience, e.URL)
				}
			})
		}
	}
}

// TestClientAssertionAgentUnavailable checks that a grant fails with
// ErrClientAssertion, without a token request, when the Workload API can't be
// reached.
func TestClientAssertionAgentUnavailable(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix://"+filepath.Join(t.TempDir(), "missing.sock"))
	for _, r := range redeemers {
		t.Run(r.grant, func(t *testing.T) {
			e := newTokenEndpoint(t)
			_, err := r.redeem(New(e.URL), t, Credentials{ClientID: "test-client", SPIFFE: true})
			if !errors.Is(err, ErrClientAssertion) {
				t.Errorf("redeem: %v, want ErrClientAssertion", err)
			}
			if got := e.received(); len(got) != 0 {
				t.Errorf("got %d token requests, want none", len(got))
			}
		})
	}
}

// TestTokenResponseErrors checks that an error response, or a response without
// an id_token, fails the grant.
func TestTokenResponseErrors(t *testing.T) {
	for _, tt := range []struct {
		name     string
		status   int
		response string
		wantErr  string
	}{
		{
			name:     "error response",
			status:   http.StatusBadRequest,
			response: `{"error":"invalid_grant","error_description":"token revoked"}`,
			wantErr:  "invalid_grant token revoked",
		},
		{
			name:     "no id_token",
			status:   http.StatusOK,
			response: `{"access_token":"a","token_type":"Bearer"}`,
			wantErr:  "no id_token",
		},
		{
			name:     "not JSON",
			status:   http.StatusOK,
			response: `<html>`,
			wantErr:  "parsing token response",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := newTokenEndpoint(t)
			e.status, e.response = tt.status, tt.response
			_, err := New(e.URL).Refresh(t.Context(), "refresh", Credentials{ClientID: "test-client"})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Refresh: %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestRefreshTokenOptional checks that a response without a refresh token
// still succeeds.
func TestRefreshTokenOptional(t *testing.T) {
	e := newTokenEndpoint(t)
	e.response = `{"id_token":"id","token_type":"Bearer"}`
	got, err := New(e.URL).Refresh(t.Context(), "refresh", Credentials{ClientID: "test-client"})
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got != (Tokens{IDToken: "id"}) {
		t.Errorf("tokens = %+v, want only an id_token", got)
	}
}
