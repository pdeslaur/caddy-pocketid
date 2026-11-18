package pocketid

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"chainguard.dev/go-oidctest/pkg/oidctest"
	"github.com/caddyserver/caddy/v2"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/pdeslaur/caddy-pocketid/internal/issuer"
	"github.com/pdeslaur/caddy-pocketid/internal/state"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"google.golang.org/grpc"
)

const testSPIFFEID = "spiffe://example.org/svc/app"

// fakeWorkloadAPI serves JWT-SVIDs for testSPIFFEID, signed with a key of its
// own, standing in for a SPIRE agent.
type fakeWorkloadAPI struct {
	workload.UnimplementedSpiffeWorkloadAPIServer
	signer jose.Signer
}

// serveWorkloadAPI serves a fake Workload API until the test ends and points
// SPIFFE_ENDPOINT_SOCKET at it.
func serveWorkloadAPI(t *testing.T) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	// Not t.TempDir: its paths can be longer than a socket's may be.
	dir, err := os.MkdirTemp("", "workload")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "api.sock")
	lis, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(srv, &fakeWorkloadAPI{signer: signer})
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix://"+socket)
}

func (a *fakeWorkloadAPI) FetchJWTSVID(_ context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	now := time.Now()
	token, err := jwt.Signed(a.signer).Claims(jwt.Claims{
		Subject:  testSPIFFEID,
		Audience: req.Audience,
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}).Serialize()
	if err != nil {
		return nil, err
	}
	return &workload.JWTSVIDResponse{Svids: []*workload.JWTSVID{{SpiffeId: testSPIFFEID, Svid: token}}}, nil
}

// tokenRequest is what a client sent to the token endpoint.
type tokenRequest struct {
	form          url.Values
	authorization string
}

// recordTokenRequests records the requests issuer.HTTPClient sends to a token
// endpoint until the test ends.
func recordTokenRequests(t *testing.T) func() []tokenRequest {
	t.Helper()
	rec := &tokenRecorder{}
	transport := issuer.HTTPClient.Transport
	issuer.HTTPClient.Transport = rec
	t.Cleanup(func() { issuer.HTTPClient.Transport = transport })
	return func() []tokenRequest {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		return slices.Clone(rec.requests)
	}
}

type tokenRecorder struct {
	mu       sync.Mutex
	requests []tokenRequest
}

func (rec *tokenRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	if strings.HasSuffix(r.URL.Path, "/token") {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		_ = r.Body.Close()
		form, err := url.ParseQuery(string(body))
		if err != nil {
			return nil, err
		}
		rec.mu.Lock()
		rec.requests = append(rec.requests, tokenRequest{form: form, authorization: r.Header.Get("Authorization")})
		rec.mu.Unlock()
		r = r.Clone(r.Context())
		r.Body = io.NopCloser(bytes.NewReader(body))
	}
	return http.DefaultTransport.RoundTrip(r)
}

// login runs the whole login flow against srv and returns the final response's
// status.
func login(t *testing.T, srv *httptest.Server) int {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	client := srv.Client()
	client.Jar = jar
	resp, err := client.Get(srv.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func provision(t *testing.T, m *Middleware) error {
	t.Helper()
	ctx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	return m.Provision(ctx)
}

// TestClientAuthentication checks how the client authenticates its code
// exchange: with its secret, with a JWT-SVID, or as a public client.
func TestClientAuthentication(t *testing.T) {
	for _, tt := range []struct {
		name            string
		secret          string
		assertion       string
		wantBasicAuth   bool
		wantSVIDInParam bool
	}{
		{name: "secret", secret: "test-secret", wantBasicAuth: true},
		{name: "spiffe", assertion: "spiffe", wantSVIDInParam: true},
		{name: "public"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			serveWorkloadAPI(t)
			requests := recordTokenRequests(t)
			_, issuerURL := oidctest.NewIssuer(t)
			m := &Middleware{
				Issuer:          issuerURL,
				ClientID:        "test-client",
				ClientSecret:    tt.secret,
				ClientAssertion: tt.assertion,
			}
			if err := provision(t, m); err != nil {
				t.Fatalf("Provision: %v", err)
			}
			srv := httptest.NewTLSServer(serveMiddleware(m, func(w http.ResponseWriter, r *http.Request) {}))
			t.Cleanup(srv.Close)

			if status := login(t, srv); status != http.StatusOK {
				t.Fatalf("login: got status %d, want 200", status)
			}

			got := requests()
			if len(got) != 1 {
				t.Fatalf("got %d token requests, want 1", len(got))
			}
			req := got[0]
			if gotBasic := strings.HasPrefix(req.authorization, "Basic "); gotBasic != tt.wantBasicAuth {
				t.Errorf("Basic auth sent: %v, want %v", gotBasic, tt.wantBasicAuth)
			}
			if req.form.Has("client_secret") {
				t.Errorf("client_secret sent in the body")
			}
			if !tt.wantBasicAuth && req.form.Get("client_id") != "test-client" {
				t.Errorf("client_id = %q, want test-client", req.form.Get("client_id"))
			}
			if !tt.wantSVIDInParam {
				if req.form.Has("client_assertion") || req.form.Has("client_assertion_type") {
					t.Errorf("client assertion sent: %v", req.form)
				}
				return
			}
			if got := req.form.Get("client_assertion_type"); got != issuer.ClientAssertionType {
				t.Errorf("client_assertion_type = %q, want %q", got, issuer.ClientAssertionType)
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
			if !slices.Equal([]string(claims.Audience), []string{issuerURL}) {
				t.Errorf("aud = %v, want [%s]", claims.Audience, issuerURL)
			}
		})
	}
}

// TestClientAssertionAgentUnavailable checks that a login fails with 502,
// without a token request, when the Workload API can't be reached.
func TestClientAssertionAgentUnavailable(t *testing.T) {
	t.Setenv("SPIFFE_ENDPOINT_SOCKET", "unix://"+filepath.Join(t.TempDir(), "missing.sock"))
	requests := recordTokenRequests(t)
	_, issuerURL := oidctest.NewIssuer(t)
	m := &Middleware{Issuer: issuerURL, ClientID: "test-client", ClientAssertion: "spiffe"}
	if err := provision(t, m); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	srv := httptest.NewTLSServer(serveMiddleware(m, func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	if status := login(t, srv); status != http.StatusBadGateway {
		t.Errorf("login: got status %d, want 502", status)
	}
	if got := requests(); len(got) != 0 {
		t.Errorf("got %d token requests, want none", len(got))
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
			if err := provision(t, m); (err != nil) != tt.wantErr {
				t.Errorf("Provision: %v, want error: %v", err, tt.wantErr)
			}
		})
	}
}

// TestStateKeyWithoutSecret checks that a client without a secret still
// signs its state, with a key no other instance shares.
func TestStateKeyWithoutSecret(t *testing.T) {
	a := &Middleware{Issuer: "https://id.example.com", ClientID: "c", ClientAssertion: "spiffe"}
	b := &Middleware{Issuer: "https://id.example.com", ClientID: "c", ClientAssertion: "spiffe"}
	for _, m := range []*Middleware{a, b} {
		if err := provision(t, m); err != nil {
			t.Fatalf("Provision: %v", err)
		}
	}
	if a.stateKey == "" || a.stateKey == b.stateKey {
		t.Fatalf("state keys %q and %q: want distinct and non-empty", a.stateKey, b.stateKey)
	}
	st := state.Encode("nonce", "/", a.stateKey)
	if _, err := state.Verify(st, b.stateKey); err == nil {
		t.Error("state signed by one instance verified by another")
	}
}
