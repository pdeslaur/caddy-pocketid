package pocketid

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/pdeslaur/caddy-pocketid/internal/issuer"
	"github.com/pdeslaur/caddy-pocketid/internal/state"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("pocketid_auth", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("pocketid_auth", httpcaddyfile.Before, "basicauth")
}

const (
	cookieName        = "pocketid_token"
	refreshCookieName = "pocketid_refresh"
	// refreshCookieMaxAge matches PocketID's default refresh token lifetime.
	refreshCookieMaxAge = 30 * 24 * time.Hour
	// pkceCookiePrefix is followed by the state nonce, giving each login flow
	// its own verifier cookie.
	pkceCookiePrefix = "pocketid_pkce_"
)

// Middleware gates requests behind PocketID OIDC authentication.
// Valid sessions are identified by an RS256 id_token stored in a cookie.
// With Refresh, a refresh token stored in a second cookie renews the id_token
// once it has expired or its cookie is gone, without a redirect.
type Middleware struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	// ClientAssertion authenticates the client without a secret: "spiffe"
	// sends a JWT-SVID from the SPIFFE Workload API, for the issuer as its
	// audience.
	ClientAssertion string        `json:"client_assertion,omitempty"`
	CookieDomain    string        `json:"cookie_domain,omitempty"`
	CallbackPath    string        `json:"callback_path,omitempty"`
	Prompt          string        `json:"prompt,omitempty"`
	Refresh         bool          `json:"refresh,omitempty"`
	Headers         []HeaderPair  `json:"headers,omitempty"`
	ClaimHeaders    []ClaimHeader `json:"claim_headers,omitempty"`

	issuer *issuer.Provider
	// stateKey signs the OAuth2 state: the client secret, or a random key
	// without one, so a restart fails only the logins in flight.
	stateKey string
	logger   *zap.Logger
}

// HeaderPair is a static header injected into every authenticated request.
type HeaderPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ClaimHeader maps a JWT claim to a request header injected into authenticated requests.
type ClaimHeader struct {
	Claim  string `json:"claim"`
	Header string `json:"header"`
}

func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.pocketid_auth",
		New: func() caddy.Module { return new(Middleware) },
	}
}

func (m *Middleware) Provision(ctx caddy.Context) error {
	if m.Issuer == "" {
		return fmt.Errorf("issuer is required")
	}
	if m.ClientID == "" {
		return fmt.Errorf("client_id is required")
	}
	switch m.ClientAssertion {
	case "":
	case "spiffe":
		if m.ClientSecret != "" {
			return fmt.Errorf("client_secret and client_assertion are exclusive")
		}
	default:
		return fmt.Errorf("unknown client_assertion %q: only spiffe", m.ClientAssertion)
	}
	if m.CallbackPath == "" {
		m.CallbackPath = "/auth/callback"
	}
	m.stateKey = m.ClientSecret
	if m.stateKey == "" {
		key, err := state.NewNonce()
		if err != nil {
			return fmt.Errorf("generating state key: %w", err)
		}
		m.stateKey = key
	}

	m.logger = ctx.Logger()
	m.issuer = issuer.New(m.Issuer)
	return nil
}

func (m *Middleware) Validate() error {
	if _, err := url.ParseRequestURI(m.Issuer); err != nil {
		return fmt.Errorf("invalid issuer URL: %w", err)
	}
	if !strings.HasPrefix(m.CallbackPath, "/") {
		return fmt.Errorf("callback_path must begin with /")
	}
	return nil
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if _, err := m.issuer.Discover(r.Context()); err != nil {
		m.logger.Error("OIDC provider unavailable", zap.Error(err))
		return caddyhttp.Error(http.StatusBadGateway, err)
	}

	if r.URL.Path == m.CallbackPath {
		return m.handleCallback(w, r)
	}

	if cookie, err := r.Cookie(cookieName); err == nil {
		claims, err := m.issuer.ValidateToken(r.Context(), cookie.Value, m.ClientID)
		if err == nil {
			return next.ServeHTTP(w, m.injectHeaders(r, claims))
		}
		m.logger.Debug("rejecting token cookie", zap.Error(err))
	}

	if m.Refresh {
		if claims, ok := m.refreshSession(w, r); ok {
			return next.ServeHTTP(w, m.injectHeaders(r, claims))
		}
	}

	return m.redirectToAuth(w, r)
}

// refreshSession renews the session from the refresh token cookie, setting
// both cookies again, since PocketID rotates the refresh token. A rejected
// refresh token is cleared, so the next request doesn't try it again.
func (m *Middleware) refreshSession(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	cookie, err := r.Cookie(refreshCookieName)
	if err != nil {
		return nil, false
	}
	auth, err := m.clientAuth(r)
	if err != nil {
		m.logger.Error("client assertion unavailable", zap.Error(err))
		return nil, false
	}
	t, err := m.issuer.Refresh(r.Context(), cookie.Value, auth)
	if err != nil {
		m.logger.Info("refresh failed", zap.Error(err))
		m.clearRefreshCookie(w)
		return nil, false
	}
	claims, err := m.issuer.ValidateToken(r.Context(), t.IDToken, m.ClientID)
	if err != nil {
		m.logger.Error("refreshed id_token validation failed", zap.Error(err))
		m.clearRefreshCookie(w)
		return nil, false
	}
	if t.RefreshToken == "" {
		t.RefreshToken = cookie.Value
	}
	m.setSessionCookies(w, r, t)
	return claims, true
}

// injectHeaders clones the request, removes the session cookies, and sets
// static and claim-derived headers. Claim headers are always removed from the
// incoming request first, so a client cannot supply its own value when the
// claim is absent from the token.
func (m *Middleware) injectHeaders(r *http.Request, claims map[string]any) *http.Request {
	r = r.Clone(r.Context())
	stripSessionCookies(r.Header)
	for _, h := range m.Headers {
		r.Header.Set(h.Key, h.Value)
	}
	for _, ch := range m.ClaimHeaders {
		r.Header.Del(ch.Header)
		if v, ok := claims[ch.Claim].(string); ok {
			r.Header.Set(ch.Header, v)
		}
	}
	return r
}

// stripSessionCookies removes the session cookies from the Cookie headers, so
// the backend never sees the tokens, leaving the others as they were sent.
func stripSessionCookies(h http.Header) {
	var kept []string
	for _, line := range h.Values("Cookie") {
		var parts []string
		for part := range strings.SplitSeq(line, ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if name == cookieName || name == refreshCookieName {
				continue
			}
			parts = append(parts, strings.TrimSpace(part))
		}
		if len(parts) > 0 {
			kept = append(kept, strings.Join(parts, "; "))
		}
	}
	h.Del("Cookie")
	for _, line := range kept {
		h.Add("Cookie", line)
	}
}

func (m *Middleware) handleCallback(w http.ResponseWriter, r *http.Request) error {
	code := r.URL.Query().Get("code")
	stateParam := r.URL.Query().Get("state")

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		m.logger.Warn("auth error from provider", zap.String("error", errParam),
			zap.String("description", r.URL.Query().Get("error_description")))
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return nil
	}

	payload, err := state.Verify(stateParam, m.stateKey)
	if err != nil {
		m.logger.Warn("invalid state in callback", zap.Error(err))
		http.Error(w, "invalid state", http.StatusBadRequest)
		return nil
	}

	verifierCookie, err := r.Cookie(pkceCookiePrefix + payload.Nonce)
	if err != nil {
		http.Error(w, "missing pkce cookie", http.StatusBadRequest)
		return nil
	}

	auth, err := m.clientAuth(r)
	if err != nil {
		m.logger.Error("client assertion unavailable", zap.Error(err))
		http.Error(w, "client assertion unavailable", http.StatusBadGateway)
		return nil
	}

	t, err := m.issuer.ExchangeCode(r.Context(), code, verifierCookie.Value, m.callbackURI(r), auth)
	if err != nil {
		m.logger.Error("token exchange failed", zap.Error(err))
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return nil
	}

	if _, err := m.issuer.ValidateToken(r.Context(), t.IDToken, m.ClientID); err != nil {
		m.logger.Error("id_token validation failed", zap.Error(err))
		http.Error(w, "invalid id_token", http.StatusBadGateway)
		return nil
	}

	m.setSessionCookies(w, r, t)

	http.SetCookie(w, &http.Cookie{
		Name:   verifierCookie.Name,
		Value:  "",
		Path:   m.CallbackPath,
		MaxAge: -1,
	})

	http.Redirect(w, r, payload.ReturnURL, http.StatusFound)
	return nil
}

// clientAuth returns how the client authenticates to the token endpoint,
// fetching a JWT-SVID with client_assertion spiffe.
func (m *Middleware) clientAuth(r *http.Request) (issuer.ClientAuth, error) {
	auth := issuer.ClientAuth{ClientID: m.ClientID, Secret: m.ClientSecret}
	if m.ClientAssertion == "spiffe" {
		assertion, err := issuer.FetchSVID(r.Context(), m.Issuer)
		if err != nil {
			return issuer.ClientAuth{}, err
		}
		auth.Assertion = assertion
	}
	return auth, nil
}

// setSessionCookies stores the id_token and, with Refresh, the refresh token.
func (m *Middleware) setSessionCookies(w http.ResponseWriter, r *http.Request, t issuer.Tokens) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    t.IDToken,
		Domain:   m.cookieDomain(),
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	if !m.Refresh || t.RefreshToken == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     refreshCookieName,
		Value:    t.RefreshToken,
		Domain:   m.cookieDomain(),
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(refreshCookieMaxAge.Seconds()),
	})
}

func (m *Middleware) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   refreshCookieName,
		Value:  "",
		Domain: m.cookieDomain(),
		Path:   "/",
		MaxAge: -1,
	})
}

func (m *Middleware) cookieDomain() string {
	if m.CookieDomain == "" {
		return ""
	}
	return "." + m.CookieDomain
}

func (m *Middleware) redirectToAuth(w http.ResponseWriter, r *http.Request) error {
	verifier, challenge, err := issuer.GeneratePKCE()
	if err != nil {
		return fmt.Errorf("generating PKCE: %w", err)
	}
	nonce, err := state.NewNonce()
	if err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	st := state.Encode(nonce, r.URL.RequestURI(), m.stateKey)
	authURL, err := m.issuer.AuthURL(r.Context(), m.ClientID, m.callbackURI(r), st, challenge, m.Prompt)
	if err != nil {
		return caddyhttp.Error(http.StatusBadGateway, err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     pkceCookiePrefix + nonce,
		Value:    verifier,
		Path:     m.CallbackPath,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

func (m *Middleware) callbackURI(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + m.CallbackPath
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := &Middleware{}
	if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	for d.NextBlock(0) {
		switch d.Val() {
		case "issuer":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.Issuer = d.Val()
		case "client_id":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.ClientID = d.Val()
		case "client_secret":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.ClientSecret = d.Val()
		case "client_assertion":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.ClientAssertion = d.Val()
		case "cookie_domain":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.CookieDomain = d.Val()
		case "callback_path":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.CallbackPath = d.Val()
		case "prompt":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.Prompt = d.Val()
		case "refresh":
			if d.NextArg() {
				return d.ArgErr()
			}
			m.Refresh = true
		case "set_header":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return d.Errf("set_header requires exactly two arguments: key value")
			}
			m.Headers = append(m.Headers, HeaderPair{Key: args[0], Value: args[1]})
		case "forward_claim":
			args := d.RemainingArgs()
			if len(args) != 2 {
				return d.Errf("forward_claim requires exactly two arguments: claim header")
			}
			m.ClaimHeaders = append(m.ClaimHeaders, ClaimHeader{Claim: args[0], Header: args[1]})
		default:
			return d.Errf("unknown subdirective: %s", d.Val())
		}
	}
	return nil
}

var (
	_ caddy.Provisioner           = (*Middleware)(nil)
	_ caddy.Validator             = (*Middleware)(nil)
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
