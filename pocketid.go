package pocketid

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("pocketid_auth", parseCaddyfile)
}

const (
	cookieName     = "pocketid_token"
	pkceCookieName = "pocketid_pkce"
)

// Middleware gates requests behind PocketID OIDC authentication.
// Valid sessions are identified by an RS256 id_token stored in a cookie.
type Middleware struct {
	Issuer       string   `json:"issuer"`
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	CookieDomain string   `json:"cookie_domain,omitempty"`
	CallbackPath string   `json:"callback_path,omitempty"`
	BypassPaths  []string `json:"bypass_paths,omitempty"`
	BypassQuery  []string `json:"bypass_query,omitempty"`

	oidc   *oidcProvider
	logger *zap.Logger
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
	if m.ClientSecret == "" {
		return fmt.Errorf("client_secret is required")
	}
	if m.CallbackPath == "" {
		m.CallbackPath = "/auth/callback"
	}

	m.logger = ctx.Logger()

	provider, err := newOIDCProvider(ctx, m.Issuer)
	if err != nil {
		return fmt.Errorf("initializing OIDC provider: %w", err)
	}
	m.oidc = provider
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
	if r.URL.Path == m.CallbackPath {
		return m.handleCallback(w, r)
	}

	for _, p := range m.BypassPaths {
		if matchPath(r.URL.Path, p) {
			return next.ServeHTTP(w, r)
		}
	}

	for _, q := range m.BypassQuery {
		if r.URL.Query().Has(q) {
			return next.ServeHTTP(w, r)
		}
	}

	if cookie, err := r.Cookie(cookieName); err == nil {
		if _, err := m.oidc.validateToken(r.Context(), cookie.Value, m.ClientID); err == nil {
			return next.ServeHTTP(w, r)
		} else {
			m.logger.Debug("rejecting token cookie", zap.Error(err))
		}
	}

	return m.redirectToAuth(w, r)
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

	returnURL, err := verifyState(stateParam, m.ClientSecret)
	if err != nil {
		m.logger.Warn("invalid state in callback", zap.Error(err))
		http.Error(w, "invalid state", http.StatusBadRequest)
		return nil
	}

	verifierCookie, err := r.Cookie(pkceCookieName)
	if err != nil {
		http.Error(w, "missing pkce cookie", http.StatusBadRequest)
		return nil
	}

	idToken, err := m.oidc.exchangeCode(r.Context(), code, verifierCookie.Value,
		m.callbackURI(r), m.ClientID, m.ClientSecret)
	if err != nil {
		m.logger.Error("token exchange failed", zap.Error(err))
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return nil
	}

	cookieDomain := ""
	if m.CookieDomain != "" {
		cookieDomain = "." + m.CookieDomain
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    idToken,
		Domain:   cookieDomain,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:   pkceCookieName,
		Value:  "",
		MaxAge: -1,
	})

	http.Redirect(w, r, returnURL, http.StatusFound)
	return nil
}

func (m *Middleware) redirectToAuth(w http.ResponseWriter, r *http.Request) error {
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return fmt.Errorf("generating PKCE: %w", err)
	}

	returnURL := r.URL.RequestURI()
	state := encodeState(returnURL, m.ClientSecret)
	authURL := m.oidc.authURL(m.ClientID, m.callbackURI(r), state, challenge)

	http.SetCookie(w, &http.Cookie{
		Name:     pkceCookieName,
		Value:    verifier,
		Path:     m.CallbackPath,
		HttpOnly: true,
		Secure:   true,
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

func matchPath(path, pattern string) bool {
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "/*")
		return path == prefix || strings.HasPrefix(path, prefix+"/")
	}
	return path == pattern
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
		case "bypass_paths":
			m.BypassPaths = d.RemainingArgs()
			if len(m.BypassPaths) == 0 {
				return d.ArgErr()
			}
		case "bypass_query":
			m.BypassQuery = d.RemainingArgs()
			if len(m.BypassQuery) == 0 {
				return d.ArgErr()
			}
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
