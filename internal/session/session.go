// Package session gates requests behind an OIDC login: it validates the
// session cookies, renews them with a refresh token, redirects to log in, and
// completes the login at the callback.
package session

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pdeslaur/caddy-pocketid/internal/issuer"
	"github.com/pdeslaur/caddy-pocketid/internal/state"
	"go.uber.org/zap"
)

const (
	// TokenCookie holds the id_token.
	TokenCookie = "pocketid_token"
	// RefreshCookie holds the refresh token.
	RefreshCookie = "pocketid_refresh"
	// RefreshCookieMaxAge matches PocketID's default refresh token lifetime.
	RefreshCookieMaxAge = 30 * 24 * time.Hour
	// pkceCookiePrefix is followed by the state nonce, giving each login flow
	// its own verifier cookie.
	pkceCookiePrefix = "pocketid_pkce_"
)

// ErrIssuerUnavailable is returned, wrapped, when the issuer can't be
// discovered.
var ErrIssuerUnavailable = errors.New("OIDC issuer unavailable")

// Config configures a Manager.
type Config struct {
	Issuer       string
	Credentials  issuer.Credentials
	CallbackPath string
	// CookieDomain scopes the session cookies to a domain and its subdomains;
	// empty scopes them to the request's host.
	CookieDomain string
	// Prompt is sent as the prompt parameter of every authorization request.
	Prompt string
	// Refresh stores the refresh token and renews the session with it once
	// the id_token has expired or its cookie is gone, without a redirect.
	Refresh bool
	Logger  *zap.Logger
}

// Manager gates requests behind an OIDC login. Valid sessions are identified
// by an id_token stored in a cookie.
type Manager struct {
	cfg    Config
	issuer *issuer.Provider
	// stateKey signs the OAuth2 state: the client secret, or a random key
	// without one, so a restart fails only the logins in flight.
	stateKey string
	logger   *zap.Logger
}

// New returns a Manager for cfg. The issuer is discovered on first use.
func New(cfg Config) (*Manager, error) {
	m := &Manager{
		cfg:      cfg,
		issuer:   issuer.New(cfg.Issuer),
		stateKey: cfg.Credentials.Secret,
		logger:   cfg.Logger,
	}
	if m.stateKey == "" {
		key, err := state.NewNonce()
		if err != nil {
			return nil, fmt.Errorf("generating state key: %w", err)
		}
		m.stateKey = key
	}
	if m.logger == nil {
		m.logger = zap.NewNop()
	}
	return m, nil
}

// Next serves an authenticated request with the claims of its id_token.
type Next func(w http.ResponseWriter, r *http.Request, claims map[string]any) error

// Handle completes the login at the callback path, and otherwise calls next
// when the request has a session or redirects to log in when it hasn't. It
// returns next's error as is.
func (m *Manager) Handle(w http.ResponseWriter, r *http.Request, next Next) error {
	if _, err := m.issuer.Discover(r.Context()); err != nil {
		return fmt.Errorf("%w: %w", ErrIssuerUnavailable, err)
	}

	if r.URL.Path == m.cfg.CallbackPath {
		m.callback(w, r)
		return nil
	}

	if claims, ok := m.authenticate(w, r); ok {
		return next(w, r, claims)
	}

	return m.redirectToLogin(w, r)
}

// authenticate returns the claims of the request's id_token or, with
// Refresh, of the one its refresh token renews.
func (m *Manager) authenticate(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	if cookie, err := r.Cookie(TokenCookie); err == nil {
		claims, err := m.issuer.ValidateToken(r.Context(), cookie.Value, m.cfg.Credentials.ClientID)
		if err == nil {
			return claims, true
		}
		m.logger.Debug("rejecting token cookie", zap.Error(err))
	}

	if m.cfg.Refresh {
		return m.refresh(w, r)
	}
	return nil, false
}

// refresh renews the session from the refresh token cookie, setting both
// cookies again, since PocketID rotates the refresh token. A rejected refresh
// token is cleared, so the next request doesn't try it again.
func (m *Manager) refresh(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	cookie, err := r.Cookie(RefreshCookie)
	if err != nil {
		return nil, false
	}
	t, err := m.issuer.Refresh(r.Context(), cookie.Value, m.cfg.Credentials)
	if errors.Is(err, issuer.ErrClientAssertion) {
		m.logger.Error("refresh failed", zap.Error(err))
		return nil, false
	}
	if err != nil {
		m.logger.Info("refresh failed", zap.Error(err))
		m.clearRefreshCookie(w)
		return nil, false
	}
	claims, err := m.issuer.ValidateToken(r.Context(), t.IDToken, m.cfg.Credentials.ClientID)
	if err != nil {
		m.logger.Error("refreshed id_token validation failed", zap.Error(err))
		m.clearRefreshCookie(w)
		return nil, false
	}
	if t.RefreshToken == "" {
		t.RefreshToken = cookie.Value
	}
	m.setCookies(w, r, t)
	return claims, true
}

func (m *Manager) callback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	stateParam := r.URL.Query().Get("state")

	if errParam := r.URL.Query().Get("error"); errParam != "" {
		m.logger.Warn("auth error from provider", zap.String("error", errParam),
			zap.String("description", r.URL.Query().Get("error_description")))
		http.Error(w, "authentication failed", http.StatusUnauthorized)
		return
	}

	payload, err := state.Verify(stateParam, m.stateKey)
	if err != nil {
		m.logger.Warn("invalid state in callback", zap.Error(err))
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	verifierCookie, err := r.Cookie(pkceCookiePrefix + payload.Nonce)
	if err != nil {
		http.Error(w, "missing pkce cookie", http.StatusBadRequest)
		return
	}

	t, err := m.issuer.ExchangeCode(r.Context(), code, verifierCookie.Value, m.callbackURI(r), m.cfg.Credentials)
	if errors.Is(err, issuer.ErrClientAssertion) {
		m.logger.Error("token exchange failed", zap.Error(err))
		http.Error(w, "client assertion unavailable", http.StatusBadGateway)
		return
	}
	if err != nil {
		m.logger.Error("token exchange failed", zap.Error(err))
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	if _, err := m.issuer.ValidateToken(r.Context(), t.IDToken, m.cfg.Credentials.ClientID); err != nil {
		m.logger.Error("id_token validation failed", zap.Error(err))
		http.Error(w, "invalid id_token", http.StatusBadGateway)
		return
	}

	m.setCookies(w, r, t)

	http.SetCookie(w, &http.Cookie{
		Name:   verifierCookie.Name,
		Value:  "",
		Path:   m.cfg.CallbackPath,
		MaxAge: -1,
	})

	http.Redirect(w, r, payload.ReturnURL, http.StatusFound)
}

func (m *Manager) redirectToLogin(w http.ResponseWriter, r *http.Request) error {
	verifier, challenge, err := issuer.GeneratePKCE()
	if err != nil {
		return fmt.Errorf("generating PKCE: %w", err)
	}
	nonce, err := state.NewNonce()
	if err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}

	st := state.Encode(nonce, r.URL.RequestURI(), m.stateKey)
	authURL, err := m.issuer.AuthURL(r.Context(), m.cfg.Credentials.ClientID, m.callbackURI(r), st, challenge, m.cfg.Prompt)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrIssuerUnavailable, err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     pkceCookiePrefix + nonce,
		Value:    verifier,
		Path:     m.cfg.CallbackPath,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   300,
	})

	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

// setCookies stores the id_token and, with Refresh, the refresh token.
func (m *Manager) setCookies(w http.ResponseWriter, r *http.Request, t issuer.Tokens) {
	http.SetCookie(w, &http.Cookie{
		Name:     TokenCookie,
		Value:    t.IDToken,
		Domain:   m.cookieDomain(),
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
	if !m.cfg.Refresh || t.RefreshToken == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookie,
		Value:    t.RefreshToken,
		Domain:   m.cookieDomain(),
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(RefreshCookieMaxAge.Seconds()),
	})
}

func (m *Manager) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   RefreshCookie,
		Value:  "",
		Domain: m.cookieDomain(),
		Path:   "/",
		MaxAge: -1,
	})
}

func (m *Manager) cookieDomain() string {
	if m.cfg.CookieDomain == "" {
		return ""
	}
	return "." + m.cfg.CookieDomain
}

func (m *Manager) callbackURI(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + m.cfg.CallbackPath
}

// StripCookies removes the session cookies from the Cookie headers, so the
// backend never sees the tokens, leaving the others as they were sent.
func StripCookies(h http.Header) {
	var kept []string
	for _, line := range h.Values("Cookie") {
		var parts []string
		for part := range strings.SplitSeq(line, ";") {
			name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if name == TokenCookie || name == RefreshCookie {
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
