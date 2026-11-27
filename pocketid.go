package pocketid

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/pdeslaur/caddy-pocketid/internal/issuer"
	"github.com/pdeslaur/caddy-pocketid/internal/session"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(Middleware{})
	httpcaddyfile.RegisterHandlerDirective("pocketid_auth", parseCaddyfile)
	httpcaddyfile.RegisterDirectiveOrder("pocketid_auth", httpcaddyfile.Before, "basicauth")
}

// Middleware gates requests behind PocketID OIDC authentication, and injects
// headers into the authenticated requests it passes on.
type Middleware struct {
	Issuer       string `json:"issuer"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	// ClientAssertion authenticates the client without a secret: "spiffe"
	// sends a JWT-SVID from the SPIFFE Workload API, for the issuer as its
	// audience.
	ClientAssertion string `json:"client_assertion,omitempty"`
	CookieDomain    string `json:"cookie_domain,omitempty"`
	CallbackPath    string `json:"callback_path,omitempty"`
	// LogoutPath, when set, signs the user out: it clears the session, and
	// ends PocketID's own, which returns the browser to PostLogoutRedirect.
	LogoutPath         string        `json:"logout_path,omitempty"`
	PostLogoutRedirect string        `json:"post_logout_redirect,omitempty"`
	Prompt             string        `json:"prompt,omitempty"`
	Refresh            bool          `json:"refresh,omitempty"`
	Headers            []HeaderPair  `json:"headers,omitempty"`
	ClaimHeaders       []ClaimHeader `json:"claim_headers,omitempty"`

	session *session.Manager
	logger  *zap.Logger
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
	if m.LogoutPath != "" && m.PostLogoutRedirect == "" {
		m.PostLogoutRedirect = "/"
	}

	m.logger = ctx.Logger()
	s, err := session.New(session.Config{
		Issuer: m.Issuer,
		Credentials: issuer.Credentials{
			ClientID: m.ClientID,
			Secret:   m.ClientSecret,
			SPIFFE:   m.ClientAssertion == "spiffe",
		},
		CallbackPath:       m.CallbackPath,
		LogoutPath:         m.LogoutPath,
		PostLogoutRedirect: m.PostLogoutRedirect,
		CookieDomain:       m.CookieDomain,
		Prompt:             m.Prompt,
		Refresh:            m.Refresh,
		Logger:             m.logger,
	})
	if err != nil {
		return err
	}
	m.session = s
	return nil
}

func (m *Middleware) Validate() error {
	if _, err := url.ParseRequestURI(m.Issuer); err != nil {
		return fmt.Errorf("invalid issuer URL: %w", err)
	}
	if !strings.HasPrefix(m.CallbackPath, "/") {
		return fmt.Errorf("callback_path must begin with /")
	}
	if m.LogoutPath != "" && !strings.HasPrefix(m.LogoutPath, "/") {
		return fmt.Errorf("logout_path must begin with /")
	}
	if m.LogoutPath != "" && m.LogoutPath == m.CallbackPath {
		return fmt.Errorf("logout_path and callback_path must differ")
	}
	if m.PostLogoutRedirect != "" && (m.LogoutPath == "" || !strings.HasPrefix(m.PostLogoutRedirect, "/")) {
		return fmt.Errorf("post_logout_redirect must begin with / and needs logout_path")
	}
	return nil
}

func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	err := m.session.Handle(w, r, func(w http.ResponseWriter, r *http.Request, claims map[string]any) error {
		return next.ServeHTTP(w, m.injectHeaders(r, claims))
	})
	if errors.Is(err, session.ErrIssuerUnavailable) {
		m.logger.Error("OIDC provider unavailable", zap.Error(err))
		return caddyhttp.Error(http.StatusBadGateway, err)
	}
	return err
}

// injectHeaders clones the request, removes the session cookies, and sets
// static and claim-derived headers. Claim headers are always removed from the
// incoming request first, so a client cannot supply its own value when the
// claim is absent from the token.
func (m *Middleware) injectHeaders(r *http.Request, claims map[string]any) *http.Request {
	r = r.Clone(r.Context())
	session.StripCookies(r.Header)
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
		case "logout_path":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.LogoutPath = d.Val()
		case "post_logout_redirect":
			if !d.NextArg() {
				return d.ArgErr()
			}
			m.PostLogoutRedirect = d.Val()
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
