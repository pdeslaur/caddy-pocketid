package session

import (
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
	"time"

	"chainguard.dev/go-oidctest/pkg/oidctest"
)

const testLogoutPath = "/auth/logout"

func withLogout(c *Config) {
	c.LogoutPath = testLogoutPath
	c.PostLogoutRedirect = "/signed-out"
}

// logoutRequest returns a request to the logout path, with Sec-Fetch-Site
// site unless it's empty, and the session cookies.
func logoutRequest(site string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://example.com"+testLogoutPath, nil)
	if site != "" {
		r.Header.Set("Sec-Fetch-Site", site)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

// checkCleared fails unless w deletes both session cookies.
func checkCleared(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	for _, name := range []string{TokenCookie, RefreshCookie} {
		if c := responseCookie(w, name); c == nil || c.MaxAge >= 0 || c.Path != "/" {
			t.Errorf("cookie %s = %v, want it deleted", name, c)
		}
	}
}

// TestLogout checks that the logout path clears the session and sends the
// browser to the issuer's end_session_endpoint, keeping its own query, with
// the id_token as the hint and the post-logout redirect on the request's
// host.
func TestLogout(t *testing.T) {
	iss := newRefreshIssuer(t)
	m := newTestManager(t, iss.URL, withRefresh, withLogout)
	idToken := iss.idToken(time.Now().Add(-time.Hour))

	for _, site := range []string{"", "same-origin", "none"} {
		t.Run("Sec-Fetch-Site="+site, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := logoutRequest(site,
				&http.Cookie{Name: TokenCookie, Value: idToken},
				&http.Cookie{Name: RefreshCookie, Value: iss.issueRefreshToken()})
			if err := m.Handle(w, r, failNext(t)); err != nil {
				t.Fatalf("Handle: %v", err)
			}
			if w.Code != http.StatusFound {
				t.Fatalf("status = %d, want 302", w.Code)
			}
			loc, err := url.Parse(w.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			if got, want := loc.Scheme+"://"+loc.Host+loc.Path, iss.URL+"/end-session"; got != want {
				t.Errorf("redirect to %s, want %s", got, want)
			}
			want := url.Values{
				"ui":                       {"1"},
				"client_id":                {"test-client"},
				"id_token_hint":            {idToken},
				"post_logout_redirect_uri": {"http://example.com/signed-out"},
			}
			if got := loc.Query(); !maps.EqualFunc(got, want, slices.Equal) {
				t.Errorf("query = %v, want %v", got, want)
			}
			checkCleared(t, w)
		})
	}
}

// TestLogoutWithoutSession checks that a logout without an id_token leaves
// the hint out, for the issuer to ask the user.
func TestLogoutWithoutSession(t *testing.T) {
	iss := newRefreshIssuer(t)
	m := newTestManager(t, iss.URL, withLogout)

	w := httptest.NewRecorder()
	if err := m.Handle(w, logoutRequest("same-origin"), failNext(t)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Query().Has("id_token_hint") {
		t.Errorf("redirect %s has an id_token_hint", loc)
	}
	checkCleared(t, w)
}

// TestLogoutWithoutEndSession checks that, against an issuer without an
// end_session_endpoint, the logout path clears the session and redirects to
// the post-logout redirect.
func TestLogoutWithoutEndSession(t *testing.T) {
	signer, issuerURL := oidctest.NewIssuer(t)
	m := newTestManager(t, issuerURL, withLogout)

	w := httptest.NewRecorder()
	r := logoutRequest("same-origin", &http.Cookie{Name: TokenCookie, Value: signedToken(t, signer, issuerURL, time.Now().Add(time.Hour))})
	if err := m.Handle(w, r, failNext(t)); err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if got, want := w.Header().Get("Location"), "http://example.com/signed-out"; w.Code != http.StatusFound || got != want {
		t.Errorf("got %d to %q, want 302 to %q", w.Code, got, want)
	}
	checkCleared(t, w)
}

// TestLogoutCrossSite checks that a logout from another site is refused,
// keeping the session.
func TestLogoutCrossSite(t *testing.T) {
	iss := newRefreshIssuer(t)
	m := newTestManager(t, iss.URL, withLogout)

	for _, site := range []string{"cross-site", "same-site"} {
		w := httptest.NewRecorder()
		r := logoutRequest(site, &http.Cookie{Name: TokenCookie, Value: iss.idToken(time.Now().Add(time.Hour))})
		if err := m.Handle(w, r, failNext(t)); err != nil {
			t.Fatalf("Handle: %v", err)
		}
		if w.Code != http.StatusForbidden {
			t.Errorf("Sec-Fetch-Site %s: status = %d, want 403", site, w.Code)
		}
		if len(w.Result().Cookies()) > 0 {
			t.Errorf("Sec-Fetch-Site %s: set cookies %v", site, w.Result().Cookies())
		}
	}
}

// TestLogoutDisabled checks that, without LogoutPath, the path is like any
// other: it needs a session.
func TestLogoutDisabled(t *testing.T) {
	iss := newRefreshIssuer(t)
	m := newTestManager(t, iss.URL)

	var reached bool
	w := httptest.NewRecorder()
	r := logoutRequest("same-origin", &http.Cookie{Name: TokenCookie, Value: iss.idToken(time.Now().Add(time.Hour))})
	err := m.Handle(w, r, func(w http.ResponseWriter, r *http.Request, claims map[string]any) error {
		reached = true
		return nil
	})
	if err != nil {
		t.Fatalf("Handle: %v", err)
	}
	if !reached || len(w.Result().Cookies()) > 0 {
		t.Errorf("backend reached = %v, cookies %v; want the request passed on as is", reached, w.Result().Cookies())
	}
}
