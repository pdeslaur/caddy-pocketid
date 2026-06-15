package pocketid

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMatchPath(t *testing.T) {
	cases := []struct {
		path    string
		pattern string
		want    bool
	}{
		{"/api", "/api", true},
		{"/api/", "/api", false},
		{"/api/v1", "/api", false},
		{"/api", "/api/*", true},
		{"/api/v1", "/api/*", true},
		{"/api/v1/users", "/api/*", true},
		{"/apiv1", "/api/*", false},
		{"/", "/api/*", false},
		{"/ping", "/ping", true},
		{"/ping/extra", "/ping", false},
	}
	for _, tc := range cases {
		got := matchPath(tc.path, tc.pattern)
		if got != tc.want {
			t.Errorf("matchPath(%q, %q) = %v, want %v", tc.path, tc.pattern, got, tc.want)
		}
	}
}

func TestCallbackURIScheme(t *testing.T) {
	m := &Middleware{CallbackPath: "/auth/callback"}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Host = "example.com"
	if got := m.callbackURI(r); got != "http://example.com/auth/callback" {
		t.Errorf("plain request: got %q", got)
	}

	r.TLS = &tls.ConnectionState{}
	if got := m.callbackURI(r); got != "https://example.com/auth/callback" {
		t.Errorf("TLS request: got %q", got)
	}
}
