package proxy_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jdxin0/nass/internal/proxy"
)

func TestReverseProxyStripsSessionCookie(t *testing.T) {
	var gotCookies []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookies = r.Header.Values("Cookie")
	}))
	defer backend.Close()

	router := proxy.New()
	router.AddRoute("app.example.com", proxy.NewReverseProxy(proxy.BackendOptions{Backend: mustURL(t, backend.URL)}))
	front := httptest.NewServer(router)
	defer front.Close()

	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"middle", []string{"a=1; " + proxy.SessionCookieName + "=secret; b=2"}, []string{"a=1; b=2"}},
		{"first", []string{proxy.SessionCookieName + "=secret; b=2"}, []string{"b=2"}},
		{"only", []string{proxy.SessionCookieName + "=secret"}, nil},
		// HTTP/2 clients send one Cookie header per cookie.
		{"split headers", []string{"a=1", proxy.SessionCookieName + "=secret", "b=\"quoted value\""}, []string{"a=1", "b=\"quoted value\""}},
		{"similar name kept", []string{proxy.SessionCookieName + "_other=keep"}, []string{proxy.SessionCookieName + "_other=keep"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotCookies = nil
			req, _ := http.NewRequest("GET", front.URL+"/", nil)
			req.Host = "app.example.com"
			for _, v := range c.in {
				req.Header.Add("Cookie", v)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if strings.Join(gotCookies, "|") != strings.Join(c.want, "|") {
				t.Fatalf("backend saw Cookie %q, want %q", gotCookies, c.want)
			}
		})
	}
}
