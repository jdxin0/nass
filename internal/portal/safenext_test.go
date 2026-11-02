package portal

import "testing"

func TestSafeNext(t *testing.T) {
	https := &Portal{BaseHost: "example.com", HTTPS: true}
	dev := &Portal{BaseHost: "example.com", HTTPS: false}
	cases := []struct {
		p    *Portal
		in   string
		want string
	}{
		{https, "", "/"},
		{https, "/", "/"},
		{https, "/portal/admin?x=1#users", "/portal/admin?x=1#users"},
		// Gated apps and the OIDC issuer send absolute next URLs on subdomains.
		{https, "https://qbittorrent.example.com/", "https://qbittorrent.example.com/"},
		{https, "https://auth.example.com/login?authRequestID=abc", "https://auth.example.com/login?authRequestID=abc"},
		{https, "https://example.com/", "https://example.com/"},
		{https, "https://Example.COM:8443/x", "https://Example.COM:8443/x"},
		{dev, "http://qbittorrent.example.com/", "http://qbittorrent.example.com/"},
		// Off-site, downgraded, or browser-normalised escapes.
		{https, "http://qbittorrent.example.com/", "/"},
		{https, "https://evil.com/", "/"},
		{https, "https://example.com.evil.com/", "/"},
		{https, "https://evilexample.com/", "/"},
		{https, "https://example.com@evil.com/", "/"},
		{https, "//evil.com", "/"},
		{https, `/\evil.com`, "/"},
		{https, `https://example.com\@evil.com`, "/"},
		{https, "javascript:alert(1)", "/"},
		{https, "https:/evil.com", "/"},
		{https, "relative/path", "/"},
	}
	for _, c := range cases {
		if got := c.p.safeNext(c.in); got != c.want {
			t.Errorf("safeNext(%q) [https=%v] = %q, want %q", c.in, c.p.HTTPS, got, c.want)
		}
	}
}
