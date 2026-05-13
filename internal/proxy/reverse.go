package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// BackendOptions configures a single reverse-proxy route.
type BackendOptions struct {
	// Backend is the upstream URL (e.g. http://127.0.0.1:18080).
	Backend *url.URL

	// FlushInterval forces flushes to the client every N. Defaults to 100ms,
	// which is a reasonable choice for streaming responses (jellyfin, immich).
	FlushInterval time.Duration

	// MaxIdleConnsPerHost caps the upstream pool. Default 32.
	MaxIdleConnsPerHost int

	// ResponseHeaderTimeout caps how long we wait for the upstream's response
	// headers. Per-app override (Nextcloud large uploads need a long one).
	ResponseHeaderTimeout time.Duration

	// PreserveHost, when true, forwards the original Host header upstream.
	// Most apps want this (so they generate correct self-referencing URLs).
	PreserveHost bool
}

// NewReverseProxy builds an http.Handler that proxies to opts.Backend.
// Websocket upgrades are passed through transparently (httputil.ReverseProxy
// has handled this since Go 1.12). Standard X-Forwarded-* headers are set.
func NewReverseProxy(opts BackendOptions) http.Handler {
	if opts.Backend == nil {
		panic("proxy: BackendOptions.Backend is required")
	}
	if opts.FlushInterval == 0 {
		opts.FlushInterval = 100 * time.Millisecond
	}
	if opts.MaxIdleConnsPerHost == 0 {
		opts.MaxIdleConnsPerHost = 32
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   opts.MaxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
	}

	rp := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: opts.FlushInterval,
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(opts.Backend)
			if opts.PreserveHost {
				r.Out.Host = r.In.Host
			}
			// Set / preserve forwarded headers.
			r.SetXForwarded()
			if proto := scheme(r.In); proto != "" {
				r.Out.Header.Set("X-Forwarded-Proto", proto)
			}
			r.Out.Header.Set("X-Forwarded-Host", r.In.Host)
		},
	}
	return rp
}

// scheme returns the scheme nass terminated. We deliberately do NOT honour
// an inbound X-Forwarded-Proto header: nass is the front door, so the only
// trustworthy signal is whether the TCP connection used TLS. A client that
// sets X-Forwarded-Proto: https to a plain :80 listener would otherwise
// trick downstream apps into trusting an unencrypted hop.
func scheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}
