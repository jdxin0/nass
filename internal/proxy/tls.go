package proxy

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

// TLSConfig builds a sensible TLS config from a cert/key pair on disk.
// The returned *tls.Config supports TLS 1.2+ with modern ciphers; SNI
// is handled by the cert itself (a wildcard cert covering all subdomains
// is the common nass-simple deployment).
func TLSConfig(certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS keypair: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// Let the runtime pick the cipher suites; Go's defaults are aligned
		// with Mozilla's intermediate compatibility profile.
		NextProtos: []string{"h2", "http/1.1"},
	}, nil
}

// HTTPSServer wraps handler in an *http.Server with the given TLS config and
// reasonable timeouts. The server is *not* started; the caller invokes
// ListenAndServeTLS("", "") (cert is already in TLSConfig).
func HTTPSServer(addr string, handler http.Handler, tlsConf *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         tlsConf,
		ReadHeaderTimeout: 10 * time.Second,
		// No ReadTimeout/WriteTimeout: long-lived websocket connections
		// (jellyfin, immich) and large uploads (nextcloud) need them off.
	}
}

// HTTPRedirectServer returns an *http.Server that 301-redirects every request
// to https on the same host+path. Used to handle :80 requests so users can
// type bare hostnames.
func HTTPRedirectServer(addr string) *http.Server {
	return &http.Server{
		Addr:              addr,
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + stripPort(r.Host) + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}),
	}
}
