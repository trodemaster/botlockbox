package proxy

import (
	"crypto/tls"
	"net/http"
)

// NewVerifyingTransport returns an http.Transport that always verifies
// upstream TLS certificates, defeating DNS rebinding attacks.
func NewVerifyingTransport() *http.Transport {
	return &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS12,
		},
		ForceAttemptHTTP2: true,
	}
}