package proxy

import (
	"fmt"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/trodemaster/botlockbox/internal/config"
	"github.com/trodemaster/botlockbox/internal/secrets"
)

// New creates a goproxy server configured to inject credentials per the rules.
// It returns the HTTP handler, the Injector (for live secret rotation via SwapSecrets), and any error.
func New(cfg *config.Config, result *secrets.UnsealResult) (http.Handler, *Injector, error) {
	ephemeralCA, caCertPEM, err := GenerateEphemeralCA()
	if err != nil {
		return nil, nil, fmt.Errorf("generating ephemeral CA: %w", err)
	}

	p := goproxy.NewProxyHttpServer()
	p.Verbose = cfg.Verbose
	p.Tr = NewVerifyingTransport()

	mitmConfig := goproxy.ConnectAction{
		Action:    goproxy.ConnectMitm,
		TLSConfig: goproxy.TLSConfigFromCA(ephemeralCA),
	}
	alwaysMitm := goproxy.FuncHttpsHandler(func(host string, ctx *goproxy.ProxyCtx) (*goproxy.ConnectAction, string) {
		return &mitmConfig, host
	})
	p.OnRequest().HandleConnect(alwaysMitm)

	injector := &Injector{
		rules:         cfg.Rules,
		envelope:      result.Envelope,
		lockedSecrets: result.LockedSecrets,
		CACertPEM:     caCertPEM,
	}
	p.OnRequest().DoFunc(injector.Handle)
	InstallResponseScrubber(p)

	return p, injector, nil
}