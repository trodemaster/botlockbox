package proxy

import (
	"fmt"
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/trodemaster/botlockbox/internal/config"
	"github.com/trodemaster/botlockbox/internal/secrets"
)

// New creates a goproxy server configured to inject credentials per the rules.
func New(cfg *config.Config, result *secrets.UnsealResult) (http.Handler, error) {
	ephemeralCA, err := GenerateEphemeralCA()
	if err != nil {
		return nil, fmt.Errorf("generating ephemeral CA: %w", err)
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
	}
	p.OnRequest().DoFunc(injector.Handle)
	InstallResponseScrubber(p)

	return p, nil
}