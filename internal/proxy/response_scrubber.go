package proxy

import (
	"bytes"
	"io"
	"net/http"
	"regexp"

	"github.com/elazarl/goproxy"
)

var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`ghp_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`ghs_[a-zA-Z0-9]{36}`),
	regexp.MustCompile(`sk-[a-zA-Z0-9]{48}`),
	regexp.MustCompile(`sk-proj-[a-zA-Z0-9_\-]{50,}`),
	regexp.MustCompile(`AKIA[A-Z0-9]{16}`),
	regexp.MustCompile(`(?i)"access_token"\s*:.*"[^"]+"`),
	regexp.MustCompile(`(?i)"refresh_token"\s*:.*"[^"]+"`),
	regexp.MustCompile(`(?i)"api_key"\s*:.*"[^"]+"`),
}

var redacted = []byte("[REDACTED-BY-BOTLOCKBOX]")

// InstallResponseScrubber adds a response handler that redacts known
// credential patterns from response bodies before forwarding to agents.
func InstallResponseScrubber(p *goproxy.ProxyHttpServer) {
	p.OnResponse().DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
		if resp == nil {
			return nil
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			resp.Body = io.NopCloser(bytes.NewReader(body))
			return resp
		}
		for _, re := range credentialPatterns {
			body = re.ReplaceAll(body, redacted)
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		return resp
	})
}