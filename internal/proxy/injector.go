package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"text/template"

	"github.com/awnumar/memguard"
	"github.com/elazarl/goproxy"
	"github.com/trodemaster/botlockbox/internal/config"
	"github.com/trodemaster/botlockbox/internal/matcher"
	"github.com/trodemaster/botlockbox/internal/secrets"
)

var secretNameRe = regexp.MustCompile(`\{\{secrets\.(\w+)\}\}`)

// Injector holds the rules, sealed envelope, and locked secrets.
type Injector struct {
	rules         []config.Rule
	envelope      *secrets.SealedEnvelope
	lockedSecrets map[string]*memguard.Enclave
}

// Handle is the goproxy request handler.
func (inj *Injector) Handle(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	for _, rule := range inj.rules {
		if matcher.Matches(req, rule.Match) {
			if resp := inj.apply(req, rule); resp != nil {
				return req, resp
			}
			return req, nil
		}
	}
	return req, nil
}

func (inj *Injector) apply(req *http.Request, rule config.Rule) *http.Response {
	host := req.URL.Hostname()

	for header, tmplStr := range rule.Inject.Headers {
		secretName, err := extractSingleSecretName(tmplStr)
		if err != nil {
			LogAuditEvent(req, rule.Name, "unknown", false, true, err.Error())
			return goproxy.NewResponse(req, goproxy.ContentTypeText, 503, "botlockbox: template error")
		}
		if err := inj.assertHostAllowed(secretName, host); err != nil {
			LogAuditEvent(req, rule.Name, secretName, false, true, err.Error())
			return goproxy.NewResponse(req, goproxy.ContentTypeText, 503,
				"botlockbox: security block -- credential injection refused")
		}
		value, err := inj.getSecret(secretName)
		if err != nil {
			LogAuditEvent(req, rule.Name, secretName, false, true, err.Error())
			return goproxy.NewResponse(req, goproxy.ContentTypeText, 503, "botlockbox: secret unavailable")
		}
		rendered, renderErr := renderTemplate(tmplStr, secretName, value)
		memguard.ScrambleBytes([]byte(value))
		if renderErr != nil {
			LogAuditEvent(req, rule.Name, secretName, false, true, renderErr.Error())
			return goproxy.NewResponse(req, goproxy.ContentTypeText, 503, "botlockbox: template render error")
		}
		req.Header.Set(header, rendered)
		LogAuditEvent(req, rule.Name, secretName, true, false, "")
	}

	if len(rule.Inject.QueryParams) > 0 {
		q := req.URL.Query()
		for param, tmplStr := range rule.Inject.QueryParams {
			secretName, err := extractSingleSecretName(tmplStr)
			if err != nil {
				LogAuditEvent(req, rule.Name, "unknown", false, true, err.Error())
				return goproxy.NewResponse(req, goproxy.ContentTypeText, 503, "botlockbox: template error")
			}
			if err := inj.assertHostAllowed(secretName, host); err != nil {
				LogAuditEvent(req, rule.Name, secretName, false, true, err.Error())
				return goproxy.NewResponse(req, goproxy.ContentTypeText, 503,
					"botlockbox: security block -- credential injection refused")
			}
			value, err := inj.getSecret(secretName)
			if err != nil {
				LogAuditEvent(req, rule.Name, secretName, false, true, err.Error())
				return goproxy.NewResponse(req, goproxy.ContentTypeText, 503, "botlockbox: secret unavailable")
			}
			rendered, renderErr := renderTemplate(tmplStr, secretName, value)
			memguard.ScrambleBytes([]byte(value))
			if renderErr != nil {
				LogAuditEvent(req, rule.Name, secretName, false, true, renderErr.Error())
				return goproxy.NewResponse(req, goproxy.ContentTypeText, 503, "botlockbox: template render error")
			}
			q.Set(param, rendered)
			LogAuditEvent(req, rule.Name, secretName, true, false, "")
		}
		req.URL.RawQuery = q.Encode()
	}

	return nil
}

func (inj *Injector) assertHostAllowed(secretName, host string) error {
	allowedHosts, ok := inj.envelope.AllowedHosts[secretName]
	if !ok {
		return fmt.Errorf("secret %q has no allowlist in sealed envelope", secretName)
	}
	for _, pattern := range allowedHosts {
		if matcher.HostMatches(host, pattern) {
			return nil
		}
	}
	return fmt.Errorf("secret %q may not be sent to host %q -- sealed allowlist: %v",
		secretName, host, allowedHosts)
}

func (inj *Injector) getSecret(name string) (string, error) {
	enc, ok := inj.lockedSecrets[name]
	if !ok {
		return "", fmt.Errorf("secret %q not found in locked secrets", name)
	}
	buf, err := enc.Open()
	if err != nil {
		return "", fmt.Errorf("opening memguard enclave for %q: %w", name, err)
	}
	val := string(buf.Bytes())
	buf.Destroy()
	return val, nil
}

func extractSingleSecretName(tmpl string) (string, error) {
	matches := secretNameRe.FindAllStringSubmatch(tmpl, -1)
	if len(matches) == 0 {
		return "", fmt.Errorf("no {{secrets.NAME}} reference found in template %q", tmpl)
	}
	return matches[0][1], nil
}

func renderTemplate(tmplStr, secretName, secretValue string) (string, error) {
	result := strings.ReplaceAll(tmplStr, "{{secrets."+secretName+"}}", secretValue)
	if strings.Contains(result, "{{") {
		t, err := template.New(" ").Parse(result)
		if err != nil {
			return "", err
		}
		var buf bytes.Buffer
		if err := t.Execute(&buf, nil); err != nil {
			return "", err
		}
		return buf.String(), nil
	}
	return result, nil
}