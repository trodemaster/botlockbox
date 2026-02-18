package proxy

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
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
	mu            sync.RWMutex
	rules         []config.Rule
	envelope      *secrets.SealedEnvelope
	lockedSecrets map[string]*memguard.Enclave

	// CACertPEM is the PEM-encoded public certificate of the ephemeral MITM CA.
	// Safe to write to disk or share with clients that need to trust the proxy.
	CACertPEM []byte
}

// Handle is the goproxy request handler.
func (inj *Injector) Handle(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	inj.mu.RLock()
	defer inj.mu.RUnlock()
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

// SwapSecrets atomically replaces the live secrets after validating the new envelope.
// Validation and AllowedHosts equality checks are performed before acquiring the write lock.
// Old enclaves are destroyed after the swap. Returns an error without modifying state on failure.
func (inj *Injector) SwapSecrets(newResult *secrets.UnsealResult, configAllowedHosts map[string][]string) error {
	if err := newResult.Envelope.Validate(configAllowedHosts); err != nil {
		return fmt.Errorf("reload validation failed: %w", err)
	}

	inj.mu.RLock()
	oldAllowedHosts := inj.envelope.AllowedHosts
	inj.mu.RUnlock()

	if err := allowedHostsEqual(oldAllowedHosts, newResult.Envelope.AllowedHosts); err != nil {
		return fmt.Errorf("reload rejected (AllowedHosts changed — re-seal required): %w", err)
	}

	inj.mu.Lock()
	old := inj.lockedSecrets
	inj.envelope = newResult.Envelope
	inj.lockedSecrets = newResult.LockedSecrets
	inj.mu.Unlock()

	for _, enc := range old {
		if buf, err := enc.Open(); err == nil {
			buf.Destroy()
		}
	}
	return nil
}

// allowedHostsEqual returns nil iff old and new contain identical key/value sets.
func allowedHostsEqual(old, new map[string][]string) error {
	if len(old) != len(new) {
		return fmt.Errorf("key count changed: %d → %d", len(old), len(new))
	}
	for secretName, oldHosts := range old {
		newHosts, ok := new[secretName]
		if !ok {
			return fmt.Errorf("secret %q removed from AllowedHosts", secretName)
		}
		if len(oldHosts) != len(newHosts) {
			return fmt.Errorf("secret %q host count changed: %d → %d", secretName, len(oldHosts), len(newHosts))
		}
		newSet := make(map[string]struct{}, len(newHosts))
		for _, h := range newHosts {
			newSet[h] = struct{}{}
		}
		for _, h := range oldHosts {
			if _, ok := newSet[h]; !ok {
				return fmt.Errorf("secret %q host %q removed from AllowedHosts", secretName, h)
			}
		}
	}
	return nil
}