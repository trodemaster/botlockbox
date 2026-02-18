package proxy

import (
	"encoding/json"
	"log"
	"net/http"
	"time"
)

// AuditEvent records a credential injection attempt.
// Secret VALUES are never logged -- only names.
type AuditEvent struct {
	Timestamp   time.Time `json:"ts"`
	Host        string    `json:"host"`
	Method      string    `json:"method"`
	Path        string    `json:"path"`
	RuleName    string    `json:"rule"`
	SecretName  string    `json:"secret_name"`
	Injected    bool      `json:"injected"`
	Blocked     bool      `json:"blocked"`
	BlockReason string    `json:"block_reason,omitempty"`
}

// LogAuditEvent emits a structured JSON audit log line.
func LogAuditEvent(req *http.Request, ruleName, secretName string, injected, blocked bool, blockReason string) {
	evt := AuditEvent{
		Timestamp:   time.Now().UTC(),
		Host:        req.URL.Hostname(),
		Method:      req.Method,
		Path:        req.URL.Path,
		RuleName:    ruleName,
		SecretName:  secretName,
		Injected:    injected,
		Blocked:     blocked,
		BlockReason: blockReason,
	}
	b, _ := json.Marshal(evt)
	log.Printf("AUDIT %s", b)
}