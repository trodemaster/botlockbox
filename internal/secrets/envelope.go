package secrets

import (
	"fmt"
	"time"
)

// SealedEnvelope is the structure that gets age-encrypted to disk.
// It binds each secret to the exact set of hosts it is allowed to be sent to.
type SealedEnvelope struct {
	Version      int                 `json:"version"`
	SealedAt     time.Time           `json:"sealed_at"`
	AllowedHosts map[string][]string `json:"allowed_hosts"`
	Secrets      map[string]string   `json:"secrets"`
}

// Validate checks that every secret+host in configAllowedHosts is present
// in the sealed envelope's AllowedHosts. Any mismatch returns a descriptive error.
func (e *SealedEnvelope) Validate(configAllowedHosts map[string][]string) error {
	for secretName, configHosts := range configAllowedHosts {
		sealedHosts, ok := e.AllowedHosts[secretName]
		if !ok {
			return fmt.Errorf(
				"security violation: secret %q is referenced in botlockbox.yaml but was not present at seal time -- re-seal to add new secrets",
				secretName,
			)
		}

		sealedSet := make(map[string]struct{}, len(sealedHosts))
		for _, h := range sealedHosts {
			sealedSet[h] = struct{}{}
		}

		for _, configHost := range configHosts {
			if _, allowed := sealedSet[configHost]; !allowed {
				return fmt.Errorf(
					"security violation: botlockbox.yaml attempts to use secret %q against host %q, "+
					"but that host was not committed at seal time.\n"+
					"  Sealed allowed hosts for %q: %v\n"+
					"  To add new hosts, re-run `botlockbox seal` with the updated config.",
					secretName, configHost, secretName, sealedHosts,
				)
			}
		}
	}
	return nil
}