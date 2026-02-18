package config

import (
	"fmt"
	"regexp"
)

// Config is the structure of botlockbox.yaml.
// This file contains NO secrets — only routing rules and references.
// Actual secrets are in the age-encrypted file pointed to by SecretsFile.
type Config struct {
	Listen      string `yaml:"listen"`
	SecretsFile string `yaml:"secrets_file"`
	Verbose     bool   `yaml:"verbose"`
	Rules       []Rule `yaml:"rules"`
}

// Rule binds a set of match conditions to a credential injection action.
type Rule struct {
	Name   string `yaml:"name"`
	Match  Match  `yaml:"match"`
	Inject Inject `yaml:"inject"`
}

// Match describes which requests the rule applies to.
type Match struct {
	// Hosts is a list of host patterns (exact or glob, e.g. "*.s3.amazonaws.com").
	Hosts []string `yaml:"hosts"`
	// PathPrefixes optionally restricts the rule to specific URL path prefixes.
	PathPrefixes []string `yaml:"path_prefixes,omitempty"`
}

// Inject describes what credentials to add to matching requests.
type Inject struct {
	// Headers maps header name → template string, e.g. "Authorization": "Bearer {{secrets.my_token}}"
	Headers map[string]string `yaml:"headers,omitempty"`
	// QueryParams maps query parameter name → template string.
	QueryParams map[string]string `yaml:"query_params,omitempty"`
}

// AllowedHostsFromRules derives the map[secretName][]hostGlob from the config's
// rules by walking every inject directive and extracting referenced secret names.
//
// This map is used at seal time to commit the binding, and at serve time to
// validate the live config against the sealed envelope.
func (c *Config) AllowedHostsFromRules() (map[string][]string, error) {
	result := make(map[string][]string)

	for _, rule := range c.Rules {
		secretNames, err := extractSecretNames(rule.Inject)
		if err != nil {
			return nil, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
		for _, secretName := range secretNames {
			existing := result[secretName]
			hostSet := make(map[string]struct{}, len(existing))
			for _, h := range existing {
				hostSet[h] = struct{}{}
			}
			for _, h := range rule.Match.Hosts {
				if _, seen := hostSet[h]; !seen {
					existing = append(existing, h)
					hostSet[h] = struct{}{}
				}
			}
			result[secretName] = existing
		}
	}
	return result, nil
}

// secretsTemplateRe matches {{secrets.key_name}} patterns.
var secretsTemplateRe = regexp.MustCompile(`\{\{secrets\.([a-zA-Z0-9_]+)\}\}`)

// extractSecretNames finds all secret names referenced in an Inject block.
func extractSecretNames(inject Inject) ([]string, error) {
	seen := make(map[string]struct{})
	var names []string

	collect := func(tmpl string) {
		for _, match := range secretsTemplateRe.FindAllStringSubmatch(tmpl, -1) {
			name := match[1]
			if _, ok := seen[name]; !ok {
				seen[name] = struct{}{}
				names = append(names, name)
			}
		}
	}

	for _, v := range inject.Headers {
		collect(v)
	}
	for _, v := range inject.QueryParams {
		collect(v)
	}
	return names, nil
}

