package matcher

import (
	"net/http"
	"strings"

	"github.com/trodemaster/botlockbox/internal/config"
)

// Matches returns true if the request matches the given match criteria.
func Matches(req *http.Request, match config.Match) bool {
	host := req.URL.Hostname()
	hostMatched := false
	for _, pattern := range match.Hosts {
		if HostMatches(host, pattern) {
			hostMatched = true
			break
		}
	}
	if !hostMatched {
		return false
	}
	if len(match.PathPrefixes) == 0 {
		return true
	}
	for _, prefix := range match.PathPrefixes {
		if strings.HasPrefix(req.URL.Path, prefix) {
			return true
		}
	}
	return false
}

// HostMatches checks if host matches a pattern.
// Supports exact matches and wildcard prefix (*.example.com).
func HostMatches(host, pattern string) bool {
	if host == pattern {
		return true
	}
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]
		return strings.HasSuffix(host, suffix)
	}
	return false
}