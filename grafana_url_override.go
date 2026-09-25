package mcpgrafana

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

type grafanaOverrideKey struct{}

// ParseGrafanaURLOverrides validates a comma-separated base-URL allowlist.
// Entries match exactly, except that an entry whose host starts with "*."
// (for example https://*.grafana.example.com) matches any single DNS label in
// that position; scheme, port, and path must still match exactly.
// An empty list leaves targets unrestricted when overrides are enabled.
func ParseGrafanaURLOverrides(raw string) ([]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	allowed := make([]string, 0, len(parts))
	for _, part := range parts {
		candidate := strings.TrimRight(strings.TrimSpace(part), "/")
		if err := validateOverrideAllowlistEntry(candidate); err != nil {
			return nil, fmt.Errorf("invalid Grafana URL override allowlist entry: %w", err)
		}
		allowed = append(allowed, candidate)
	}
	return allowed, nil
}

// wildcardHostPrefix marks an allowlist entry whose leftmost host label is a
// wildcard for exactly one DNS label.
const wildcardHostPrefix = "*."

// sharedHostingDomains serve many tenants' Grafana instances (or other
// services) from subdomains of one domain. A wildcard on or under any of them
// would let callers reach other customers' instances, so those must be listed
// exactly. The list cannot be complete; operators should only use wildcards on
// domains they control.
var sharedHostingDomains = []string{
	"grafana.net",          // Grafana Cloud stacks and service endpoints
	"grafana-dev.net",      // Grafana Labs internal environments
	"grafana-ops.net",      // Grafana Labs internal environments
	"grafana.azure.com",    // Azure Managed Grafana
	"grafana.aliyuncs.com", // Alibaba Cloud Managed Service for Grafana
	"amazonaws.com",        // Amazon Managed Grafana and other shared AWS hostnames
	"aivencloud.com",       // Aiven for Grafana and other Aiven services
}

// sharedHostingDomain returns the entry of sharedHostingDomains that host is
// equal to or under, or "" if there is none. host must be lower case.
func sharedHostingDomain(host string) string {
	for _, d := range sharedHostingDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return d
		}
	}
	return ""
}

func validateOverrideAllowlistEntry(raw string) error {
	u, err := url.Parse(raw)
	if err == nil && strings.HasPrefix(u.Host, wildcardHostPrefix) {
		suffix := strings.TrimPrefix(u.Hostname(), wildcardHostPrefix)
		// A numeric last label would let the pattern match IPv4 addresses
		// (*.1.2.3 matching 9.1.2.3).
		tld := suffix[strings.LastIndex(suffix, ".")+1:]
		if !isDNSName(suffix) || !strings.Contains(suffix, ".") || strings.Trim(tld, "0123456789") == "" {
			return fmt.Errorf("wildcard entry must be *.<domain> with at least two domain labels and a non-numeric top-level label")
		}
		lower := strings.ToLower(suffix)
		if d := sharedHostingDomain(lower); d != "" {
			return fmt.Errorf("wildcard entries are not allowed under the shared hosting domain %s; list each instance URL exactly", d)
		}
		// A wildcard directly on a public suffix (co.uk, github.io, ...) would
		// match every registrant under it.
		if ps, _ := publicsuffix.PublicSuffix(lower); ps == lower {
			return fmt.Errorf("wildcard entries are not allowed directly on the public suffix %s", lower)
		}
		// Validate the rest of the entry with a concrete label in place of the
		// wildcard; validateOverrideURL rejects "*" in hosts.
		u.Host = "wildcard" + strings.TrimPrefix(u.Host, "*")
		raw = u.String()
	}
	return validateOverrideURL(raw)
}

func validateOverrideURL(raw string) error {
	if err := ValidateGrafanaURL(raw); err != nil {
		return err
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery {
		return fmt.Errorf("URL must be an absolute HTTP(S) base URL without query or fragment")
	}
	if _, err := url.Parse("http://" + u.Host); err != nil {
		return fmt.Errorf("invalid host: %w", err)
	}
	if strings.Contains(u.Host, "*") {
		return fmt.Errorf("host must not contain wildcards")
	}
	if !canonicalGrafanaOverridePath(u.Path) {
		return fmt.Errorf("URL path must not contain dot segments, repeated separators, backslashes, or percent signs")
	}
	return nil
}

// Reject path forms that a downstream proxy might normalize or decode into a
// different route after the base-path check. u.Path is already URL-decoded once;
// a percent sign there could introduce dot segments on a second decode.
func canonicalGrafanaOverridePath(p string) bool {
	if strings.ContainsAny(p, `\%`) || strings.Contains(p, "//") {
		return false
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// isDNSLabel reports whether s is a single LDH hostname label.
func isDNSLabel(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func isDNSName(s string) bool {
	for _, label := range strings.Split(s, ".") {
		if !isDNSLabel(label) {
			return false
		}
	}
	return true
}

// wildcardGrafanaURL is an allowlist entry of the form
// scheme://*.suffix[:port][/path].
type wildcardGrafanaURL struct {
	scheme, suffix, port, path string
}

// grafanaURLAllowlist holds exact entries and single-label wildcard entries.
type grafanaURLAllowlist struct {
	exact    map[string]struct{}
	wildcard []wildcardGrafanaURL
}

// newGrafanaURLAllowlist expects entries already validated by
// ParseGrafanaURLOverrides.
func newGrafanaURLAllowlist(allowed []string) grafanaURLAllowlist {
	l := grafanaURLAllowlist{exact: make(map[string]struct{}, len(allowed))}
	for _, raw := range allowed {
		u, err := url.Parse(raw)
		if err == nil && strings.HasPrefix(u.Host, wildcardHostPrefix) {
			l.wildcard = append(l.wildcard, wildcardGrafanaURL{
				scheme: u.Scheme,
				suffix: "." + strings.ToLower(strings.TrimPrefix(u.Hostname(), wildcardHostPrefix)),
				port:   u.Port(),
				path:   u.Path,
			})
			continue
		}
		l.exact[raw] = struct{}{}
	}
	return l
}

func (l grafanaURLAllowlist) empty() bool {
	return len(l.exact) == 0 && len(l.wildcard) == 0
}

// allows expects raw to have passed validateOverrideURL. A wildcard matches
// exactly one label, so *.example.com matches foo.example.com but neither
// example.com nor foo.bar.example.com.
func (l grafanaURLAllowlist) allows(raw string) bool {
	if _, ok := l.exact[raw]; ok {
		return true
	}
	if len(l.wildcard) == 0 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, w := range l.wildcard {
		if u.Scheme != w.scheme || u.Port() != w.port || u.Path != w.path {
			continue
		}
		label, ok := strings.CutSuffix(host, w.suffix)
		if ok && isDNSLabel(label) {
			return true
		}
	}
	return false
}

// GrafanaURLOverrideMiddleware authorizes request-selected URLs before any
// clients are created. A caller must supply its own Grafana service account
// token. When enabled and allowed is empty, callers may select any valid
// HTTP(S) URL; operators must restrict access to trusted callers.
// The selected URL is passed through a private context key so header-only
// calls to the extractors cannot enable it.
func GrafanaURLOverrideMiddleware(enabled bool, allowed []string, next http.Handler) http.Handler {
	allowlist := newGrafanaURLAllowlist(allowed)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		values := r.Header.Values(grafanaURLHeader)
		if len(values) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		if len(values) != 1 || values[0] == "" {
			http.Error(w, "invalid X-Grafana-URL header", http.StatusBadRequest)
			return
		}
		if !enabled {
			http.Error(w, "X-Grafana-URL is disabled; set GRAFANA_ALLOW_URL_OVERRIDE=true", http.StatusForbidden)
			return
		}
		raw := strings.TrimRight(values[0], "/")
		if err := validateOverrideURL(raw); err != nil {
			http.Error(w, "invalid X-Grafana-URL header", http.StatusBadRequest)
			return
		}
		if !allowlist.empty() && !allowlist.allows(raw) {
			http.Error(w, "X-Grafana-URL is not allowlisted", http.StatusForbidden)
			return
		}
		if apiKeyFromHeaders(r) == "" {
			http.Error(w, "X-Grafana-URL requires X-Grafana-Service-Account-Token or X-Grafana-API-Key on this request", http.StatusBadRequest)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), grafanaOverrideKey{}, raw))
		next.ServeHTTP(w, r)
	})
}

// grafanaTargetTransport prevents redirects and other secondary requests from
// escaping the selected Grafana base URL, including through auth transports
// that would otherwise reattach credentials on a redirect.
type grafanaTargetTransport struct {
	baseURL string
	next    http.RoundTripper
}

func (t *grafanaTargetTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base, err := url.Parse(t.baseURL)
	if err != nil {
		return nil, err
	}
	u := req.URL
	if u.Scheme != base.Scheme || !strings.EqualFold(u.Host, base.Host) ||
		(req.Host != "" && !strings.EqualFold(req.Host, base.Host)) ||
		(base.Path != "" && (!canonicalGrafanaOverridePath(u.Path) ||
			(u.Path != base.Path && !strings.HasPrefix(u.Path, strings.TrimRight(base.Path, "/")+"/")))) {
		return nil, fmt.Errorf("grafana URL override blocked request outside selected target")
	}
	return t.next.RoundTrip(req)
}
