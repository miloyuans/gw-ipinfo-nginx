package model

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

func CanonicalSnapshotFingerprint(hosts []SnapshotHost) string {
	if len(hosts) == 0 {
		return ""
	}
	parts := make([]string, 0, len(hosts))
	for _, host := range hosts {
		fields := []string{
			host.Host,
			host.Source,
			host.BackendService,
			host.BackendHost,
			host.IPEnrichmentMode,
			fmt.Sprintf("%t", host.SecurityChecksEnabled),
			fmt.Sprintf("%t", host.Probe.Enabled),
		}
		if host.Probe.DirectRedirectEnabled {
			fields = append(fields, "direct_redirect_enabled=true")
		}
		fields = append(fields,
			host.Probe.Mode,
			host.Probe.URL,
			strings.Join(host.Probe.HTMLPaths, ","),
			strings.Join(host.Probe.JSPaths, ","),
			host.Probe.LinkURL,
			strings.Join(host.Probe.RedirectURLs, ","),
			strings.Join(host.Probe.Patterns, ","),
			fmt.Sprint(host.Probe.UnhealthyStatusCodes),
			host.Probe.Interval.String(),
			host.Probe.Timeout.String(),
			fmt.Sprint(host.Probe.HealthyThreshold),
			fmt.Sprint(host.Probe.UnhealthyThreshold),
			host.Probe.MinSwitchInterval.String(),
		)
		parts = append(parts, strings.Join(fields, "|"))
	}
	sort.Strings(parts)
	sum := sha1.Sum([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:])
}
