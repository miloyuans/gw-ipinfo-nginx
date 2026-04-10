package ipinfo

import (
	"encoding/json"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/cache"
)

func encodeLookupDetails(details LookupDetails) string {
	payload, err := json.Marshal(details)
	if err != nil {
		return ""
	}
	return string(payload)
}

func decodeLookupDetails(raw string) (LookupDetails, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return LookupDetails{}, false
	}

	var details LookupDetails
	if err := json.Unmarshal([]byte(raw), &details); err != nil {
		return LookupDetails{}, false
	}

	return details, true
}

func detailsFromEntry(entry cache.Entry) LookupDetails {
	if details, ok := decodeLookupDetails(entry.DetailsJSON); ok {
		return details
	}
	return DetailsFromContext(entry.IPContext)
}

func hasLookupDetails(entry cache.Entry) bool {
	_, ok := decodeLookupDetails(entry.DetailsJSON)
	return ok
}

func (s *LookupService) successEntryFromDetails(details LookupDetails, now time.Time) cache.Entry {
	return cache.Entry{
		IPContext:          details.ToContext(),
		DetailsJSON:        encodeLookupDetails(details),
		GeoExpiresAt:       now.Add(s.ttls.Geo),
		PrivacyExpiresAt:   now.Add(s.ttls.Privacy),
		ResProxyExpiresAt:  now.Add(s.ttls.ResidentialProxy),
		ExpiresAt:          maxTime(now.Add(s.ttls.Geo), now.Add(s.ttls.Privacy), now.Add(s.ttls.ResidentialProxy)),
		UpdatedAt:          now,
	}
}

func (s *LookupService) failureEntry(err error, now time.Time) cache.Entry {
	return cache.Entry{
		Failure:          err.Error(),
		FailureExpiresAt: now.Add(s.failureTTL),
		ExpiresAt:        now.Add(s.failureTTL),
		UpdatedAt:        now,
	}
}
