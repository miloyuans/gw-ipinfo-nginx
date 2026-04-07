package shortcircuit

import (
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/policy"
)

const (
	DecisionAllow = "allow"
	DecisionDeny  = "deny"
)

type Record struct {
	ClientIP                string             `json:"client_ip" bson:"client_ip"`
	LastDecision            string             `json:"last_decision" bson:"last_decision"`
	LastReasonCode          string             `json:"last_reason_code" bson:"last_reason_code"`
	CountryCode             string             `json:"country_code" bson:"country_code"`
	CountryName             string             `json:"country_name" bson:"country_name"`
	Region                  string             `json:"region" bson:"region"`
	City                    string             `json:"city" bson:"city"`
	Privacy                 ipctx.PrivacyFlags `json:"privacy" bson:"privacy"`
	FirstSeenAt             time.Time          `json:"first_seen_at" bson:"first_seen_at"`
	LastSeenAt              time.Time          `json:"last_seen_at" bson:"last_seen_at"`
	AllowCount              uint64             `json:"allow_count" bson:"allow_count"`
	DenyCount               uint64             `json:"deny_count" bson:"deny_count"`
	ShortCircuitAllowCount  uint64             `json:"short_circuit_allow_count" bson:"short_circuit_allow_count"`
	ShortCircuitDenyCount   uint64             `json:"short_circuit_deny_count" bson:"short_circuit_deny_count"`
	Host                    string             `json:"host" bson:"host"`
	Path                    string             `json:"path" bson:"path"`
	UserAgentHash           string             `json:"user_agent_hash" bson:"user_agent_hash"`
	ExpiresAt               time.Time          `json:"expires_at" bson:"expires_at"`
	UpdatedAt               time.Time          `json:"updated_at" bson:"updated_at"`
}

func (r Record) Fresh(now time.Time) bool {
	return now.Before(r.ExpiresAt)
}

func NewRecord(clientIP, host, path, userAgent string, decision policy.Decision, ipContext *ipctx.Context, ttl time.Duration, now time.Time) Record {
	record := Record{
		ClientIP:       clientIP,
		LastDecision:   DecisionAllow,
		LastReasonCode: decision.Reason,
		FirstSeenAt:    now,
		LastSeenAt:     now,
		Host:           host,
		Path:           path,
		UserAgentHash:  HashUserAgent(userAgent),
		ExpiresAt:      now.Add(ttl),
		UpdatedAt:      now,
	}
	if !decision.Allowed {
		record.LastDecision = DecisionDeny
		record.DenyCount = 1
	} else {
		record.AllowCount = 1
	}
	if ipContext != nil {
		record.CountryCode = ipContext.CountryCode
		record.CountryName = ipContext.CountryName
		record.Region = ipContext.Region
		record.City = ipContext.City
		record.Privacy = ipContext.Privacy
	}
	return record
}

func (r *Record) ApplyDecision(decision policy.Decision, ipContext *ipctx.Context, host, path, userAgent string, ttl time.Duration, now time.Time) {
	r.LastDecision = DecisionAllow
	if !decision.Allowed {
		r.LastDecision = DecisionDeny
		r.DenyCount++
	} else {
		r.AllowCount++
	}
	r.LastReasonCode = decision.Reason
	r.LastSeenAt = now
	r.Host = host
	r.Path = path
	r.UserAgentHash = HashUserAgent(userAgent)
	r.ExpiresAt = now.Add(ttl)
	r.UpdatedAt = now
	if ipContext != nil {
		r.CountryCode = ipContext.CountryCode
		r.CountryName = ipContext.CountryName
		r.Region = ipContext.Region
		r.City = ipContext.City
		r.Privacy = ipContext.Privacy
	}
}

func (r *Record) ApplyShortCircuitHit(ttl time.Duration, now time.Time) {
	r.LastSeenAt = now
	r.ExpiresAt = now.Add(ttl)
	r.UpdatedAt = now
	if r.LastDecision == DecisionAllow {
		r.ShortCircuitAllowCount++
	} else {
		r.ShortCircuitDenyCount++
	}
}

func HashUserAgent(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return ""
	}
	sum := sha1.Sum([]byte(trimmed))
	return hex.EncodeToString(sum[:8])
}
