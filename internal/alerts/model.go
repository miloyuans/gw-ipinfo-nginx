package alerts

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/ipctx"
	"gw-ipinfo-nginx/internal/policy"
)

type Payload struct {
	Type        string             `bson:"type" json:"type"`
	NotifyType  string             `bson:"notify_type" json:"notify_type"`
	Severity    string             `bson:"severity" json:"severity"`
	ClientIP    string             `bson:"client_ip" json:"client_ip"`
	Result      string             `bson:"result" json:"result"`
	FinalAction string             `bson:"final_action" json:"final_action"`
	Reason      string             `bson:"reason" json:"reason"`
	Method      string             `bson:"method" json:"method"`
	URL         string             `bson:"url" json:"url"`
	ServiceName string             `bson:"service_name" json:"service_name"`
	CountryCode string             `bson:"country_code" json:"country_code"`
	City        string             `bson:"city" json:"city"`
	Privacy     ipctx.PrivacyFlags `bson:"privacy" json:"privacy"`
	CacheSource string             `bson:"cache_source" json:"cache_source"`
	RequestID   string             `bson:"request_id" json:"request_id"`
	Timestamp   time.Time          `bson:"timestamp" json:"timestamp"`
	UserAgent   string             `bson:"user_agent,omitempty" json:"user_agent,omitempty"`
}

func NewPayload(req *http.Request, requestID, serviceName, clientIP, safeURL string, cacheSource ipctx.CacheSource, decision policy.Decision, context *ipctx.Context, includeUserAgent bool) Payload {
	payload := Payload{
		Type:        decision.AlertType,
		NotifyType:  decision.AlertType,
		Severity:    severityForDecision(decision),
		ClientIP:    clientIP,
		Result:      decision.Result,
		FinalAction: ternary(decision.Allowed, "allow", "deny"),
		Reason:      decision.Reason,
		Method:      req.Method,
		URL:         safeURL,
		ServiceName: serviceName,
		CacheSource: string(cacheSource),
		RequestID:   requestID,
		Timestamp:   time.Now().UTC(),
	}
	if context != nil {
		payload.CountryCode = context.CountryCode
		payload.City = context.City
		payload.Privacy = context.Privacy
	}
	if includeUserAgent {
		payload.UserAgent = strings.TrimSpace(req.UserAgent())
	}
	return payload
}

func DedupeKey(payload Payload, window time.Duration) string {
	seconds := int64(window.Seconds())
	if seconds <= 0 {
		seconds = 60
	}
	slot := payload.Timestamp.UTC().Unix() / seconds
	notifyType := payload.NotifyType
	if notifyType == "" {
		notifyType = payload.Type
	}
	sum := sha1.Sum([]byte(fmt.Sprintf("%s|%s|%s|%s|%d", notifyType, payload.ServiceName, payload.ClientIP, payload.Reason, slot)))
	return hex.EncodeToString(sum[:])
}

func ternary(condition bool, yes, no string) string {
	if condition {
		return yes
	}
	return no
}

func severityForDecision(decision policy.Decision) string {
	switch decision.AlertType {
	case "allowed_with_risk":
		return "warning"
	case "blocked_with_ambiguity":
		return "high"
	default:
		if decision.Allowed {
			return "info"
		}
		return "medium"
	}
}
