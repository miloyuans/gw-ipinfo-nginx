package model

import "gw-ipinfo-nginx/internal/ipctx"

type AuditRecord struct {
	RequestID   string
	ClientIP    string
	ServiceName string
	Method      string
	Path        string
	Allowed     bool
	Result      string
	ReasonCode  string
	CacheSource ipctx.CacheSource
	CountryCode string
	CountryName string
	Region      string
	City        string
	Privacy     ipctx.PrivacyFlags
	LatencyMS   float64
}
