package model

import "gw-ipinfo-nginx/internal/ipctx"

type AuditRecord struct {
	RequestID              string
	ClientIP               string
	ServiceName            string
	UpstreamURL            string
	Host                   string
	Method                 string
	Path                   string
	RequestURL             string
	Allowed                bool
	Result                 string
	ReasonCode             string
	CacheSource            ipctx.CacheSource
	DataSourceMode         string
	ShortCircuitHit        bool
	ShortCircuitSource     string
	ShortCircuitDecision string
	IPInfoLookupAction     string
	RouteSetKind           string
	RouteID                string
	SourceHost             string
	SourcePathPrefix       string
	TargetHost             string
	TargetPublicURL        string
	BackendService         string
	BackendHost            string
	GrantStatus            string
	GrantExpireAt          string
	V3SecurityFilterEnabled bool
	V3SelectedTargetID      string
	V3SelectedTargetHost    string
	V3StrategyMode          string
	V3BindingReused         bool
	CountryCode            string
	CountryName            string
	Region                 string
	City                   string
	Privacy                ipctx.PrivacyFlags
	LatencyMS              float64
}
