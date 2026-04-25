package model

import "time"

const (
	CollectionSnapshots     = "v4_route_snapshots"
	CollectionSnapshotHosts = "v4_route_snapshot_hosts"
	CollectionRuntimeStates = "v4_host_runtime_states"
	CollectionEvents        = "v4_events"
)

const (
	SyncStateID         = "sync_state"
	ModePassthrough    = "passthrough"
	ModeDegradedRedirect = "degraded_redirect"
	ModeRecovering     = "recovering"
)

const (
	EventSnapshotUpdated             = "snapshot_updated"
	EventSnapshotSyncFailed          = "snapshot_sync_failed"
	EventDomainUnhealthy             = "domain_unhealthy"
	EventDomainRecovered             = "domain_recovered"
	EventTrafficSwitchedToRedirect   = "traffic_switched_to_redirect"
	EventTrafficRestoredPassthrough  = "traffic_restored_to_passthrough"
)

type Snapshot struct {
	ID          string    `json:"id" bson:"_id"`
	Version     string    `json:"version" bson:"version"`
	Fingerprint string    `json:"fingerprint" bson:"fingerprint"`
	HostCount   int       `json:"host_count" bson:"host_count"`
	CreatedAt   time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" bson:"updated_at"`
	WriterInstanceID string `json:"writer_instance_id" bson:"writer_instance_id"`
	WriterStartedAt  time.Time `json:"writer_started_at" bson:"writer_started_at"`
	LastGood    bool      `json:"last_good" bson:"last_good"`
	Source      string    `json:"source" bson:"source"`
}

type SyncState struct {
	ID                   string    `json:"id" bson:"_id"`
	LeaseName            string    `json:"lease_name" bson:"lease_name"`
	LeaseOwner           string    `json:"lease_owner" bson:"lease_owner"`
	LeaseExpiresAt       time.Time `json:"lease_expires_at" bson:"lease_expires_at"`
	WriterInstanceID     string    `json:"writer_instance_id" bson:"writer_instance_id"`
	WriterStartedAt      time.Time `json:"writer_started_at" bson:"writer_started_at"`
	LastSyncAt           time.Time `json:"last_sync_at" bson:"last_sync_at"`
	LastSuccessAt        time.Time `json:"last_success_at" bson:"last_success_at"`
	LastStatus           string    `json:"last_status" bson:"last_status"`
	LastError            string    `json:"last_error" bson:"last_error"`
	LastSnapshotVersion  string    `json:"last_snapshot_version" bson:"last_snapshot_version"`
	LastFingerprint      string    `json:"last_fingerprint" bson:"last_fingerprint"`
	LastHostCount        int       `json:"last_host_count" bson:"last_host_count"`
	UpdatedAt            time.Time `json:"updated_at" bson:"updated_at"`
}

type SnapshotHost struct {
	ID                    string    `json:"id" bson:"_id"`
	SnapshotID            string    `json:"snapshot_id" bson:"snapshot_id"`
	Host                  string    `json:"host" bson:"host"`
	Source                string    `json:"source" bson:"source"`
	BackendService        string    `json:"backend_service" bson:"backend_service"`
	BackendHost           string    `json:"backend_host" bson:"backend_host"`
	SecurityChecksEnabled bool      `json:"security_checks_enabled" bson:"security_checks_enabled"`
	IPEnrichmentMode      string    `json:"ip_enrichment_mode" bson:"ip_enrichment_mode"`
	Probe                 ProbeSpec `json:"probe" bson:"probe"`
	UpdatedAt             time.Time `json:"updated_at" bson:"updated_at"`
}

type ProbeSpec struct {
	Enabled            bool          `json:"enabled" bson:"enabled"`
	Mode               string        `json:"mode" bson:"mode"`
	URL                string        `json:"url" bson:"url"`
	HTMLPaths          []string      `json:"html_paths" bson:"html_paths"`
	JSPaths            []string      `json:"js_paths" bson:"js_paths"`
	LinkURL            string        `json:"link_url" bson:"link_url"`
	RedirectURLs       []string      `json:"redirect_urls" bson:"redirect_urls"`
	Patterns           []string      `json:"patterns" bson:"patterns"`
	UnhealthyStatusCodes []int       `json:"unhealthy_status_codes" bson:"unhealthy_status_codes"`
	Interval           time.Duration `json:"interval" bson:"interval"`
	Timeout            time.Duration `json:"timeout" bson:"timeout"`
	HealthyThreshold   int           `json:"healthy_threshold" bson:"healthy_threshold"`
	UnhealthyThreshold int           `json:"unhealthy_threshold" bson:"unhealthy_threshold"`
	MinSwitchInterval  time.Duration `json:"min_switch_interval" bson:"min_switch_interval"`
}

type HostRuntimeState struct {
	ID                string    `json:"id" bson:"_id"`
	Host              string    `json:"host" bson:"host"`
	SnapshotVersion   string    `json:"snapshot_version" bson:"snapshot_version"`
	SnapshotFingerprint string  `json:"snapshot_fingerprint" bson:"snapshot_fingerprint"`
	WriterInstanceID  string    `json:"writer_instance_id" bson:"writer_instance_id"`
	WriterStartedAt   time.Time `json:"writer_started_at" bson:"writer_started_at"`
	Mode              string    `json:"mode" bson:"mode"`
	FaultActive       bool      `json:"fault_active" bson:"fault_active"`
	FaultCount        int       `json:"fault_count" bson:"fault_count"`
	SwitchSuccessCount int      `json:"switch_success_count" bson:"switch_success_count"`
	SwitchFailureCount int      `json:"switch_failure_count" bson:"switch_failure_count"`
	RedirectUniqueClientCount int `json:"redirect_unique_client_count" bson:"redirect_unique_client_count"`
	SourceURL         string    `json:"source_url" bson:"source_url"`
	RedirectURL       string    `json:"redirect_url" bson:"redirect_url"`
	RedirectCandidates []string `json:"redirect_candidates" bson:"redirect_candidates"`
	RedirectClientKeys []string `json:"redirect_client_keys" bson:"redirect_client_keys"`
	LastProbeTargets  []string  `json:"last_probe_targets" bson:"last_probe_targets"`
	LastFailedTargets []string  `json:"last_failed_targets" bson:"last_failed_targets"`
	WorkspaceFile     string    `json:"workspace_file" bson:"workspace_file"`
	LastProbeAt       time.Time `json:"last_probe_at" bson:"last_probe_at"`
	LastProbeError    string    `json:"last_probe_error" bson:"last_probe_error"`
	LastHealthyAt     time.Time `json:"last_healthy_at" bson:"last_healthy_at"`
	LastUnhealthyAt   time.Time `json:"last_unhealthy_at" bson:"last_unhealthy_at"`
	LastSwitchAt      time.Time `json:"last_switch_at" bson:"last_switch_at"`
	HealthyCount      int       `json:"healthy_count" bson:"healthy_count"`
	UnhealthyCount    int       `json:"unhealthy_count" bson:"unhealthy_count"`
	UpdatedAt         time.Time `json:"updated_at" bson:"updated_at"`
}

type Event struct {
	ID          string         `json:"id" bson:"_id"`
	Type        string         `json:"type" bson:"type"`
	Host        string         `json:"host" bson:"host"`
	Fingerprint string         `json:"fingerprint" bson:"fingerprint"`
	Level       string         `json:"level" bson:"level"`
	Title       string         `json:"title" bson:"title"`
	Message     string         `json:"message" bson:"message"`
	SilentUntil time.Time      `json:"silent_until" bson:"silent_until"`
	Recovered   bool           `json:"recovered" bson:"recovered"`
	Metadata    map[string]any `json:"metadata" bson:"metadata"`
	CreatedAt   time.Time      `json:"created_at" bson:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at" bson:"updated_at"`
}
