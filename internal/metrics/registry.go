package metrics

import (
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type Labels map[string]string

type Registry struct {
	mu         sync.RWMutex
	counters   []*Counter
	histograms []*Histogram
}

func NewRegistry() *Registry {
	return &Registry{}
}

func (r *Registry) NewCounter(name, help string) *Counter {
	counter := &Counter{
		name:   name,
		help:   help,
		values: make(map[string]*counterSeries),
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.counters = append(r.counters, counter)
	return counter
}

func (r *Registry) NewHistogram(name, help string, buckets []float64) *Histogram {
	h := &Histogram{
		name:    name,
		help:    help,
		buckets: append([]float64(nil), buckets...),
		values:  make(map[string]*histogramSeries),
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.histograms = append(r.histograms, h)
	return h
}

func (r *Registry) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	r.mu.RLock()
	counters := append([]*Counter(nil), r.counters...)
	histograms := append([]*Histogram(nil), r.histograms...)
	r.mu.RUnlock()

	for _, counter := range counters {
		counter.writeTo(w)
	}
	for _, histogram := range histograms {
		histogram.writeTo(w)
	}
}

type Counter struct {
	name   string
	help   string
	mu     sync.Mutex
	values map[string]*counterSeries
}

type counterSeries struct {
	labels Labels
	value  uint64
}

func (c *Counter) Inc(labels Labels) {
	c.Add(labels, 1)
}

func (c *Counter) Add(labels Labels, delta uint64) {
	key, frozen := freezeLabels(labels)
	c.mu.Lock()
	defer c.mu.Unlock()
	series, ok := c.values[key]
	if !ok {
		series = &counterSeries{labels: frozen}
		c.values[key] = series
	}
	series.value += delta
}

func (c *Counter) writeTo(w http.ResponseWriter) {
	_, _ = fmt.Fprintf(w, "# HELP %s %s\n", c.name, c.help)
	_, _ = fmt.Fprintf(w, "# TYPE %s counter\n", c.name)

	c.mu.Lock()
	defer c.mu.Unlock()
	keys := sortedKeys(c.values)
	for _, key := range keys {
		series := c.values[key]
		_, _ = fmt.Fprintf(w, "%s%s %d\n", c.name, formatLabels(series.labels), series.value)
	}
}

type Histogram struct {
	name    string
	help    string
	buckets []float64
	mu      sync.Mutex
	values  map[string]*histogramSeries
}

type histogramSeries struct {
	labels Labels
	sum    float64
	count  uint64
	counts []uint64
}

func (h *Histogram) Observe(labels Labels, value float64) {
	key, frozen := freezeLabels(labels)
	h.mu.Lock()
	defer h.mu.Unlock()
	series, ok := h.values[key]
	if !ok {
		series = &histogramSeries{
			labels: frozen,
			counts: make([]uint64, len(h.buckets)+1),
		}
		h.values[key] = series
	}
	series.sum += value
	series.count++
	bucketIndex := len(h.buckets)
	for idx, bucket := range h.buckets {
		if value <= bucket {
			bucketIndex = idx
			break
		}
	}
	if bucketIndex < len(h.buckets) {
		series.counts[bucketIndex]++
	}
}

func (h *Histogram) writeTo(w http.ResponseWriter) {
	_, _ = fmt.Fprintf(w, "# HELP %s %s\n", h.name, h.help)
	_, _ = fmt.Fprintf(w, "# TYPE %s histogram\n", h.name)

	h.mu.Lock()
	defer h.mu.Unlock()
	keys := sortedKeys(h.values)
	for _, key := range keys {
		series := h.values[key]
		cumulative := uint64(0)
		for idx, bucket := range h.buckets {
			cumulative += series.counts[idx]
			labels := mergeLabels(series.labels, Labels{"le": trimFloat(bucket)})
			_, _ = fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, formatLabels(labels), cumulative)
		}
		labels := mergeLabels(series.labels, Labels{"le": "+Inf"})
		_, _ = fmt.Fprintf(w, "%s_bucket%s %d\n", h.name, formatLabels(labels), series.count)
		_, _ = fmt.Fprintf(w, "%s_sum%s %s\n", h.name, formatLabels(series.labels), trimFloat(series.sum))
		_, _ = fmt.Fprintf(w, "%s_count%s %d\n", h.name, formatLabels(series.labels), series.count)
	}
}

type GatewayMetrics struct {
	Requests        *Counter
	DecisionReasons *Counter
	RequestLatency  *Histogram
	LookupResults   *Counter
	IPInfoRequests  *Counter
	IPInfoLatency   *Histogram
	MongoLatency    *Histogram
	ProxyErrors     *Counter
	AlertOutbox     *Counter
	AlertDelivery   *Counter
}

func NewGatewayMetrics(registry *Registry) *GatewayMetrics {
	return &GatewayMetrics{
		Requests: registry.NewCounter(
			"gw_gateway_requests_total",
			"Total requests handled by the gateway, partitioned by service and result.",
		),
		DecisionReasons: registry.NewCounter(
			"gw_gateway_deny_reasons_total",
			"Denied requests by service and reason.",
		),
		RequestLatency: registry.NewHistogram(
			"gw_gateway_request_duration_seconds",
			"Gateway request latency in seconds.",
			[]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
		),
		LookupResults: registry.NewCounter(
			"gw_gateway_lookup_results_total",
			"IP lookup/cache results by source.",
		),
		IPInfoRequests: registry.NewCounter(
			"gw_gateway_ipinfo_requests_total",
			"Outgoing IPinfo requests by status.",
		),
		IPInfoLatency: registry.NewHistogram(
			"gw_gateway_ipinfo_request_duration_seconds",
			"Latency of outgoing IPinfo requests.",
			[]float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5},
		),
		MongoLatency: registry.NewHistogram(
			"gw_gateway_mongo_lookup_duration_seconds",
			"Latency of Mongo cache lookups.",
			[]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
		),
		ProxyErrors: registry.NewCounter(
			"gw_gateway_proxy_errors_total",
			"Reverse proxy errors by service.",
		),
		AlertOutbox: registry.NewCounter(
			"gw_gateway_alerts_outbox_total",
			"Alert outbox enqueue attempts by type and status.",
		),
		AlertDelivery: registry.NewCounter(
			"gw_gateway_alert_delivery_total",
			"Alert delivery results by type and status.",
		),
	}
}

func freezeLabels(labels Labels) (string, Labels) {
	if len(labels) == 0 {
		return "", nil
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	frozen := make(Labels, len(labels))
	builder := strings.Builder{}
	for _, key := range keys {
		value := labels[key]
		frozen[key] = value
		builder.WriteString(key)
		builder.WriteByte('=')
		builder.WriteString(value)
		builder.WriteByte(';')
	}
	return builder.String(), frozen
}

func mergeLabels(base, extra Labels) Labels {
	merged := make(Labels, len(base)+len(extra))
	for key, value := range base {
		merged[key] = value
	}
	for key, value := range extra {
		merged[key] = value
	}
	return merged
}

func formatLabels(labels Labels) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf(`%s=%s`, key, strconv.Quote(labels[key])))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func sortedKeys[T any](series map[string]T) []string {
	keys := make([]string, 0, len(series))
	for key := range series {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func trimFloat(value float64) string {
	return strconv.FormatFloat(value, 'f', -1, 64)
}
