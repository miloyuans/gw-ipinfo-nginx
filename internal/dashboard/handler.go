package dashboard

import (
	"errors"
	"html"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gw-ipinfo-nginx/internal/reporting"
	v4query "gw-ipinfo-nginx/internal/v4/query"
)

const BasePath = "/_gw/dashboard"

type Handler struct {
	v4      *v4query.Service
	reports *reporting.Service
	now     func() time.Time
}

func New(v4 *v4query.Service, reports *reporting.Service) *Handler {
	return &Handler{
		v4:      v4,
		reports: reports,
		now:     time.Now,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path != BasePath && !strings.HasPrefix(r.URL.Path, BasePath+"/") {
		http.NotFound(w, r)
		return
	}
	if !isLocalRequest(r) {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == BasePath {
		http.Redirect(w, r, BasePath+"/", http.StatusFound)
		return
	}

	switch strings.TrimPrefix(r.URL.Path, BasePath) {
	case "/":
		h.serveIndex(w, r)
	case "/view/v4":
		h.serveV4(w, r)
	case "/view/report":
		h.serveReport(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) serveIndex(w http.ResponseWriter, _ *http.Request) {
	noCache(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML()))
}

func (h *Handler) serveV4(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	if h.v4 == nil {
		writeStatusDocument(w, http.StatusServiceUnavailable, "V4 route view is unavailable", "The v4 query service is not enabled in this process.")
		return
	}
	data, err := h.v4.BuildRoutesDocument(r.Context())
	if err != nil {
		writeStatusDocument(w, http.StatusInternalServerError, "V4 route view failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (h *Handler) serveReport(w http.ResponseWriter, r *http.Request) {
	noCache(w)
	if h.reports == nil {
		writeStatusDocument(w, http.StatusServiceUnavailable, "Report view is unavailable", "The reporting service is not enabled in this process.")
		return
	}
	start, end, label, err := h.resolveReportRange(r.URL.Query())
	if err != nil {
		writeStatusDocument(w, http.StatusBadRequest, "Invalid report range", err.Error())
		return
	}
	data, err := h.reports.GenerateHTMLRange(r.Context(), start, end, label)
	if err != nil {
		writeStatusDocument(w, http.StatusInternalServerError, "Report view failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

func (h *Handler) resolveReportRange(values url.Values) (time.Time, time.Time, string, error) {
	location := time.Local
	locationName := location.String()
	if h.reports != nil {
		location, locationName = h.reports.ReportLocation()
	}
	now := h.now().In(location)
	labelNow := now.Truncate(time.Minute)
	preset := strings.TrimSpace(strings.ToLower(values.Get("preset")))
	switch preset {
	case "", "today":
		start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, location)
		return start, now, "Today 00:00 - " + labelNow.Format("15:04") + " " + locationName, nil
	case "yesterday":
		yesterday := now.AddDate(0, 0, -1)
		start := time.Date(yesterday.Year(), yesterday.Month(), yesterday.Day(), 0, 0, 0, 0, location)
		end := start.AddDate(0, 0, 1).Add(-time.Nanosecond)
		return start, end, "Yesterday " + start.Format("2006-01-02") + " " + locationName, nil
	case "custom":
		start, err := parseLocalTime(values.Get("from"), location, false)
		if err != nil {
			return time.Time{}, time.Time{}, "", err
		}
		end, err := parseLocalTime(values.Get("to"), location, true)
		if err != nil {
			return time.Time{}, time.Time{}, "", err
		}
		if end.Before(start) {
			return time.Time{}, time.Time{}, "", errors.New("to must be after from")
		}
		return start, end, start.In(location).Format("2006-01-02 15:04") + " - " + end.In(location).Format("2006-01-02 15:04") + " " + locationName, nil
	default:
		return time.Time{}, time.Time{}, "", errors.New("preset must be today, yesterday, or custom")
	}
}

func parseLocalTime(value string, location *time.Location, endOfDay bool) (time.Time, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}, errors.New("from and to are required for custom ranges")
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.In(location), nil
	}
	for _, layout := range []string{"2006-01-02T15:04", "2006-01-02 15:04"} {
		if parsed, err := time.ParseInLocation(layout, value, location); err == nil {
			return parsed, nil
		}
	}
	if parsed, err := time.ParseInLocation("2006-01-02", value, location); err == nil {
		if endOfDay {
			return parsed.AddDate(0, 0, 1).Add(-time.Nanosecond), nil
		}
		return parsed, nil
	}
	return time.Time{}, errors.New("time must use RFC3339, YYYY-MM-DDTHH:MM, or YYYY-MM-DD")
}

func isLocalRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	host := strings.TrimSpace(r.Host)
	if hostName, _, err := net.SplitHostPort(host); err == nil {
		host = hostName
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	remoteHost, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		remoteHost = strings.TrimSpace(r.RemoteAddr)
	}
	if ip := net.ParseIP(remoteHost); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

func noCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func writeStatusDocument(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>` +
		html.EscapeString(title) +
		`</title><style>body{margin:0;padding:24px;background:#f6f8fb;color:#111827;font:14px/1.55 Arial,Helvetica,sans-serif}.box{max-width:860px;margin:0 auto;background:#fff;border:1px solid #dbe5f0;border-radius:12px;padding:20px}h1{margin:0 0 8px;font-size:22px}p{margin:0;color:#526173;white-space:pre-wrap}</style></head><body><main class="box"><h1>` +
		html.EscapeString(title) +
		`</h1><p>` +
		html.EscapeString(detail) +
		`</p></main></body></html>`))
}

func indexHTML() string {
	defaultInterval := "60"
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Gateway Dashboard</title>
<style>
:root{--bg:#eef3f8;--panel:#fff;--text:#111827;--muted:#5f6f83;--line:#ccd8e5;--line2:#e3ebf3;--accent:#0f766e;--accent2:#2563eb;--danger:#b91c1c;--shadow:0 10px 28px rgba(15,23,42,.08)}
*{box-sizing:border-box}
html,body{margin:0;min-height:100%;background:var(--bg);color:var(--text);font:14px/1.45 Arial,Helvetica,sans-serif}
body{display:flex;flex-direction:column}
.bar{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:14px;align-items:center;padding:14px 16px;background:var(--panel);border-bottom:1px solid var(--line);box-shadow:var(--shadow);position:sticky;top:0;z-index:5}
.brand{display:flex;align-items:center;gap:12px;min-width:0}
.mark{width:34px;height:34px;border-radius:8px;background:linear-gradient(135deg,var(--accent),var(--accent2));box-shadow:inset 0 0 0 1px rgba(255,255,255,.28)}
.title{display:grid;gap:1px;min-width:0}
.title strong{font-size:16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.title span{font-size:12px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.controls{display:flex;flex-wrap:wrap;justify-content:flex-end;gap:8px;align-items:center}
.seg,.field,.check{display:inline-flex;align-items:center;border:1px solid var(--line);background:#f8fbfe;border-radius:8px;min-height:36px}
.seg button{border:0;border-right:1px solid var(--line);background:transparent;color:var(--muted);height:34px;padding:0 12px;font-weight:700;cursor:pointer}
.seg button:last-child{border-right:0}
.seg button.active{background:#e7f5f2;color:#075e58}
.field{gap:6px;padding:0 8px}
.field label,.check label{font-size:12px;color:var(--muted);font-weight:700}
input,select{border:0;background:transparent;color:var(--text);height:32px;font:13px Arial,Helvetica,sans-serif;outline:none}
input[type=datetime-local]{width:176px}
.check{gap:7px;padding:0 10px}
.check input{height:auto}
.refresh{height:36px;border:1px solid var(--accent);background:var(--accent);color:#fff;border-radius:8px;padding:0 13px;font-weight:800;cursor:pointer}
.refresh:active{transform:translateY(1px)}
.status{padding:8px 16px;color:var(--muted);font-size:12px;border-bottom:1px solid var(--line2);background:#f8fbfe}
.frame-wrap{flex:1;min-height:0;padding:12px}
iframe{display:block;width:100%;height:calc(100vh - 120px);border:1px solid var(--line);border-radius:8px;background:#fff;box-shadow:var(--shadow)}
@media (max-width:980px){.bar{grid-template-columns:1fr}.controls{justify-content:flex-start}iframe{height:calc(100vh - 210px)}}
@media (max-width:620px){.bar{padding:12px}.controls{display:grid;grid-template-columns:1fr 1fr;width:100%}.seg,.field,.check,.refresh{width:100%;justify-content:center}.field{justify-content:space-between}.view-seg,.preset-seg{grid-column:1 / -1}.seg button{flex:1}input[type=datetime-local]{width:100%;min-width:0}.frame-wrap{padding:8px}iframe{height:calc(100vh - 268px)}}
</style></head><body>
<header class="bar">
	<div class="brand"><div class="mark"></div><div class="title"><strong>Gateway Dashboard</strong><span id="caption">Live report analytics</span></div></div>
	<form class="controls" onsubmit="return false">
		<div class="seg view-seg" role="tablist" aria-label="View">
			<button type="button" data-view="report" class="active">Report</button>
			<button type="button" data-view="v4">V4 Routes</button>
		</div>
		<div class="seg preset-seg" role="tablist" aria-label="Range">
			<button type="button" data-preset="today" class="active">Today</button>
			<button type="button" data-preset="yesterday">Yesterday</button>
			<button type="button" data-preset="custom">Custom</button>
		</div>
		<div class="field"><label for="from">From</label><input id="from" type="datetime-local"></div>
		<div class="field"><label for="to">To</label><input id="to" type="datetime-local"></div>
		<label class="check"><input id="auto" type="checkbox" checked><span>Auto</span></label>
		<div class="field"><label for="interval">Every</label><select id="interval"><option value="30">30s</option><option value="60" selected>60s</option><option value="120">120s</option><option value="300">300s</option></select></div>
		<button type="button" class="refresh" id="refresh">Refresh</button>
	</form>
</header>
<div class="status" id="status">Auto refresh is on, interval ` + defaultInterval + `s.</div>
<main class="frame-wrap"><iframe id="frame" title="Gateway dashboard view"></iframe></main>
<script>
(function(){
	const base='` + BasePath + `';
	const state={view:'report',preset:'today',timer:0};
	const frame=document.getElementById('frame');
	const status=document.getElementById('status');
	const caption=document.getElementById('caption');
	const from=document.getElementById('from');
	const to=document.getElementById('to');
	const auto=document.getElementById('auto');
	const interval=document.getElementById('interval');
	const refresh=document.getElementById('refresh');
	function pad(n){return String(n).padStart(2,'0')}
	function inputValue(d){return d.getFullYear()+'-'+pad(d.getMonth()+1)+'-'+pad(d.getDate())+'T'+pad(d.getHours())+':'+pad(d.getMinutes())}
	function setDefaults(){
		const now=new Date(); now.setSeconds(0,0);
		const start=new Date(now); start.setHours(0,0,0,0);
		from.value=inputValue(start); to.value=inputValue(now);
	}
	function readURL(){
		const p=new URLSearchParams(location.search);
		state.view=p.get('view')||state.view;
		state.preset=p.get('preset')||state.preset;
		if(p.get('from')) from.value=p.get('from');
		if(p.get('to')) to.value=p.get('to');
		if(p.get('auto')==='0') auto.checked=false;
		if(p.get('interval')) interval.value=p.get('interval');
	}
	function activate(){
		document.querySelectorAll('[data-view]').forEach(b=>b.classList.toggle('active',b.dataset.view===state.view));
		document.querySelectorAll('[data-preset]').forEach(b=>b.classList.toggle('active',b.dataset.preset===state.preset));
		const report=state.view==='report';
		document.querySelectorAll('[data-preset],#from,#to').forEach(el=>el.disabled=!report);
		from.disabled=!report||state.preset!=='custom';
		to.disabled=!report||state.preset!=='custom';
		caption.textContent=report?'Live report analytics':'Persisted v4 route state';
	}
	function viewURL(){
		const p=new URLSearchParams();
		p.set('_',Date.now());
		if(state.view==='v4') return base+'/view/v4?'+p.toString();
		p.set('preset',state.preset);
		if(state.preset==='custom'){p.set('from',from.value);p.set('to',to.value)}
		return base+'/view/report?'+p.toString();
	}
	function syncURL(){
		const p=new URLSearchParams();
		p.set('view',state.view); p.set('preset',state.preset); p.set('interval',interval.value);
		if(!auto.checked) p.set('auto','0');
		if(state.preset==='custom'){p.set('from',from.value);p.set('to',to.value)}
		history.replaceState(null,'',base+'/?'+p.toString());
	}
	function load(){
		activate(); syncURL(); frame.src=viewURL();
		status.textContent=(auto.checked?'Auto refresh is on':'Auto refresh is off')+', interval '+interval.value+'s, last load '+new Date().toLocaleString()+'.';
		resetTimer();
	}
	function resetTimer(){
		clearInterval(state.timer);
		if(auto.checked){state.timer=setInterval(function(){frame.src=viewURL(); status.textContent='Refreshed '+new Date().toLocaleString()+', interval '+interval.value+'s.'}, Number(interval.value)*1000)}
	}
	document.querySelectorAll('[data-view]').forEach(b=>b.addEventListener('click',function(){state.view=this.dataset.view;load()}));
	document.querySelectorAll('[data-preset]').forEach(b=>b.addEventListener('click',function(){state.preset=this.dataset.preset;load()}));
	[from,to,interval,auto].forEach(el=>el.addEventListener('change',load));
	refresh.addEventListener('click',load);
	setDefaults(); readURL(); load();
})();
</script></body></html>`
}
