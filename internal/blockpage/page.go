package blockpage

import (
	"html/template"
	"net/http"

	"gw-ipinfo-nginx/internal/config"
)

var denyTemplate = template.Must(template.New("deny-page").Parse(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{{ .Title }}</title>
    <style>
      :root {
        color-scheme: light;
        --bg: #f4efe6;
        --panel: #fffdf8;
        --ink: #1f2937;
        --muted: #6b7280;
        --accent: #b45309;
        --border: #eadfce;
      }
      * { box-sizing: border-box; }
      body {
        margin: 0;
        min-height: 100vh;
        display: grid;
        place-items: center;
        background:
          radial-gradient(circle at top left, #fff3d6 0%, transparent 30%),
          linear-gradient(180deg, #f7f1e5 0%, var(--bg) 100%);
        color: var(--ink);
        font: 16px/1.6 "Segoe UI", "Helvetica Neue", Arial, sans-serif;
      }
      .card {
        width: min(92vw, 720px);
        padding: 40px 32px;
        border: 1px solid var(--border);
        border-radius: 24px;
        background: var(--panel);
        box-shadow: 0 24px 80px rgba(31, 41, 55, 0.12);
      }
      .eyebrow {
        display: inline-block;
        margin-bottom: 14px;
        padding: 6px 12px;
        border-radius: 999px;
        background: #fff4db;
        color: var(--accent);
        font-size: 12px;
        font-weight: 700;
        letter-spacing: 0.08em;
        text-transform: uppercase;
      }
      h1 {
        margin: 0 0 14px;
        font-size: clamp(30px, 5vw, 48px);
        line-height: 1.05;
      }
      p {
        margin: 0 0 12px;
        color: var(--muted);
      }
      .meta {
        margin-top: 22px;
        padding-top: 18px;
        border-top: 1px solid var(--border);
        color: var(--ink);
        font-size: 14px;
      }
      code {
        display: inline-block;
        margin-top: 8px;
        padding: 6px 10px;
        border-radius: 10px;
        background: #f6f3ee;
        color: #111827;
      }
    </style>
  </head>
  <body>
    <main class="card">
      <div class="eyebrow">Gateway Guard</div>
      <h1>{{ .Heading }}</h1>
      <p>{{ .Message }}</p>
      <p>{{ .Hint }}</p>
      <div class="meta">
        Request ID<br />
        <code>{{ .RequestID }}</code>
      </div>
    </main>
  </body>
</html>`))

type viewData struct {
	Title     string
	Heading   string
	Message   string
	Hint      string
	RequestID string
}

func Write(w http.ResponseWriter, status int, cfg config.DenyPageConfig, requestID string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Request-ID", requestID)
	w.WriteHeader(status)

	data := viewData{
		Title:     cfg.Title,
		Heading:   cfg.Heading,
		Message:   cfg.Message,
		Hint:      cfg.Hint,
		RequestID: requestID,
	}
	if err := denyTemplate.Execute(w, data); err != nil {
		http.Error(w, "access unavailable", status)
	}
}
