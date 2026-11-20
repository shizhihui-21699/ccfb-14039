package api

import (
	"html/template"
	"net/http"
	"time"

	"hijackwatch/internal/model"
)

var dashTmpl = template.Must(template.New("dash").Funcs(template.FuncMap{
	"ts":    func(t time.Time) string { return t.UTC().Format("01-02 15:04:05") },
	"since": func(t time.Time) string { return t.UTC().Format("15:04") },
	"sevClass": func(s model.Severity) string {
		switch s {
		case model.SevCritical:
			return "crit"
		case model.SevHigh:
			return "high"
		case model.SevMedium:
			return "med"
		case model.SevLow:
			return "low"
		}
		return "info"
	},
}).Parse(dashHTML))

type dashData struct {
	Meta   Meta
	Now    time.Time
	Stats  any
	Alerts []model.Alert
	Firing int
	At     string
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	alerts := s.det.Alerts()
	firing := 0
	for _, a := range alerts {
		if a.Status == model.StatusFiring {
			firing++
		}
	}
	data := dashData{
		Meta: s.meta, Now: s.det.Now(), Stats: s.det.StatsSnapshot(),
		Alerts: alerts, Firing: firing, At: time.Now().UTC().Format(time.RFC3339),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashTmpl.Execute(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

const dashHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>hijackwatch</title>
<style>
:root{--bg:#0e1117;--panel:#161b22;--line:#30363d;--fg:#e6edf3;--dim:#8b949e;
--crit:#f85149;--high:#ff8c42;--med:#d29922;--low:#3fb950;--info:#58a6ff}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
header{background:var(--panel);border-bottom:1px solid var(--line);padding:14px 20px;display:flex;gap:24px;align-items:baseline;flex-wrap:wrap}
h1{font-size:16px;margin:0}
.head-meta{color:var(--dim);font-size:12px}
main{padding:20px;max-width:1200px;margin:0 auto}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:12px 14px}
.card .n{font-size:22px}
.card .l{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.06em}
.badge{display:inline-block;padding:1px 8px;border-radius:999px;font-size:11px;font-weight:600;text-transform:uppercase}
.crit{background:var(--crit);color:#0b0d10}.high{background:var(--high);color:#0b0d10}
.med{background:var(--med);color:#0b0d10}.low{background:var(--low);color:#0b0d10}
.info{background:var(--info);color:#0b0d10}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:6px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top;font-size:12.5px}
th{color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
.firing{color:var(--crit)}.resolved{color:var(--low)}
.ev{color:var(--dim);font-size:11px;margin-top:4px}
.ev code{background:#0b0d10;padding:0 4px;border-radius:3px;color:var(--fg)}
.mono{white-space:nowrap}
.empty{color:var(--dim);text-align:center;padding:28px}
a{color:var(--info)}
</style></head><body>
<header>
  <h1>hijackwatch</h1>
  <span class="head-meta">mode={{.Meta.Mode}} {{if .Meta.Dataset}}dataset={{.Meta.Dataset}}{{end}}</span>
  <span class="head-meta">simulated clock={{ts .Now}}</span>
  <span class="head-meta">firing=<span class="firing">{{.Firing}}</span></span>
  <span class="head-meta"><a href="/v1/alerts">JSON</a> · <a href="/metrics">metrics</a> · <a href="/v1/incidents">ground truth</a></span>
</header>
<main>
<div class="grid">
  <div class="card"><div class="l">updates</div><div class="n">{{.Stats.Received}}</div></div>
  <div class="card"><div class="l">ignored</div><div class="n">{{.Stats.Ignored}}</div></div>
  <div class="card"><div class="l">unrelated</div><div class="n">{{.Stats.Unrelated}}</div></div>
  <div class="card"><div class="l">candidates</div><div class="n">{{.Stats.Candidates}}</div></div>
  <div class="card"><div class="l">fired</div><div class="n">{{.Stats.AlertsFired}}</div></div>
  <div class="card"><div class="l">resolved</div><div class="n">{{.Stats.AlertsResolved}}</div></div>
</div>
{{if .Alerts}}
<table>
<thead><tr><th>first seen</th><th>sev</th><th>status</th><th>prefix</th><th>origin</th><th>kind</th><th>pts</th><th>score</th><th>summary / evidence</th></tr></thead>
<tbody>
{{range .Alerts}}
<tr>
  <td class="mono">{{ts .FirstSeen}}</td>
  <td><span class="badge {{sevClass .Severity}}">{{.Severity}}</span></td>
  <td class="{{.Status}}">{{.Status}}</td>
  <td class="mono">{{.Prefix}}{{if .Parent}}<div class="ev">parent {{.Parent}}</div>{{end}}</td>
  <td class="mono">AS{{.Origin}}</td>
  <td class="mono">{{.Kind}}</td>
  <td class="mono">{{len .Collectors}}</td>
  <td class="mono">{{.Score}}</td>
  <td>{{.Summary}}
    {{range .Evidence}}<div class="ev"><code>{{.Code}}</code> {{.Weight}} — {{.Detail}}</div>{{end}}
  </td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<div class="empty">no alerts (yet)</div>
{{end}}
</main></body></html>`
