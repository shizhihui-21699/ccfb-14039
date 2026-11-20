// Package api exposes the detector over HTTP: update ingestion, alert queries,
// metrics and a small server-rendered dashboard.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"hijackwatch/internal/detect"
	"hijackwatch/internal/model"
	"hijackwatch/internal/sim"
)

// Meta describes the data the server is running on.
type Meta struct {
	Dataset    string         `json:"dataset,omitempty"`
	Mode       string         `json:"mode"`
	Start      time.Time      `json:"start,omitempty"`
	End        time.Time      `json:"end,omitempty"`
	Collectors []string       `json:"collectors,omitempty"`
	Incidents  []sim.Incident `json:"-"`
}

// Server is the HTTP front end.
type Server struct {
	det  *detect.Detector
	meta Meta
	mux  *http.ServeMux
}

// New builds a server around a detector.
func New(det *detect.Detector) *Server {
	s := &Server{det: det, mux: http.NewServeMux()}
	s.routes()
	return s
}

// SetMeta attaches dataset metadata for the dashboard.
func (s *Server) SetMeta(m Meta) { s.meta = m }

// Handler returns the root mux.
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	s.mux.HandleFunc("POST /v1/updates", s.handleIngest)
	s.mux.HandleFunc("POST /v1/updates/batch", s.handleBatch)
	s.mux.HandleFunc("GET /v1/alerts", s.handleAlerts)
	s.mux.HandleFunc("GET /v1/alerts/{id}", s.handleAlert)
	s.mux.HandleFunc("GET /v1/incidents", s.handleIncidents)
	s.mux.HandleFunc("GET /v1/stats", s.handleStats)
	s.mux.HandleFunc("GET /metrics", s.handleMetrics)
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok\n")
	})
	s.mux.HandleFunc("GET /", s.handleDashboard)
}

// StartTicker drives Tick on a timer so quiet periods age out.
func (s *Server) StartTicker(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.det.Tick(now.UTC())
		}
	}
}

func (s *Server) handleIngest(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var u model.Update
	if err := json.Unmarshal(body, &u); err != nil {
		httpError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	if err := u.Validate(time.Now().UTC()); err != nil {
		httpError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}
	alerts := s.det.Process(u)
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": 1, "alerts": len(alerts)})
}

func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		httpError(w, http.StatusBadRequest, "read body: "+err.Error())
		return
	}
	var ups []model.Update
	if err := json.Unmarshal(body, &ups); err != nil {
		httpError(w, http.StatusBadRequest, "invalid json: "+err.Error())
		return
	}
	now := time.Now().UTC()
	accepted, rejected := 0, 0
	for _, u := range ups {
		if err := u.Validate(now); err != nil {
			rejected++
			continue
		}
		s.det.Process(u)
		accepted++
	}
	s.det.Flush()
	writeJSON(w, http.StatusAccepted, map[string]any{"accepted": accepted, "rejected": rejected})
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	alerts := s.det.Alerts()
	q := r.URL.Query()
	if st := q.Get("status"); st != "" {
		alerts = filter(alerts, func(a model.Alert) bool { return string(a.Status) == st })
	}
	if sev := q.Get("min_severity"); sev != "" {
		if min, err := model.ParseSeverity(sev); err == nil {
			alerts = filter(alerts, func(a model.Alert) bool { return a.Severity >= min })
		}
	}
	limit := len(alerts)
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < limit {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"count": len(alerts), "alerts": alerts[:limit]})
}

func (s *Server) handleAlert(w http.ResponseWriter, r *http.Request) {
	a, ok := s.det.Alert(r.PathValue("id"))
	if !ok {
		httpError(w, http.StatusNotFound, "alert not found")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"incidents": s.meta.Incidents})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st := s.det.StatsSnapshot()
	writeJSON(w, http.StatusOK, map[string]any{
		"stats":      st,
		"candidates": s.det.CandidateCount(),
		"now":        s.det.Now(),
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	st := s.det.StatsSnapshot()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP bgpwatch_updates_total Updates ingested.\n")
	fmt.Fprintf(w, "# TYPE bgpwatch_updates_total counter\n")
	fmt.Fprintf(w, "bgpwatch_updates_total %d\n", st.Received)
	fmt.Fprintf(w, "bgpwatch_updates_ignored_total %d\n", st.Ignored)
	fmt.Fprintf(w, "bgpwatch_updates_unrelated_total %d\n", st.Unrelated)
	fmt.Fprintf(w, "bgpwatch_updates_malformed_total %d\n", st.Malformed)
	fmt.Fprintf(w, "bgpwatch_candidates_dropped_total %d\n", st.CandidatesDropped)
	fmt.Fprintf(w, "bgpwatch_alerts_fired_total %d\n", st.AlertsFired)
	fmt.Fprintf(w, "bgpwatch_alerts_upgraded_total %d\n", st.AlertsUpgraded)
	fmt.Fprintf(w, "bgpwatch_alerts_resolved_total %d\n", st.AlertsResolved)
	for _, sev := range []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow} {
		n := 0
		for _, a := range s.det.Alerts() {
			if a.Status == model.StatusFiring && a.Severity == sev {
				n++
			}
		}
		fmt.Fprintf(w, "bgpwatch_alerts_firing{severity=%q} %d\n", sev.String(), n)
	}
}

func filter(in []model.Alert, keep func(model.Alert) bool) []model.Alert {
	out := in[:0]
	for _, a := range in {
		if keep(a) {
			out = append(out, a)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
