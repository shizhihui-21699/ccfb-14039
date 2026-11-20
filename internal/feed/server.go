// Package feed runs the detection engine as a service: it streams a scenario
// feed in real time (scaled), exposes alerts over HTTP, and keeps state so an
// operator can inspect open incidents.
package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"routewatch/internal/detect"
	"routewatch/internal/model"
	"routewatch/internal/registry"
)

// Options configures the server.
type Options struct {
	// Speed multiplies wall-clock time; 60 means one simulated minute per
	// second.
	Speed float64
	Addr  string
	Quiet bool
}

// Server is the streaming service.
type Server struct {
	reg *registry.Registry
	cfg detect.Config
	opt Options

	mu      sync.Mutex
	eng     *detect.Engine
	alerts  []model.Alert
	started time.Time
	now     time.Time
}

// NewServer builds a server; call Run with a scenario.
func NewServer(reg *registry.Registry, cfg detect.Config, opt Options) *Server {
	if opt.Speed <= 0 {
		opt.Speed = 60
	}
	if opt.Addr == "" {
		opt.Addr = ":8080"
	}
	return &Server{reg: reg, cfg: cfg, opt: opt, started: time.Now()}
}

// Run streams the scenario and serves HTTP until ctx is cancelled or the
// scenario ends. The HTTP server keeps running after the feed ends so an
// operator can still inspect the final state.
func (s *Server) Run(sc model.Scenario) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	s.mu.Lock()
	s.eng = detect.New(s.reg, s.cfg, sc.Start)
	s.eng.Start(sc.Start)
	s.now = sc.Start
	s.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/api/alerts", s.handleAlerts)
	mux.HandleFunc("/api/incidents", s.handleIncidents)
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/config", s.handleConfig)

	srv := &http.Server{Addr: s.opt.Addr, Handler: mux}
	errCh := make(chan error, 2)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	fmt.Fprintf(osStderr(), "routewatch serving on %s (feed %s..%s at %.0fx)\n",
		s.opt.Addr, sc.Start.Format(time.RFC3339), sc.End.Format(time.RFC3339), s.opt.Speed)

	go func() { errCh <- s.stream(ctx, sc) }()

	select {
	case err := <-errCh:
		shutdownCtx, c2 := context.WithTimeout(context.Background(), 3*time.Second)
		defer c2()
		_ = srv.Shutdown(shutdownCtx)
		if err != context.Canceled {
			return err
		}
	case <-ctx.Done():
	}
	// Keep serving final state until interrupted.
	return srv.ListenAndServe()
}

// stream feeds observations in ReceivedAt order, paced by Speed.
func (s *Server) stream(ctx context.Context, sc model.Scenario) error {
	obs := append([]model.Observation(nil), sc.Observations...)
	model.SortObservations(obs)
	if len(obs) == 0 {
		return fmt.Errorf("feed: empty scenario")
	}
	tick := s.cfg.EvalInterval
	origin := s.started.Add(2 * time.Second)
	simZero := obs[0].ReceivedAt

	// Deliver on a fixed real-time grid so engine ticks and data arrive in the
	// same relationship they would live.
	scale := func(simDur time.Duration) time.Duration {
		return time.Duration(float64(simDur) / s.opt.Speed)
	}

	next := origin
	idx := 0
	var tickAt time.Duration
	for idx < len(obs) {
		wait := time.Until(next)
		if wait > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(wait):
			}
		}
		simNow := simZero.Add(time.Duration(float64(time.Since(origin)) * s.opt.Speed))
		for idx < len(obs) && !obs[idx].ReceivedAt.After(simNow) {
			s.mu.Lock()
			s.eng.Ingest(obs[idx : idx+1])
			s.mu.Unlock()
			idx++
		}
		for tickAt <= simNow.Sub(simZero) {
			s.mu.Lock()
			d := s.eng.Tick(simNow)
			s.mu.Unlock()
			s.emit(d)
			tickAt += tick
		}
		next = time.Now().Add(scale(500 * time.Millisecond))
	}
	// Drain final ticks.
	for i := 0; i < 5; i++ {
		s.mu.Lock()
		d := s.eng.Tick(obs[len(obs)-1].ReceivedAt.Add(time.Duration(i+1) * s.cfg.ResolveAfter))
		s.mu.Unlock()
		s.emit(d)
	}
	return nil
}

func (s *Server) emit(d model.Decision) {
	if len(d.NewAlerts) == 0 && len(d.Updated) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, a := range d.NewAlerts {
		s.alerts = append(s.alerts, a)
		if !s.opt.Quiet {
			fmt.Fprintf(osStderr(), "[%s] %-8s %-20s %s\n",
				a.AlertedAt.Format(time.RFC3339), a.Severity, a.Kind, a.Summary)
		}
	}
	for _, a := range d.Updated {
		s.alerts = append(s.alerts, a)
		if !s.opt.Quiet && (a.Phase == model.PhaseEscalated || a.Phase == model.PhaseResolved) {
			fmt.Fprintf(osStderr(), "[%s] %-8s %-20s %s (%s)\n",
				a.AlertedAt.Format(time.RFC3339), a.Severity, a.Kind, a.Summary, a.Phase)
		}
	}
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSONResponse(w, s.alerts)
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSONResponse(w, s.eng.OpenIncidents())
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.eng.Stats()
	writeJSONResponse(w, map[string]any{
		"observations": st.Observations,
		"withdrawals":  st.Withdrawals,
		"ignored":      st.Ignored,
		"suppressed":   st.Suppressed,
		"resolved":     st.Resolved,
		"escalated":    st.Escalated,
		"downgraded":   st.Downgraded,
		"alerts_total": len(s.alerts),
		"engine_time":  s.eng.Now(),
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSONResponse(w, map[string]any{
		"self_asn":       s.reg.SelfASN,
		"org":            s.reg.OrgName,
		"prefixes":       s.reg.OurPrefixes,
		"vantage_points": s.reg.VPs,
		"detector":       s.cfg,
	})
}

func writeJSONResponse(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
