package eval

import (
	"testing"
	"time"

	"routewatch/internal/config"
	"routewatch/internal/model"
	"routewatch/internal/sim"
)

// TestEndToEndScenarioMetrics is the regression test for the whole pipeline.
// It asserts on the properties that matter operationally, not on exact numbers:
// every detectable attack is caught, nothing legitimate pages, and no alert is
// unaccounted for.
func TestEndToEndScenarioMetrics(t *testing.T) {
	reg, cfg, err := config.Load("../../config/topology.yaml")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	opt := sim.DefaultOptions()
	opt.Duration = 36 * time.Hour
	sc, err := sim.Build(reg, "e2e", opt)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	res, err := Replay(reg, cfg, sc, Options{})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	m := res.Metrics()

	if m.Detected != m.HostileLabels {
		for _, l := range res.Missed {
			t.Errorf("missed hostile event %s (%s)", l.ID, l.Description)
		}
		t.Errorf("detected %d/%d hostile events", m.Detected, m.HostileLabels)
	}
	if len(res.FalsePositives) > 0 {
		for _, a := range res.FalsePositives {
			t.Errorf("false positive: %s %s %s (score %d)", a.Severity, a.Kind, a.Prefix, a.Score)
		}
	}
	if len(res.BenignViolations) > 0 {
		for _, a := range res.BenignViolations {
			t.Errorf("legitimate operation raised %s: %s %s", a.Severity, a.Kind, a.Prefix)
		}
	}
	// A hijack that is visible should be caught within minutes, not hours. The
	// one deliberately permitted exception is single-collector evidence, which
	// is held for a long time on purpose before it is allowed to page.
	for id, ttd := range res.TimeToDetect {
		if ttd > 30*time.Minute && id != "hijack-single-vp" {
			t.Errorf("%s took %s to detect; that is too slow for a visible hijack", id, ttd)
		}
	}
	t.Logf("%s", FormatMetrics(m))
}

// TestScoreMatchingRules pins the evaluator's own semantics, since a scoring
// bug can make a broken detector look perfect.
func TestScoreMatchingRules(t *testing.T) {
	start := time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)
	p := model.MustPrefix("198.51.100.0/23")
	hostile := model.Label{ID: "h", Kind: model.KindOriginHijack, Prefix: p, Start: start, End: start.Add(time.Hour), MustAlert: true}
	benign := model.Label{ID: "b", Kind: model.KindScrubbing, Prefix: p, Start: start, End: start.Add(time.Hour), Benign: true}

	t.Run("late detection still counts", func(t *testing.T) {
		res := Result{Alerts: []model.Alert{{
			ID: "a1", Kind: model.KindOriginHijack, Severity: model.SevCritical, Prefix: p,
			AlertedAt: start.Add(25 * time.Minute),
		}}}
		Score(&res, []model.Label{hostile}, time.Time{})
		if len(res.Detections) != 1 {
			t.Fatalf("late but valid detection not counted: %+v", res.Missed)
		}
	})

	t.Run("after the label ends is a miss", func(t *testing.T) {
		res := Result{Alerts: []model.Alert{{
			ID: "a1", Kind: model.KindOriginHijack, Severity: model.SevCritical, Prefix: p,
			AlertedAt: start.Add(3 * time.Hour),
		}}}
		Score(&res, []model.Label{hostile}, time.Time{})
		if len(res.Detections) != 0 {
			t.Fatal("an alert hours after the label should not count as detection")
		}
	})

	t.Run("a real attack during a benign window is not excused", func(t *testing.T) {
		res := Result{Alerts: []model.Alert{{
			ID: "a1", Kind: model.KindOriginHijack, Severity: model.SevCritical, Prefix: p,
			AlertedAt: start.Add(10 * time.Minute),
		}}}
		// Both labels overlap in time. Hostile matching runs first, so the
		// attack must be credited as a detection, not counted against the
		// benign label.
		Score(&res, []model.Label{hostile, benign}, time.Time{})
		if len(res.Detections) != 1 {
			t.Fatal("attack overlapping a benign window was not credited")
		}
		if len(res.BenignViolations) != 0 {
			t.Fatal("attack was scored as a benign violation")
		}
	})

	t.Run("blind spot is neither detected nor missed", func(t *testing.T) {
		blind := hostile
		blind.ID = "blind"
		blind.MustAlert = false
		blind.UndetectableFromBGP = true
		res := Result{}
		Score(&res, []model.Label{blind}, time.Time{})
		if len(res.BlindSpots) != 1 || len(res.Missed) != 0 || len(res.Detections) != 0 {
			t.Fatalf("blind spot handled wrongly: blind=%d missed=%d detected=%d",
				len(res.BlindSpots), len(res.Missed), len(res.Detections))
		}
	})

	t.Run("info alert on a benign label is not a violation", func(t *testing.T) {
		res := Result{Alerts: []model.Alert{{
			ID: "a1", Kind: model.KindScrubbing, Severity: model.SevInfo, Prefix: p,
			AlertedAt: start.Add(10 * time.Minute),
		}}}
		Score(&res, []model.Label{benign}, time.Time{})
		if len(res.BenignViolations) != 0 {
			t.Fatal("INFO audit entry counted as a benign violation")
		}
		if len(res.FalsePositives) != 0 {
			t.Fatal("INFO alert counted as a false positive")
		}
	})
}

// TestReplayRejectsStepLargerThanInterval: silently skipping ticks would
// invalidate every latency measurement, so it is an error.
func TestReplayRejectsStepLargerThanInterval(t *testing.T) {
	reg, cfg, err := config.Load("../../config/topology.yaml")
	if err != nil {
		t.Fatal(err)
	}
	sc := model.Scenario{Name: "x", Start: time.Now(), End: time.Now().Add(time.Hour)}
	_, err = Replay(reg, cfg, sc, Options{Step: time.Hour})
	if err == nil {
		t.Fatal("expected an error for a step larger than the eval interval")
	}
}
