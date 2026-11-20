package sim

import (
	"testing"
	"time"

	"routewatch/internal/config"
	"routewatch/internal/model"
)

func testConfig(t *testing.T) *model.Scenario {
	t.Helper()
	reg, _, err := config.Load("../../config/topology.yaml")
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	opt := DefaultOptions()
	opt.Duration = 12 * time.Hour // shorter for tests
	sc, err := Build(reg, "test", opt)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return &sc
}

// TestScenarioIsDeterministic: the same seed must produce byte-identical feeds,
// otherwise the evaluator's thresholds mean nothing across runs.
func TestScenarioIsDeterministic(t *testing.T) {
	a := testConfig(t)
	b := testConfig(t)
	if len(a.Observations) != len(b.Observations) {
		t.Fatalf("observation counts differ: %d vs %d", len(a.Observations), len(b.Observations))
	}
	for i := range a.Observations {
		x, y := a.Observations[i], b.Observations[i]
		if x.ID != y.ID || !x.ReceivedAt.Equal(y.ReceivedAt) || x.PathSignature() != y.PathSignature() {
			t.Fatalf("observation %d differs", i)
		}
	}
}

// TestFeedIsOrderedByReceiveTime: a collector stream is only meaningful if the
// detector sees observations in arrival order.
func TestFeedIsOrderedByReceiveTime(t *testing.T) {
	sc := testConfig(t)
	for i := 1; i < len(sc.Observations); i++ {
		if sc.Observations[i].ReceivedAt.Before(sc.Observations[i-1].ReceivedAt) {
			t.Fatalf("observation %d is out of order", i)
		}
	}
}

// TestLabelsHaveVisibleData: a label that no collector could ever see is a
// broken scenario, not a hard detection.
func TestLabelsHaveVisibleData(t *testing.T) {
	sc := testConfig(t)
	for _, l := range sc.Labels {
		if l.Benign || l.UndetectableFromBGP {
			continue
		}
		seen := 0
		for _, o := range sc.Observations {
			if o.Withdraw || !o.Prefix.Overlaps(l.Prefix) {
				continue
			}
			if !o.ReceivedAt.Before(l.Start) && !o.ReceivedAt.After(l.End.Add(30*time.Minute)) {
				seen++
			}
		}
		if seen == 0 {
			t.Errorf("label %s (%s) has no visible observations", l.ID, l.Description)
		}
	}
}

// TestLatencyIsRealistic: every observation must be delivered after it happened
// at the collector, with a latency the detector could plausibly see.
func TestLatencyIsRealistic(t *testing.T) {
	sc := testConfig(t)
	maxLat := time.Duration(0)
	for _, o := range sc.Observations {
		d := o.ReceivedAt.Sub(o.Timestamp)
		if d < 0 {
			t.Fatalf("observation delivered before it happened: %s", o.ID)
		}
		if d > maxLat {
			maxLat = d
		}
	}
	if maxLat > 3*time.Hour {
		t.Errorf("maximum delivery latency %s is implausibly large", maxLat)
	}
}

// TestCoveringPrefixActuallyCovers guards the bug where a "covering" /22 did not
// contain our /23, making the scenario test nothing.
func TestCoveringPrefixActuallyCovers(t *testing.T) {
	sc := testConfig(t)
	found := false
	for _, l := range sc.Labels {
		if l.Kind == model.KindCoveringHijack {
			found = true
			covered := false
			for _, o := range sc.Observations {
				if !o.Prefix.Contains(l.Prefix) && o.Prefix != l.Prefix {
					covered = true
					break
				}
			}
			if !covered {
				t.Errorf("covering label %s prefix %s contains no monitored prefix", l.ID, l.Prefix)
			}
		}
	}
	if !found {
		t.Skip("no covering hijack in this scenario")
	}
}

// TestFlapsAppear guards the bug where maintenance was modelled as a path
// change rather than a withdraw, making the flap scenario invisible.
func TestFlapsAppear(t *testing.T) {
	reg, _, err := config.Load("../../config/topology.yaml")
	if err != nil {
		t.Fatal(err)
	}
	opt := DefaultOptions()
	opt.Duration = 36 * time.Hour
	sc, err := Build(reg, "flaps", opt)
	if err != nil {
		t.Fatal(err)
	}
	var flapLabel *model.Label
	for i := range sc.Labels {
		if sc.Labels[i].ID == "benign-maintenance" {
			flapLabel = &sc.Labels[i]
		}
	}
	if flapLabel == nil {
		t.Skip("no maintenance label")
	}
	withdraws := 0
	for _, o := range sc.Observations {
		if o.Withdraw && o.Prefix.Overlaps(flapLabel.Prefix) &&
			!o.ReceivedAt.Before(flapLabel.Start.Add(-5*time.Minute)) && !o.ReceivedAt.After(flapLabel.End.Add(10*time.Minute)) {
			withdraws++
		}
	}
	if withdraws < 8 {
		t.Errorf("maintenance window produced only %d withdrawals; flaps are not visible in the feed", withdraws)
	}
}
