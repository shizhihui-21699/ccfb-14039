package replay

import (
	"fmt"
	"testing"

	"hijackwatch/internal/detect"
	"hijackwatch/internal/sim"
)

// TestDatasetRegression replays the generated dataset and asserts the detector
// meets the quality bar on it: every attack caught, no benign operation paged.
// Update the seed list as scenarios change; a failure here is a real
// regression in the decision policy, not flakiness (the generator is
// deterministic for a given seed).
func TestDatasetRegression(t *testing.T) {
	t.Parallel()
	for _, seed := range []int64{1, 7, 42, sim.DefaultOptions().Seed} {
		seed := seed
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			t.Parallel()
			opt := sim.DefaultOptions()
			opt.Seed = seed
			ds, err := sim.Build(opt)
			if err != nil {
				t.Fatalf("build: %v", err)
			}
			res := Run(ds, detect.New(ds.Policy))
			m := Score(res)
			if m.FalseNegatives != 0 {
				t.Errorf("missed attacks %v", m.MissedIDs)
			}
			if m.FalsePositives != 0 {
				t.Errorf("paged benign operations %v", m.FalseIDs)
			}
			if m.TruePositives < 6 {
				t.Errorf("only %d true positives", m.TruePositives)
			}
			for _, id := range m.AmbiguousHits {
				t.Logf("ambiguous benign event %s reached Medium+ (accepted)", id)
			}
		})
	}
}

// TestLatency checks the detection lag on clear-cut attacks stays small.
func TestLatency(t *testing.T) {
	ds, _ := sim.Build(sim.DefaultOptions())
	res := Run(ds, detect.New(ds.Policy))
	for id, lat := range res.Latency {
		if lat > 5*60*1e9 {
			t.Errorf("%s detected after %v, want under 5m", id, lat)
		}
	}
}

// TestBenignCeiling asserts that legitimate operations never exceed their
// stated maximum severity in the dataset.
func TestBenignCeiling(t *testing.T) {
	ds, _ := sim.Build(sim.DefaultOptions())
	res := Run(ds, detect.New(ds.Policy))
	for _, o := range res.Outcomes {
		if o.Incident.ExpectAlert || o.Incident.Ambiguous {
			continue
		}
		ceil, err := parseSeverity(o.Incident.MaxSeverity)
		if err != nil {
			continue
		}
		if o.MaxSeverity > ceil {
			t.Errorf("%s reached %s, ceiling %s", o.Incident.ID, o.MaxSeverity, ceil)
		}
	}
}
