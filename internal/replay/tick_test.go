package replay

import (
	"testing"
	"time"

	"hijackwatch/internal/detect"
	"hijackwatch/internal/sim"
)

// Guard against a regression where the tick clock started at the zero time and
// burned millions of no-op iterations (or mis-set the detector clock).
func TestReplayClockStartsAtDatasetStart(t *testing.T) {
	ds, _ := sim.Build(sim.DefaultOptions())
	det := detect.New(ds.Policy)
	start := time.Now()
	Run(ds, det)
	if el := time.Since(start); el > 5*time.Second {
		t.Fatalf("replay took %v, clock likely starts before the dataset", el)
	}
	if det.Now().Before(ds.Start) {
		t.Errorf("detector clock %s is before dataset start %s", det.Now(), ds.Start)
	}
	if det.Now().After(ds.End.Add(time.Hour)) {
		t.Errorf("detector clock %s ran well past dataset end %s", det.Now(), ds.End)
	}
}
