package sim

import (
	"net/netip"
	"testing"
	"time"

	"hijackwatch/internal/model"
)

func TestBuildDeterministic(t *testing.T) {
	a, err := Build(DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	b, _ := Build(DefaultOptions())
	if len(a.Updates) != len(b.Updates) {
		t.Fatalf("update count differs: %d vs %d", len(a.Updates), len(b.Updates))
	}
	for i := range a.Updates {
		if a.Updates[i].Prefix != b.Updates[i].Prefix || a.Updates[i].ReceivedAt != b.Updates[i].ReceivedAt {
			t.Fatalf("update %d differs", i)
		}
	}
}

func TestBuildContinuity(t *testing.T) {
	ds, err := Build(DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	if len(ds.Updates) < 1000 {
		t.Fatalf("only %d updates generated", len(ds.Updates))
	}
	prev := time.Time{}
	for _, u := range ds.Updates {
		if u.ReceivedAt.Before(prev) {
			t.Fatalf("updates not ordered by received_at at %s", u.Prefix)
		}
		prev = u.ReceivedAt
		if u.ReceivedAt.Before(u.EventTime) {
			t.Fatalf("received before event for %s", u.Prefix)
		}
	}
	// Every attack in the truth set should have its signature present in the
	// stream.
	for _, inc := range ds.Incidents {
		if !inc.ExpectAlert {
			continue
		}
		wantOrigin := inc.Origin
		found := false
		for _, u := range ds.Updates {
			if u.Prefix != inc.Prefix || u.Type != model.Announce {
				continue
			}
			if o, _ := u.Origin(); o == wantOrigin {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("incident %s: no announcement with origin %d for %s", inc.ID, wantOrigin, inc.Prefix)
		}
	}
}

func TestAllIncidentsAccountedFor(t *testing.T) {
	ds, _ := Build(DefaultOptions())
	var attacks, benign int
	for _, inc := range ds.Incidents {
		if inc.ExpectAlert {
			attacks++
		} else {
			benign++
		}
	}
	if attacks < 5 {
		t.Errorf("only %d attack scenarios", attacks)
	}
	if benign < 8 {
		t.Errorf("only %d benign scenarios", benign)
	}
}

func TestPolicyCoversPrefixes(t *testing.T) {
	ds, _ := Build(DefaultOptions())
	regs := ds.Policy.Registered()
	for _, inc := range ds.Incidents {
		p, err := netip.ParsePrefix(inc.Prefix)
		if err != nil {
			t.Fatalf("incident %s bad prefix: %v", inc.ID, err)
		}
		_, rel, ok := ds.Policy.MatchPrefix(p, regs)
		if !ok || rel == model.Unrelated {
			t.Errorf("incident %s prefix %s not covered by policy", inc.ID, inc.Prefix)
		}
	}
}
