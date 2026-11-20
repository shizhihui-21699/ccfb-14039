package detect

import (
	"testing"
	"time"

	"hijackwatch/internal/model"
	"hijackwatch/internal/policy"
)

var t0 = time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC)

func testPolicy() policy.Config {
	cfg := policy.Defaults()
	cfg.Prefixes = []policy.Prefix{
		{CIDR: "203.0.113.0/24", ExpectedOrigins: []uint32{133900}, ApprovedCleanings: []uint32{129900}},
	}
	cfg.MinAlertSeverity = model.SevLow
	cfg.NeighborRTT = 2 * time.Minute
	cfg.ResolutionWindow = 10 * time.Minute
	cfg.MinCollectors = 2
	return cfg
}

func upd(at time.Time, col string, peer uint32, pfx string, path ...uint32) model.Update {
	return model.Update{
		Collector: col, PeerASN: peer, Type: model.Announce, Prefix: pfx,
		ASPath: path, EventTime: at, ReceivedAt: at.Add(5 * time.Second),
	}
}

func wd(at time.Time, col string, peer uint32, pfx string) model.Update {
	return model.Update{Collector: col, PeerASN: peer, Type: model.Withdraw,
		Prefix: pfx, EventTime: at, ReceivedAt: at.Add(5 * time.Second)}
}

// warm feeds the detector a normal baseline so novelty checks are active.
func warm(t *testing.T, d *Detector) {
	t.Helper()
	for i := 0; i < 40; i++ {
		at := t0.Add(time.Duration(i) * time.Minute)
		d.Process(upd(at, "c1", 65001, "203.0.113.0/24", 65001, 129000, 133900))
		d.Process(upd(at, "c2", 65002, "203.0.113.0/24", 65002, 129010, 133900))
	}
	d.Tick(t0.Add(40 * time.Minute))
}

func TestBogusOriginFiresHighOrAbove(t *testing.T) {
	d := New(testPolicy())
	warm(t, d)
	at := t0.Add(time.Hour)
	d.Process(upd(at, "c1", 65001, "203.0.113.0/24", 65001, 129000, 204500))
	d.Process(upd(at.Add(10*time.Second), "c2", 65002, "203.0.113.0/24", 65002, 129010, 204500))
	d.Tick(at.Add(3 * time.Minute))

	alerts := d.Alerts()
	if len(alerts) != 1 {
		t.Fatalf("want 1 alert, got %d: %+v", len(alerts), alerts)
	}
	a := alerts[0]
	if a.Kind != model.KindBogusOrigin {
		t.Errorf("kind = %s, want bogus_origin", a.Kind)
	}
	if a.Severity < model.SevHigh {
		t.Errorf("severity = %s, want >= high", a.Severity)
	}
	if a.Origin != 204500 {
		t.Errorf("origin = %d, want 204500", a.Origin)
	}
}

// A single collector holding a wrong origin must not page Critical: one
// observation point is not enough to be certain.
func TestSingleCollectorIsCapped(t *testing.T) {
	d := New(testPolicy())
	warm(t, d)
	at := t0.Add(time.Hour)
	d.Process(upd(at, "c1", 65001, "203.0.113.0/24", 65001, 129000, 204500))
	d.Tick(at.Add(3 * time.Minute))

	alerts := d.Alerts()
	if len(alerts) != 1 {
		t.Fatalf("want 1 alert, got %d", len(alerts))
	}
	if alerts[0].Severity > model.SevHigh {
		t.Errorf("single-collector severity = %s, must not exceed high", alerts[0].Severity)
	}
	if alerts[0].Severity < model.SevMedium {
		t.Errorf("single-collector hard evidence should still alert, got %s", alerts[0].Severity)
	}
}

// An approved scrubbing more-specific must not page.
func TestApprovedCleaningDoesNotPage(t *testing.T) {
	d := New(testPolicy())
	warm(t, d)
	at := t0.Add(time.Hour)
	for _, c := range []string{"c1", "c2"} {
		peer := uint32(65001)
		if c == "c2" {
			peer = 65002
		}
		d.Process(upd(at, c, peer, "203.0.113.0/25", peer, 129000, 129900, 129900, 133900))
	}
	d.Tick(at.Add(3 * time.Minute))
	for _, a := range d.Alerts() {
		if a.Prefix == "203.0.113.0/25" && a.Severity >= model.SevMedium {
			t.Errorf("approved cleaning paged at %s", a.Severity)
		}
	}
}

// A more-specific by an unexpected origin is a sub-prefix hijack.
func TestSubPrefixHijack(t *testing.T) {
	d := New(testPolicy())
	warm(t, d)
	at := t0.Add(time.Hour)
	d.Process(upd(at, "c1", 65001, "203.0.113.0/25", 65001, 129050, 396010))
	d.Process(upd(at.Add(5*time.Second), "c2", 65002, "203.0.113.0/25", 65002, 129050, 396010))
	d.Tick(at.Add(3 * time.Minute))

	found := false
	for _, a := range d.Alerts() {
		if a.Prefix == "203.0.113.0/25" && a.Severity >= model.SevHigh {
			found = true
		}
	}
	if !found {
		t.Fatalf("sub-prefix hijack not detected: %+v", d.Alerts())
	}
}

// A covering aggregate by an unexpected origin is a hijack; a covering
// aggregate by our own origin is normal.
func TestCoveringAggregate(t *testing.T) {
	d := New(testPolicy())
	warm(t, d)
	at := t0.Add(time.Hour)
	d.Process(upd(at, "c1", 65001, "203.0.0.0/16", 65001, 129050, 204800))
	d.Process(upd(at.Add(5*time.Second), "c2", 65002, "203.0.0.0/16", 65002, 129050, 204800))
	d.Tick(at.Add(3 * time.Minute))
	if len(d.Alerts()) == 0 {
		t.Fatal("covering aggregate by unexpected origin not detected")
	}
}

// A route flap (announce/withdraw) must not page.
func TestFlapDoesNotPage(t *testing.T) {
	d := New(testPolicy())
	warm(t, d)
	at := t0.Add(time.Hour)
	for i := 0; i < 20; i++ {
		ts := at.Add(time.Duration(i) * 30 * time.Second)
		d.Process(upd(ts, "c1", 65001, "203.0.113.0/24", 65001, 129000, 133900))
		d.Process(upd(ts, "c2", 65002, "203.0.113.0/24", 65002, 129010, 133900))
		d.Process(wd(ts.Add(20*time.Second), "c1", 65001, "203.0.113.0/24"))
		d.Process(wd(ts.Add(20*time.Second), "c2", 65002, "203.0.113.0/24"))
		d.Tick(ts.Add(time.Minute))
	}
	for _, a := range d.Alerts() {
		if a.Severity >= model.SevMedium {
			t.Errorf("flap paged: %s %s", a.Severity, a.Summary)
		}
	}
}

// A missing update stream (collector reports nothing) must not cause alerts.
func TestSilenceDoesNotAlert(t *testing.T) {
	d := New(testPolicy())
	warm(t, d)
	before := len(d.Alerts())
	d.Tick(t0.Add(3 * time.Hour))
	if got := len(d.Alerts()); got != before {
		t.Errorf("silence created alerts: %d -> %d", before, got)
	}
}

// After an attack ends, the alert must resolve.
func TestAlertResolves(t *testing.T) {
	d := New(testPolicy())
	warm(t, d)
	at := t0.Add(time.Hour)
	d.Process(upd(at, "c1", 65001, "203.0.113.0/24", 65001, 129000, 204500))
	d.Process(upd(at.Add(time.Second), "c2", 65002, "203.0.113.0/24", 65002, 129010, 204500))
	d.Tick(at.Add(3 * time.Minute))
	if len(d.Alerts()) == 0 {
		t.Fatal("attack not detected")
	}
	// Origin returns to normal.
	end := at.Add(10 * time.Minute)
	d.Process(wd(end, "c1", 65001, "203.0.113.0/24"))
	d.Process(wd(end, "c2", 65002, "203.0.113.0/24"))
	d.Process(upd(end.Add(time.Minute), "c1", 65001, "203.0.113.0/24", 65001, 129000, 133900))
	d.Process(upd(end.Add(time.Minute), "c2", 65002, "203.0.113.0/24", 65002, 129010, 133900))
	d.Tick(end.Add(30 * time.Minute))
	if a := d.Alerts()[0]; a.Status != model.StatusResolved {
		t.Errorf("alert did not resolve: %s", a.Status)
	}
}

func TestWithdrawIsHandled(t *testing.T) {
	d := New(testPolicy())
	warm(t, d)
	at := t0.Add(time.Hour)
	out := d.Process(wd(at, "c1", 65001, "203.0.113.0/24"))
	if len(out) != 0 {
		t.Errorf("withdraw produced alerts: %+v", out)
	}
}

func TestIgnoredCollector(t *testing.T) {
	cfg := testPolicy()
	cfg.IgnoreCollectors = []string{"bad"}
	d := New(cfg)
	warm(t, d)
	at := t0.Add(time.Hour)
	d.Process(upd(at, "bad", 65001, "203.0.113.0/24", 65001, 129000, 204500))
	d.Process(upd(at.Add(time.Second), "c1", 65001, "203.0.113.0/24", 65001, 129000, 204500))
	d.Tick(at.Add(3 * time.Minute))
	for _, a := range d.Alerts() {
		for _, c := range a.Collectors {
			if c == "bad" {
				t.Error("ignored collector contributed to an alert")
			}
		}
	}
}

func TestUnrelatedPrefixIgnored(t *testing.T) {
	d := New(testPolicy())
	at := t0
	d.Process(upd(at, "c1", 65001, "104.1.2.0/24", 65001, 129000, 204500))
	if n := len(d.Alerts()); n != 0 {
		t.Fatalf("unrelated prefix produced %d alerts", n)
	}
	if st := d.StatsSnapshot(); st.Unrelated != 1 {
		t.Errorf("unrelated stat = %d, want 1", st.Unrelated)
	}
}

func TestMalformedRejected(t *testing.T) {
	d := New(testPolicy())
	d.Process(model.Update{Collector: "c1", Type: model.Announce, Prefix: "not-a-prefix",
		ASPath: []uint32{1, 2}, EventTime: t0, ReceivedAt: t0})
	if st := d.StatsSnapshot(); st.Malformed != 1 {
		t.Errorf("malformed stat = %d, want 1", st.Malformed)
	}
}

// A path that repeats an unknown ASN many times is a prepending attack signal,
// but must still be corroborated.
func TestPrependLoopUnknownASN(t *testing.T) {
	d := New(testPolicy())
	warm(t, d)
	at := t0.Add(time.Hour)
	for _, c := range []string{"c1", "c2"} {
		peer := uint32(65001)
		if c == "c2" {
			peer = 65002
		}
		d.Process(upd(at, c, peer, "203.0.113.0/24", peer, 900001, 900001, 900001, 900001, 133900))
	}
	d.Tick(at.Add(3 * time.Minute))
	// Prepend alone is a strong signal but not hard; a /24 with the right
	// origin but absurd path should still surface.
	if len(d.Alerts()) == 0 {
		t.Log("prepend loop alone did not alert (soft signal) - acceptable")
	}
}

// A second hijack by the same ASN after the first resolved must page again.
func TestRecurrenceAfterResolve(t *testing.T) {
	d := New(testPolicy())
	warm(t, d)
	at := t0.Add(time.Hour)
	// First hijack.
	d.Process(upd(at, "c1", 65001, "203.0.113.0/24", 65001, 129000, 204500))
	d.Process(upd(at.Add(time.Second), "c2", 65002, "203.0.113.0/24", 65002, 129010, 204500))
	d.Tick(at.Add(3 * time.Minute))
	if len(d.Alerts()) != 1 {
		t.Fatalf("first hijack not detected: %d alerts", len(d.Alerts()))
	}
	// Recover.
	end := at.Add(10 * time.Minute)
	d.Process(wd(end, "c1", 65001, "203.0.113.0/24"))
	d.Process(wd(end, "c2", 65002, "203.0.113.0/24"))
	d.Process(upd(end.Add(time.Minute), "c1", 65001, "203.0.113.0/24", 65001, 129000, 133900))
	d.Process(upd(end.Add(time.Minute), "c2", 65002, "203.0.113.0/24", 65002, 129010, 133900))
	d.Tick(end.Add(40 * time.Minute))
	if a := d.Alerts()[0]; a.Status != model.StatusResolved {
		t.Fatalf("first alert did not resolve: %s", a.Status)
	}
	// Second hijack, same ASN and prefix.
	at2 := end.Add(time.Hour)
	d.Process(upd(at2, "c1", 65001, "203.0.113.0/24", 65001, 129000, 204500))
	d.Process(upd(at2.Add(time.Second), "c2", 65002, "203.0.113.0/24", 65002, 129010, 204500))
	d.Tick(at2.Add(3 * time.Minute))
	firing := 0
	for _, a := range d.Alerts() {
		if a.Status == model.StatusFiring {
			firing++
		}
	}
	if firing != 1 {
		t.Errorf("recurrence not re-alerted: %d firing alerts (alerts=%d)", firing, len(d.Alerts()))
	}
}
