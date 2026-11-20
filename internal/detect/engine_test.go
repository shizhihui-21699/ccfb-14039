package detect

import (
	"testing"
	"time"

	"routewatch/internal/model"
	"routewatch/internal/registry"
)

// These tests encode the design decisions in engine.go as executable claims.
// Each one corresponds to a specific failure mode the service must not have.

func asns(t *testing.T, raw ...string) []model.ASN {
	t.Helper()
	out := make([]model.ASN, len(raw))
	for i, s := range raw {
		a, err := model.ParseASN(s)
		if err != nil {
			t.Fatalf("ParseASN(%q): %v", s, err)
		}
		out[i] = a
	}
	return out
}

var (
	primary = model.MustPrefix("198.51.100.0/23")
	anycast = model.MustPrefix("203.0.113.0/24")
	vpNames = []string{"vp-a", "vp-b", "vp-c", "vp-d", "vp-e", "vp-f"}
)

func testRegistry(t *testing.T) *registry.Registry {
	t.Helper()
	var vps []registry.VPInfo
	for i, n := range vpNames {
		region := "r" + string(rune('0'+i%3))
		vps = append(vps, registry.VPInfo{Name: n, Region: region, ASN: 1299})
	}
	r := &registry.Registry{
		SelfASN:     400001,
		OurPrefixes: []model.Prefix{primary, anycast},
		VPs:         vps,
		ASNs: []registry.ASInfo{
			{ASN: 400001, Role: registry.RoleSelf, Upstreams: asns(t, "AS3356", "AS1299")},
			{ASN: 400002, Role: registry.RoleAnycast, AuthorizedFor: []model.Prefix{anycast}},
			{ASN: 400666, Role: registry.RoleHosting, Upstreams: asns(t, "AS1299")},
			{ASN: 400777, Role: registry.RoleUnknown, Upstreams: asns(t, "AS174"), NoTransit: true},
			{ASN: 400999, Role: registry.RoleScrubber, Upstreams: asns(t, "AS1299", "AS3356")},
			{ASN: 3356, Role: registry.RoleUpstream, Upstreams: asns(t, "AS174"), Downstreams: asns(t, "AS400001")},
			{ASN: 1299, Role: registry.RoleUpstream, Upstreams: asns(t, "AS174"), Downstreams: asns(t, "AS400001", "AS400666")},
			{ASN: 174, Role: registry.RoleUpstream, Downstreams: asns(t, "AS3356", "AS1299", "AS400777")},
			{ASN: 209, Role: registry.RoleUpstream, Upstreams: asns(t, "AS174")},
		},
		ROAs: []registry.ROA{
			{Prefix: primary, MaxLen: 24, Origin: 400001},
		},
		Scrubs: []registry.ScrubAgreement{
			{Prefix: primary, Scrubber: 400999, Reasons: []string{"64500:666"}},
		},
		Anycast: []registry.AnycastOrigin{
			{Prefix: anycast, Origins: asns(t, "AS400001", "AS400002")},
		},
	}
	if err := r.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return r
}

var startTime = time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC)

// harness drives an engine the way the service does: observations in on every
// tick, then a tick.
type harness struct {
	t   *testing.T
	eng *Engine
	now time.Time
	all []model.Alert
	vps []string
}

func newHarness(t *testing.T, reg *registry.Registry, cfg Config) *harness {
	t.Helper()
	cfg.Validate()
	if cfg.EvalInterval == 0 {
		cfg.EvalInterval = 30 * time.Second
	}
	eng := New(reg, cfg, startTime)
	eng.Start(startTime)
	return &harness{t: t, eng: eng, now: startTime, vps: vpNames}
}

// steady emits a route for one prefix at every VP for the next n ticks.
func (h *harness) steady(p model.Prefix, origin model.ASN, path []model.ASN, n int) {
	for i := 0; i < n; i++ {
		var obs []model.Observation
		for _, vp := range h.vps {
			obs = append(obs, model.Observation{
				ID: vp + h.now.String(), VP: vp, VPASN: 1299, Prefix: p, Origin: origin,
				ASPath: path, Timestamp: h.now, ReceivedAt: h.now,
			})
		}
		h.eng.Ingest(obs)
		d := h.eng.Tick(h.now)
		h.all = append(h.all, d.NewAlerts...)
		h.now = h.now.Add(h.eng.cfg.EvalInterval)
	}
}

// steadyAt emits a route from a subset of VPs.
func (h *harness) steadyAt(p model.Prefix, origin model.ASN, path []model.ASN, vps []string, n int) {
	for i := 0; i < n; i++ {
		var obs []model.Observation
		for _, vp := range vps {
			obs = append(obs, model.Observation{
				ID: vp + h.now.String(), VP: vp, VPASN: 1299, Prefix: p, Origin: origin,
				ASPath: path, Timestamp: h.now, ReceivedAt: h.now,
			})
		}
		h.eng.Ingest(obs)
		d := h.eng.Tick(h.now)
		h.all = append(h.all, d.NewAlerts...)
		h.now = h.now.Add(h.eng.cfg.EvalInterval)
	}
}

// mixed emits one route per VP, each VP given its own path.
func (h *harness) mixed(p model.Prefix, origin model.ASN, pathFor map[string][]model.ASN, n int) {
	for i := 0; i < n; i++ {
		var obs []model.Observation
		for vp, path := range pathFor {
			obs = append(obs, model.Observation{
				ID: vp + h.now.String(), VP: vp, VPASN: 1299, Prefix: p, Origin: origin,
				ASPath: path, Timestamp: h.now, ReceivedAt: h.now,
			})
		}
		h.eng.Ingest(obs)
		d := h.eng.Tick(h.now)
		h.all = append(h.all, d.NewAlerts...)
		h.now = h.now.Add(h.eng.cfg.EvalInterval)
	}
}

func (h *harness) find(kind model.Kind) *model.Alert {
	for i := range h.all {
		if h.all[i].Kind == kind {
			return &h.all[i]
		}
	}
	return nil
}

func (h *harness) warnings() []model.Alert {
	var out []model.Alert
	for _, a := range h.all {
		if a.Severity >= model.SevWarning {
			out = append(out, a)
		}
	}
	return out
}

// TestNormalTrafficIsSilent is the most important test in the package: the
// detector must produce nothing at all for ordinary announcements.
func TestNormalTrafficIsSilent(t *testing.T) {
	h := newHarness(t, testRegistry(t), Defaults())
	h.steady(primary, 400001, asns(t, "AS174", "AS3356", "AS400001"), 40)
	h.steady(anycast, 400001, asns(t, "AS1299", "AS400001"), 40)
	if got := h.warnings(); len(got) != 0 {
		t.Fatalf("normal traffic raised %d alert(s): %+v", len(got), got[0])
	}
}

// TestPrependingIsNotAnomalous guards against the classic false positive.
func TestPrependingIsNotAnomalous(t *testing.T) {
	h := newHarness(t, testRegistry(t), Defaults())
	h.steady(primary, 400001, asns(t, "AS174", "AS3356", "AS400001", "AS400001", "AS400001"), 40)
	if got := h.warnings(); len(got) != 0 {
		t.Fatalf("prepending raised %d alert(s): %+v", len(got), got[0])
	}
}

// TestOriginHijackIsCritical: a foreign origin on our prefix is unambiguous.
func TestOriginHijackIsCritical(t *testing.T) {
	h := newHarness(t, testRegistry(t), Defaults())
	h.steady(primary, 400001, asns(t, "AS174", "AS3356", "AS400001"), 20)
	h.steady(primary, 400666, asns(t, "AS1299", "AS400666"), 8)
	a := h.find(model.KindOriginHijack)
	if a == nil {
		t.Fatal("origin hijack was not detected")
	}
	if a.Severity != model.SevCritical {
		t.Errorf("severity = %v, want CRITICAL", a.Severity)
	}
	if a.SuspectedOrigin != 400666 {
		t.Errorf("suspected origin = %v, want AS400666", a.SuspectedOrigin)
	}
}

// TestSubPrefixHijack: a more-specific inside our space is a hijack even
// though it is not the same prefix.
func TestSubPrefixHijack(t *testing.T) {
	h := newHarness(t, testRegistry(t), Defaults())
	sub := model.MustPrefix("198.51.100.0/24")
	h.steady(primary, 400001, asns(t, "AS174", "AS3356", "AS400001"), 20)
	h.steady(sub, 400666, asns(t, "AS1299", "AS400666"), 8)
	a := h.find(model.KindSubPrefixHijack)
	if a == nil {
		t.Fatal("sub-prefix hijack was not detected")
	}
	if a.Severity < model.SevWarning {
		t.Errorf("severity = %v, want WARNING or better", a.Severity)
	}
}

// TestRegisteredAnycastIsQuiet: a second origin registered for a specific
// prefix must not page.
func TestRegisteredAnycastIsQuiet(t *testing.T) {
	h := newHarness(t, testRegistry(t), Defaults())
	h.steady(anycast, 400001, asns(t, "AS1299", "AS400001"), 20)
	h.steady(anycast, 400002, asns(t, "AS1299", "AS400002"), 20)
	if got := h.warnings(); len(got) != 0 {
		t.Fatalf("registered anycast raised %d alert(s): %+v", len(got), got[0])
	}
}

// TestAnycastAuthorizationDoesNotLeak: the same ASN announcing a different
// prefix is a hijack.
func TestAnycastAuthorizationDoesNotLeak(t *testing.T) {
	h := newHarness(t, testRegistry(t), Defaults())
	h.steady(primary, 400002, asns(t, "AS1299", "AS400002"), 12)
	if len(h.warnings()) == 0 {
		t.Fatal("anycast ASN announcing unrelated space was not flagged")
	}
}

// TestScrubbingRequiresCommunity: the scrubber's ASN alone is not enough;
// without the agreed cleaning community it is a hijack.
func TestScrubbingRequiresCommunity(t *testing.T) {
	h := newHarness(t, testRegistry(t), Defaults())
	h.steady(primary, 400999, asns(t, "AS1299", "AS3356", "AS400999"), 10)
	if len(h.warnings()) == 0 {
		t.Fatal("scrubber without cleaning community was not flagged")
	}
}

// TestScrubbingWithCommunityIsInfo: the full scrubbing signature is an audit
// entry, not a page.
func TestScrubbingWithCommunityIsInfo(t *testing.T) {
	h := newHarness(t, testRegistry(t), Defaults())
	for i := 0; i < 10; i++ {
		var obs []model.Observation
		for _, vp := range h.vps {
			obs = append(obs, model.Observation{
				ID: vp + h.now.String(), VP: vp, VPASN: 1299, Prefix: primary, Origin: 400999,
				ASPath: asns(t, "AS1299", "AS3356", "AS400999"), Communities: []string{"64500:666"},
				Timestamp: h.now, ReceivedAt: h.now,
			})
		}
		h.eng.Ingest(obs)
		d := h.eng.Tick(h.now)
		h.all = append(h.all, d.NewAlerts...)
		h.now = h.now.Add(h.eng.cfg.EvalInterval)
	}
	if len(h.warnings()) != 0 {
		t.Fatalf("scrubbing session raised WARNING+: %+v", h.warnings()[0])
	}
	a := h.find(model.KindScrubbing)
	if a == nil {
		t.Fatal("scrubbing session produced no audit entry")
	}
	if a.Severity != model.SevInfo {
		t.Errorf("severity = %v, want INFO", a.Severity)
	}
}

// TestFleetWideChangeIsNotAHijack: a change every VP sees at once is a transit
// switch. This is the propagation/scope decision.
func TestFleetWideChangeIsNotAHijack(t *testing.T) {
	cfg := Defaults()
	cfg.PropagationGrace = 5 * time.Minute
	h := newHarness(t, testRegistry(t), cfg)
	h.steady(primary, 400001, asns(t, "AS1299", "AS400001"), 20)
	// Every VP moves to a different *legitimate* upstream.
	h.steady(primary, 400001, asns(t, "AS3356", "AS174", "AS400001"), 20)
	if got := h.warnings(); len(got) != 0 {
		t.Fatalf("fleet-wide transit switch raised WARNING+: %+v", got[0])
	}
}

// TestRegionalPathHijackIsSlow: a plausible path change limited to a minority
// must not page immediately, but must page once it persists.
func TestRegionalPathHijackIsSlow(t *testing.T) {
	cfg := Defaults()
	cfg.PropagationGrace = 5 * time.Minute
	h := newHarness(t, testRegistry(t), cfg)
	paths := map[string][]model.ASN{}
	for _, vp := range h.vps {
		paths[vp] = asns(t, "AS1299", "AS400001")
	}
	h.mixed(primary, 400001, paths, 20)
	// Two of six VPs now attach through AS209, a carrier we do not use.
	twoVPs := vpNames[:2]
	for _, vp := range twoVPs {
		paths[vp] = asns(t, "AS174", "AS209", "AS400001")
	}
	h.mixed(primary, 400001, paths, 4)
	if got := h.warnings(); len(got) != 0 {
		t.Fatalf("path change alerted within the grace period: %+v", got[0])
	}
	h.mixed(primary, 400001, paths, 40)
	if len(h.warnings()) == 0 {
		t.Fatal("persistent regional path change never alerted")
	}
	a := h.find(model.KindPathHijack)
	if a == nil {
		t.Fatal("no path_hijack alert")
	}
	if a.Severity != model.SevWarning {
		t.Errorf("severity = %v, want WARNING (plausible path, not proven)", a.Severity)
	}
}

// TestStubInTransitIsCritical: a structurally impossible path is proof.
func TestStubInTransitIsCritical(t *testing.T) {
	cfg := Defaults()
	cfg.PropagationGrace = 5 * time.Minute
	h := newHarness(t, testRegistry(t), cfg)
	h.steady(primary, 400001, asns(t, "AS174", "AS1299", "AS400001"), 20)
	// A stub (AS400777) never transits; its presence mid-path is a forgery and
	// must page immediately, without waiting for propagation.
	h.steady(primary, 400001, asns(t, "AS3356", "AS174", "AS400777", "AS400001"), 3)
	a := h.find(model.KindPathHijack)
	if a == nil {
		t.Fatal("forged path with a stub in transit was not detected")
	}
	if a.Severity != model.SevCritical {
		t.Errorf("severity = %v, want CRITICAL for a structurally impossible path", a.Severity)
	}
}

// TestSingleVPRequiresPersistence: one collector is weak evidence and must not
// page on the same schedule as two.
func TestSingleVPRequiresPersistence(t *testing.T) {
	cfg := Defaults()
	cfg.PropagationGrace = 5 * time.Minute
	cfg.SingleVPMinAge = 10 * time.Minute
	h := newHarness(t, testRegistry(t), cfg)
	paths := map[string][]model.ASN{}
	for _, vp := range h.vps {
		paths[vp] = asns(t, "AS1299", "AS400001")
	}
	h.mixed(primary, 400001, paths, 20)
	paths["vp-a"] = asns(t, "AS174", "AS209", "AS400001")
	h.mixed(primary, 400001, paths, 10) // 5 simulated minutes
	if got := h.warnings(); len(got) != 0 {
		t.Fatalf("single-VP evidence paged too early: %+v", got[0])
	}
	h.mixed(primary, 400001, paths, 20) // total 15 minutes
	if len(h.warnings()) == 0 {
		t.Fatal("single-VP evidence never paged despite persisting")
	}
}

// TestIncidentIDsAreDistinctPerOccurrence: two attacks of the same kind on the
// same prefix must not collapse into one incident and lose the second.
func TestIncidentIDsAreDistinctPerOccurrence(t *testing.T) {
	cfg := Defaults()
	cfg.ResolveAfter = 5 * time.Minute
	h := newHarness(t, testRegistry(t), cfg)
	h.steady(primary, 400666, asns(t, "AS1299", "AS400666"), 10)
	h.steady(primary, 400001, asns(t, "AS174", "AS3356", "AS400001"), 30) // let it resolve
	h.steady(primary, 400666, asns(t, "AS1299", "AS400666"), 10)
	seen := map[string]bool{}
	for _, a := range h.all {
		if a.Kind == model.KindOriginHijack {
			seen[a.ID] = true
		}
	}
	if len(seen) != 2 {
		t.Fatalf("got %d distinct origin-hijack incidents, want 2", len(seen))
	}
}

// TestBlindViewDoesNotResolveAnIncident: a collector outage must not read as
// "the hijack went away".
func TestBlindViewDoesNotResolveAnIncident(t *testing.T) {
	cfg := Defaults()
	cfg.ResolveAfter = 5 * time.Minute
	cfg.BlindRatio = 0.9 // this prefix is only seen by a minority by design
	h := newHarness(t, testRegistry(t), cfg)
	h.steady(primary, 400666, asns(t, "AS1299", "AS400666"), 10)
	h.now = h.now.Add(30 * time.Minute) // everything goes silent
	d := h.eng.Tick(h.now)
	for _, a := range d.Updated {
		if a.Kind == model.KindOriginHijack && a.Phase == model.PhaseResolved {
			t.Fatal("incident resolved while the view was blind")
		}
	}
}

// TestScoreIsExplained: every alert must carry its evidence, so an operator can
// see why it fired.
func TestScoreIsExplained(t *testing.T) {
	h := newHarness(t, testRegistry(t), Defaults())
	h.steady(primary, 400001, asns(t, "AS174", "AS3356", "AS400001"), 20)
	h.steady(primary, 400666, asns(t, "AS1299", "AS400666"), 8)
	a := h.find(model.KindOriginHijack)
	if a == nil {
		t.Fatal("no alert")
	}
	if len(a.Signals) == 0 {
		t.Error("alert has no signals")
	}
	total := 0
	for _, s := range a.Signals {
		total += s.Delta
	}
	if total != a.Score {
		t.Errorf("signals sum to %d but score is %d", total, a.Score)
	}
	if a.Summary == "" {
		t.Error("alert has no summary")
	}
}
