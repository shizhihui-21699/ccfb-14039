// Package sim generates a synthetic multi-vantage BGP update stream for our
// address space, together with ground truth.  It exists so the detector can be
// developed and regression-tested against data that includes both the hard
// attack shapes and the legitimate operations that look almost identical.
//
// Everything here is fictional: AS numbers, peers and prefixes are invented.
// The documentation prefixes (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24)
// are used deliberately so no real network is implicated.
//
// The generator keeps a per-(collector,prefix) timeline of path segments.  A
// periodic "rib sample" re-emits whatever path is current, which mirrors how a
// stable route looks in a collector's table: it does not revert to a stale
// path just because a scenario is in flight.
package sim

import (
	"fmt"
	"math/rand"
	"net/netip"
	"sort"
	"time"

	"hijackwatch/internal/model"
	"hijackwatch/internal/policy"
)

// Incident is one ground-truth event in the generated timeline.
type Incident struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Prefix      string    `json:"prefix"`
	Origin      uint32    `json:"origin"`
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	ExpectAlert bool      `json:"expect_alert"`
	MinSeverity string    `json:"min_severity,omitempty"`
	MaxSeverity string    `json:"max_severity,omitempty"`
	Description string    `json:"description"`
	// Ambiguous marks benign events the detector is not expected to separate
	// perfectly; they are reported separately in evaluation.
	Ambiguous bool `json:"ambiguous,omitempty"`
}

// Dataset is everything needed to replay and score.
type Dataset struct {
	Name       string         `json:"name"`
	Start      time.Time      `json:"start"`
	End        time.Time      `json:"end"`
	Collectors []string       `json:"collectors"`
	Policy     policy.Config  `json:"policy"`
	Updates    []model.Update `json:"updates"`
	Incidents  []Incident     `json:"incidents"`
}

// Fictional network constants.
const (
	OurAS       = 133900
	OurSecondAS = 133901

	tier1North = 129000
	tier1South = 129010
	regional   = 129020
	ixPeer     = 129030
	scrubber   = 129900

	rogueExact   = 204500
	rogueSub     = 396010
	rogueForged  = 396020
	rogueStealth = 204515
	rogueLeak    = 204800
	knownMigr    = 129500
	newPeering   = 129400
)

var (
	prefixWeb  = netip.MustParsePrefix("203.0.113.0/24")
	prefixApp  = netip.MustParsePrefix("198.51.100.0/24")
	prefixEdge = netip.MustParsePrefix("192.0.2.0/24")
)

func ourPrefixes() []policy.Prefix {
	return []policy.Prefix{
		{CIDR: prefixWeb.String(), ExpectedOrigins: []uint32{OurAS}, ApprovedCleanings: []uint32{scrubber}},
		{CIDR: prefixApp.String(), ExpectedOrigins: []uint32{OurAS}, ApprovedCleanings: []uint32{scrubber}},
		{CIDR: prefixEdge.String(), ExpectedOrigins: []uint32{OurAS, OurSecondAS}},
	}
}

type collector struct {
	name      string
	peerASN   uint32
	upstreams []uint32
	lag       time.Duration
	jitter    time.Duration
	dropRate  float64
}

func collectors() []collector {
	return []collector{
		{name: "rv-lon", peerASN: 129100, upstreams: []uint32{tier1North}, lag: 5 * time.Second, jitter: 3 * time.Second},
		{name: "rv-ams", peerASN: 129110, upstreams: []uint32{tier1North}, lag: 12 * time.Second, jitter: 8 * time.Second, dropRate: 0.01},
		{name: "rv-fra", peerASN: 129170, upstreams: []uint32{ixPeer}, lag: 6 * time.Second, jitter: 4 * time.Second},
		{name: "rv-sfo", peerASN: 129120, upstreams: []uint32{tier1South}, lag: 40 * time.Second, jitter: 20 * time.Second, dropRate: 0.02},
		{name: "rv-tyo", peerASN: 129130, upstreams: []uint32{tier1South}, lag: 60 * time.Second, jitter: 30 * time.Second, dropRate: 0.02},
		{name: "rv-sin", peerASN: 129140, upstreams: []uint32{regional}, lag: 8 * time.Second, jitter: 5 * time.Second, dropRate: 0.01},
		{name: "rv-sao", peerASN: 129160, upstreams: []uint32{ixPeer}, lag: 25 * time.Second, jitter: 15 * time.Second, dropRate: 0.03},
		{name: "rv-syd", peerASN: 129150, upstreams: []uint32{regional}, lag: 8 * time.Minute, jitter: 2 * time.Minute, dropRate: 0.08},
	}
}

// Options tunes dataset generation.
type Options struct {
	Name          string
	Start         time.Time
	Duration      time.Duration
	Seed          int64
	NoisePrefixes int
}

// DefaultOptions returns the standard dataset parameters.
func DefaultOptions() Options {
	return Options{
		Name:          "multi-vantage-36h",
		Start:         time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC),
		Duration:      36 * time.Hour,
		Seed:          20260302,
		NoisePrefixes: 250,
	}
}

type event struct {
	at   time.Time
	upd  model.Update
	keep bool
}

// seg is one stable interval of a path for a (collector,prefix) pair.
type seg struct {
	from time.Time
	path []uint32
	peer uint32
}

type outage struct {
	col      string
	from, to time.Time
}

type builder struct {
	opt   Options
	rng   *rand.Rand
	cols  []collector
	byCol map[string]collector
	ev    []event
	truth []Incident

	segs    map[string]map[string][]seg // collector -> prefix -> segments
	outages []outage
	curUp   map[string]uint32 // collector -> current primary upstream
}

// Build generates the dataset.
func Build(opt Options) (Dataset, error) {
	if opt.Duration <= 0 {
		opt.Duration = DefaultOptions().Duration
	}
	if opt.Start.IsZero() {
		opt.Start = DefaultOptions().Start
	}
	if opt.NoisePrefixes == 0 {
		opt.NoisePrefixes = DefaultOptions().NoisePrefixes
	}
	b := &builder{
		opt: opt, rng: rand.New(rand.NewSource(opt.Seed)),
		cols: collectors(), segs: map[string]map[string][]seg{},
		curUp: map[string]uint32{},
	}
	b.byCol = map[string]collector{}
	for _, c := range b.cols {
		b.byCol[c.name] = c
	}

	b.seedDefaults()

	// Scenario order does not matter; segments carry absolute times.
	b.attackExactBogusOrigin(10 * time.Hour)
	b.attackSubPrefix(13 * time.Hour)
	b.attackPathInsertion(16 * time.Hour)
	b.attackForgedSubPrefix(19 * time.Hour)
	b.attackSingleCollector(28 * time.Hour)
	b.attackCoveringAggregate(31 * time.Hour)

	b.carrierSwitch(3*time.Hour, 6*time.Hour)
	b.approvedScrubbing(7*time.Hour, 2*time.Hour)
	b.ownTrafficEngineering(8*time.Hour, 90*time.Minute)
	b.newPeering(23*time.Hour, prefixApp)
	b.knownMigrationWindow(33*time.Hour, 2*time.Hour)
	b.collectorOutage("rv-syd", 25*time.Hour, 20*time.Minute)
	b.routeFlapStorm(21*time.Hour, 2*time.Minute)

	b.ribSamples()
	b.multiSiteBurst(5 * time.Hour)
	b.noise()

	updates := b.materialize()
	// Keep only incidents that actually fall inside the simulated window.
	end := opt.Start.Add(opt.Duration)
	truth := b.truth[:0]
	for _, inc := range b.truth {
		if inc.Start.Before(end) {
			truth = append(truth, inc)
		}
	}
	b.truth = truth
	d := Dataset{
		Name: opt.Name, Start: opt.Start, End: end,
		Policy: BasePolicy(), Updates: updates, Incidents: b.truth,
	}
	for _, c := range b.cols {
		d.Collectors = append(d.Collectors, c.name)
	}
	sort.Slice(d.Incidents, func(i, j int) bool { return d.Incidents[i].Start.Before(d.Incidents[j].Start) })
	return d, nil
}

// BasePolicy returns the policy the simulation expects the detector to run.
func BasePolicy() policy.Config {
	cfg := policy.Defaults()
	cfg.OrgName = "example-net (fictional)"
	cfg.Prefixes = ourPrefixes()
	cfg.SuspiciousRecentASNs = []uint32{rogueLeak, 64500}
	cfg.KnownIncidents = []policy.KnownIncident{{
		PeerASN: knownMigr,
		Reason:  "approved migration window for the edge block (change CHG-2291)",
		Expires: time.Date(2026, 3, 3, 12, 0, 0, 0, time.UTC),
	}}
	cfg.NeighborRTT = 2 * time.Minute
	cfg.DedupWindow = 30 * time.Second
	cfg.ResolutionWindow = 15 * time.Minute
	cfg.MinCollectors = 2
	cfg.MinAlertSeverity = model.SevMedium
	return cfg
}

// ---- segment timeline ----

func (b *builder) t(offset time.Duration) time.Time { return b.opt.Start.Add(offset) }

func (b *builder) path(c collector, upstreams []uint32, origin uint32) []uint32 {
	p := append([]uint32{c.peerASN}, upstreams...)
	return append(p, origin)
}

func (b *builder) setPath(colName, pfx string, at time.Time, path []uint32, peer uint32) {
	if b.segs[colName] == nil {
		b.segs[colName] = map[string][]seg{}
	}
	list := b.segs[colName][pfx]
	for i := range list {
		if list[i].from.Equal(at) {
			list[i] = seg{from: at, path: append([]uint32(nil), path...), peer: peer}
			return
		}
	}
	list = append(list, seg{from: at, path: append([]uint32(nil), path...), peer: peer})
	sort.Slice(list, func(i, j int) bool { return list[i].from.Before(list[j].from) })
	b.segs[colName][pfx] = list
}

// pathAt returns the most recent segment for a (collector,prefix) at time at.
// A nil path means the prefix was withdrawn.
func (b *builder) pathAt(colName, pfx string, at time.Time) (seg, bool) {
	list := b.segs[colName][pfx]
	var best seg
	found := false
	for _, s := range list {
		if !s.from.After(at) && (!found || s.from.After(best.from)) {
			best = s
			found = true
		}
	}
	return best, found
}

func (b *builder) seedDefaults() {
	for _, c := range b.cols {
		b.curUp[c.name] = c.upstreams[0]
		for _, p := range []netip.Prefix{prefixWeb, prefixApp, prefixEdge} {
			b.setPath(c.name, p.String(), b.opt.Start, b.path(c, b.curUpstream(c), OurAS), c.peerASN)
		}
	}
}

// curUpstream returns the upstream a collector is currently using, which the
// carrier-switch scenario changes.  Restoring a route after an attack must go
// back to *this* upstream, not the collector's original one, or the detector
// sees the restore itself as another change.
func (b *builder) curUpstream(c collector) []uint32 {
	if u, ok := b.curUp[c.name]; ok && u != 0 {
		return []uint32{u}
	}
	return c.upstreams
}

// ribSamples re-emits each stable path every ten minutes, always reflecting the
// *current* segment so an in-flight scenario is not clobbered by a stale
// refresh.  This is what gives the detector a baseline to learn from.
func (b *builder) ribSamples() {
	pfx := []netip.Prefix{prefixWeb, prefixApp, prefixEdge}
	for m := 0; m < int(b.opt.Duration.Minutes()); m += 10 {
		at := b.t(time.Duration(m) * time.Minute)
		for _, c := range b.cols {
			if b.suppressed(c.name, at) {
				continue
			}
			for i, p := range pfx {
				s, ok := b.pathAt(c.name, p.String(), at)
				if !ok || len(s.path) == 0 {
					continue
				}
				jit := time.Duration((m*7+i*13+len(c.name))%40) * time.Second
				b.emit(at.Add(jit), c.name, p, s.path, s.peer, false)
			}
		}
	}
}

func (b *builder) suppressed(col string, at time.Time) bool {
	for _, w := range b.outages {
		if w.col == col && !at.Before(w.from) && at.Before(w.to) {
			return true
		}
	}
	return false
}

// ---- benign operations ----

func (b *builder) carrierSwitch(start, dur time.Duration) {
	for i, c := range b.cols {
		at := b.t(start + time.Duration(i)*dur/time.Duration(len(b.cols)))
		b.curUp[c.name] = tier1South
		for _, p := range []netip.Prefix{prefixWeb, prefixApp, prefixEdge} {
			np := b.path(c, []uint32{tier1South}, OurAS)
			b.setPath(c.name, p.String(), at, np, c.peerASN)
			b.emit(at, c.name, p, np, c.peerASN, true)
		}
	}
	b.truth = append(b.truth, Incident{
		ID: "benign-carrier-switch", Kind: "benign_carrier_switch",
		Prefix: prefixWeb.String(), Origin: OurAS,
		Start: b.t(start), End: b.t(start + dur + time.Minute),
		ExpectAlert: false, MaxSeverity: "low",
		Description: "upstream provider change for all prefixes at once",
	})
}

func (b *builder) multiSiteBurst(start time.Duration) {
	at := b.t(start)
	b.announceAll(at, prefixWeb, OurAS, nil, true)
	b.announceAll(at.Add(2*time.Second), prefixWeb, OurAS, nil, false)
	b.truth = append(b.truth, Incident{
		ID: "benign-multisite", Kind: "benign_multisite",
		Prefix: prefixWeb.String(), Origin: OurAS,
		Start: at, End: at.Add(10 * time.Minute),
		ExpectAlert: false, MaxSeverity: "info",
		Description: "same origin announcing the same block from 8 sites simultaneously",
	})
}

// approvedScrubbing is a scrubbing centre announcing a more-specific of our
// block during a DDoS: the canonical legitimate operation that looks exactly
// like a sub-prefix hijack.
func (b *builder) approvedScrubbing(start, dur time.Duration) {
	ms := netip.MustParsePrefix("203.0.113.0/25")
	at, end := b.t(start), b.t(start+dur)
	for _, c := range b.cols[:5] {
		p := []uint32{c.peerASN, tier1North, scrubber, scrubber, OurAS}
		b.setPath(c.name, ms.String(), at, p, c.peerASN)
		b.setPath(c.name, ms.String(), end, nil, c.peerASN)
		b.emit(at, c.name, ms, p, c.peerASN, true)
		b.emit(end, c.name, ms, nil, c.peerASN, false)
	}
	b.truth = append(b.truth, Incident{
		ID: "benign-scrubbing", Kind: "benign_approved_scrubbing",
		Prefix: ms.String(), Origin: scrubber,
		Start: at, End: end, ExpectAlert: false, MaxSeverity: "low",
		Description: "approved DDoS scrubbing more-specific from AS129900",
	})
}

func (b *builder) ownTrafficEngineering(start, dur time.Duration) {
	ms := netip.MustParsePrefix("198.51.100.0/25")
	at, end := b.t(start), b.t(start+dur)
	for _, c := range b.cols[2:6] {
		p := b.path(c, b.curUpstream(c), OurAS)
		b.setPath(c.name, ms.String(), at, p, c.peerASN)
		b.setPath(c.name, ms.String(), end, nil, c.peerASN)
		b.emit(at, c.name, ms, p, c.peerASN, true)
		b.emit(end, c.name, ms, nil, c.peerASN, false)
	}
	b.truth = append(b.truth, Incident{
		ID: "benign-te-morespecific", Kind: "benign_traffic_engineering",
		Prefix: ms.String(), Origin: OurAS,
		Start: at, End: end, ExpectAlert: false, MaxSeverity: "info",
		Description: "our own origin announcing a more-specific for traffic engineering",
	})
}

func (b *builder) routeFlapStorm(start, dur time.Duration) {
	at := b.t(start)
	for i := 0; i < int(dur.Minutes())*2; i++ {
		t := at.Add(time.Duration(i) * 30 * time.Second)
		for _, c := range b.cols {
			p := b.path(c, b.curUpstream(c), OurAS)
			b.emit(t, c.name, prefixEdge, p, c.peerASN, false)
			b.emit(t.Add(20*time.Second), c.name, prefixEdge, nil, c.peerASN, false)
		}
	}
	b.truth = append(b.truth, Incident{
		ID: "benign-flap", Kind: "benign_route_flap",
		Prefix: prefixEdge.String(), Origin: OurAS,
		Start: at, End: at.Add(dur), ExpectAlert: false, MaxSeverity: "low",
		Description: "session flap: announce/withdraw every 30s for 2 minutes",
	})
}

// newPeering is a genuinely new upstream for a single prefix.  Fundamentally
// ambiguous with a path insertion, so it is marked Ambiguous: the detector may
// raise a Medium for review but must not page.
func (b *builder) newPeering(start time.Duration, p netip.Prefix) {
	at, end := b.t(start), b.t(start+3*time.Hour)
	for _, c := range b.cols[2:4] {
		np := b.path(c, []uint32{newPeering, tier1North}, OurAS)
		b.setPath(c.name, p.String(), at, np, c.peerASN)
		b.setPath(c.name, p.String(), end, b.path(c, b.curUpstream(c), OurAS), c.peerASN)
		b.emit(at, c.name, p, np, c.peerASN, true)
		b.emit(end, c.name, p, b.path(c, b.curUpstream(c), OurAS), c.peerASN, false)
	}
	b.truth = append(b.truth, Incident{
		ID: "benign-new-peering", Kind: "benign_new_peering",
		Prefix: p.String(), Origin: OurAS,
		Start: at, End: at.Add(3 * time.Hour),
		ExpectAlert: false, MaxSeverity: "medium", Ambiguous: true,
		Description: "new upstream AS129400 for one prefix only (may look like an insertion)",
	})
}

func (b *builder) collectorOutage(name string, start, dur time.Duration) {
	from, to := b.t(start), b.t(start+dur)
	b.outages = append(b.outages, outage{col: name, from: from, to: to})
	for _, p := range []netip.Prefix{prefixWeb, prefixApp, prefixEdge} {
		s, ok := b.pathAt(name, p.String(), to)
		if !ok {
			continue
		}
		b.emit(to.Add(3*time.Minute), name, p, s.path, s.peer, true)
	}
	b.truth = append(b.truth, Incident{
		ID: "benign-collector-outage", Kind: "benign_collector_outage",
		Prefix: prefixWeb.String(), Origin: OurAS,
		Start: to, End: to.Add(10 * time.Minute),
		ExpectAlert: false, MaxSeverity: "low",
		Description: "collector " + name + " outage and full-table recovery",
	})
}

// knownMigrationWindow is an operator-registered change: detected, but its
// severity must be capped by policy.
func (b *builder) knownMigrationWindow(start, dur time.Duration) {
	at, end := b.t(start), b.t(start+dur)
	for _, c := range b.cols[:3] {
		np := b.path(c, []uint32{knownMigr}, OurAS)
		b.setPath(c.name, prefixEdge.String(), at, np, c.peerASN)
		b.setPath(c.name, prefixEdge.String(), end, b.path(c, b.curUpstream(c), OurAS), c.peerASN)
		b.emit(at, c.name, prefixEdge, np, c.peerASN, true)
		b.emit(end, c.name, prefixEdge, b.path(c, b.curUpstream(c), OurAS), c.peerASN, false)
	}
	b.truth = append(b.truth, Incident{
		ID: "benign-known-migration", Kind: "benign_known_incident",
		Prefix: prefixEdge.String(), Origin: OurAS,
		Start: at, End: end, ExpectAlert: false, MaxSeverity: "low",
		Description: "announcement covered by an operator-registered change window",
	})
}

// ---- attacks ----

func (b *builder) attackExactBogusOrigin(start time.Duration) {
	at, end := b.t(start), b.t(start+40*time.Minute)
	for _, c := range b.cols {
		p := []uint32{c.peerASN, tier1North, rogueExact}
		b.setPath(c.name, prefixWeb.String(), at, p, c.peerASN)
		b.setPath(c.name, prefixWeb.String(), end, b.path(c, b.curUpstream(c), OurAS), c.peerASN)
		b.emit(at, c.name, prefixWeb, p, c.peerASN, true)
		b.emit(end, c.name, prefixWeb, b.path(c, b.curUpstream(c), OurAS), c.peerASN, false)
	}
	b.truth = append(b.truth, Incident{
		ID: "atk-bogus-origin", Kind: model.KindBogusOrigin,
		Prefix: prefixWeb.String(), Origin: rogueExact,
		Start: at, End: end, ExpectAlert: true, MinSeverity: "high",
		Description: "exact /24 announced by rogue AS204500 from 8 vantage points",
	})
}

func (b *builder) attackSubPrefix(start time.Duration) {
	at, end := b.t(start), b.t(start+35*time.Minute)
	ms := netip.MustParsePrefix("198.51.100.0/25")
	plan := []struct {
		name  string
		delay time.Duration
	}{{"rv-lon", 0}, {"rv-ams", 0}, {"rv-fra", 6 * time.Minute}, {"rv-sfo", 6 * time.Minute},
		{"rv-sin", 6 * time.Minute}, {"rv-syd", 11 * time.Minute}}
	for _, p := range plan {
		c := b.byCol[p.name]
		t := at.Add(p.delay)
		path := []uint32{c.peerASN, 129050, rogueSub}
		b.setPath(p.name, ms.String(), t, path, c.peerASN)
		b.setPath(p.name, ms.String(), end, nil, c.peerASN)
		b.emit(t, p.name, ms, path, c.peerASN, true)
		b.emit(end, p.name, ms, nil, c.peerASN, false)
	}
	b.truth = append(b.truth, Incident{
		ID: "atk-subprefix", Kind: model.KindSubprefix,
		Prefix: ms.String(), Origin: rogueSub,
		Start: at, End: end, ExpectAlert: true, MinSeverity: "high",
		Description: "rogue AS396010 hijacks a /25 more-specific, spreading over 11 minutes",
	})
}

func (b *builder) attackPathInsertion(start time.Duration) {
	at, end := b.t(start), b.t(start+45*time.Minute)
	for _, name := range []string{"rv-lon", "rv-ams", "rv-fra", "rv-sfo"} {
		c := b.byCol[name]
		p := []uint32{c.peerASN, tier1North, rogueStealth, OurAS}
		b.setPath(name, prefixEdge.String(), at, p, c.peerASN)
		b.setPath(name, prefixEdge.String(), end, b.path(c, b.curUpstream(c), OurAS), c.peerASN)
		b.emit(at, name, prefixEdge, p, c.peerASN, true)
		b.emit(end, name, prefixEdge, b.path(c, b.curUpstream(c), OurAS), c.peerASN, false)
	}
	b.truth = append(b.truth, Incident{
		ID: "atk-path-insertion", Kind: model.KindPathInsertion,
		Prefix: prefixEdge.String(), Origin: OurAS,
		Start: at, End: end, ExpectAlert: true, MinSeverity: "medium",
		Description: "AS204515 inserted as penultimate hop for one prefix on 4 collectors",
	})
}

// attackForgedSubPrefix: a rogue peer announces a /26 of our block while
// preserving our origin in the path — a forged path designed to defeat
// origin-only checks.
func (b *builder) attackForgedSubPrefix(start time.Duration) {
	at, end := b.t(start), b.t(start+30*time.Minute)
	ms := netip.MustParsePrefix("203.0.113.0/26")
	for _, name := range []string{"rv-lon", "rv-ams", "rv-sin"} {
		p := []uint32{rogueForged, tier1North, OurAS}
		b.setPath(name, ms.String(), at, p, rogueForged)
		b.setPath(name, ms.String(), end, nil, rogueForged)
		b.emit(at, name, ms, p, rogueForged, true)
		b.emit(end, name, ms, nil, rogueForged, false)
	}
	b.truth = append(b.truth, Incident{
		ID: "atk-forged-path", Kind: model.KindForgedPath,
		Prefix: ms.String(), Origin: OurAS,
		Start: at, End: end, ExpectAlert: true, MinSeverity: "high",
		Description: "forged path: rogue peer announces a /26 with our origin preserved",
	})
}

func (b *builder) attackSingleCollector(start time.Duration) {
	at, end := b.t(start), b.t(start+20*time.Minute)
	c := b.byCol["rv-fra"]
	p := []uint32{129170, 64500, 64500, rogueLeak}
	b.setPath("rv-fra", prefixApp.String(), at, p, 129170)
	b.setPath("rv-fra", prefixApp.String(), end, b.path(c, b.curUpstream(c), OurAS), 129170)
	b.emit(at, "rv-fra", prefixApp, p, 129170, true)
	b.emit(end, "rv-fra", prefixApp, b.path(c, b.curUpstream(c), OurAS), 129170, false)
	b.truth = append(b.truth, Incident{
		ID: "atk-single-collector", Kind: model.KindBogusOrigin,
		Prefix: prefixApp.String(), Origin: rogueLeak,
		Start: at, End: end, ExpectAlert: true, MinSeverity: "medium",
		Description: "bogus origin visible from only one vantage point",
	})
}

func (b *builder) attackCoveringAggregate(start time.Duration) {
	at, end := b.t(start), b.t(start+30*time.Minute)
	agg := netip.MustParsePrefix("198.51.0.0/16")
	for _, c := range b.cols[:4] {
		p := []uint32{c.peerASN, 129050, rogueLeak}
		b.setPath(c.name, agg.String(), at, p, c.peerASN)
		b.setPath(c.name, agg.String(), end, nil, c.peerASN)
		b.emit(at, c.name, agg, p, c.peerASN, true)
		b.emit(end, c.name, agg, nil, c.peerASN, false)
	}
	b.truth = append(b.truth, Incident{
		ID: "atk-covering-aggregate", Kind: model.KindBogusOrigin,
		Prefix: agg.String(), Origin: rogueLeak,
		Start: at, End: end, ExpectAlert: true, MinSeverity: "medium",
		Description: "rogue covering /16 for our /24",
	})
}

// ---- background noise ----

func (b *builder) noise() {
	base := netip.MustParsePrefix("104.0.0.0/8")
	for i := 0; i < b.opt.NoisePrefixes; i++ {
		var p netip.Prefix
		if i%5 == 0 {
			p = netip.PrefixFrom(netip.AddrFrom4([4]byte{104, byte(i / 256), byte(i % 256), 0}), 16).Masked()
		} else {
			p = netip.PrefixFrom(netip.AddrFrom4([4]byte{104, byte(i / 256), byte(i % 256), 0}), 24).Masked()
		}
		if !base.Contains(p.Addr()) {
			continue
		}
		origin := uint32(150000 + i%40)
		for m := b.rng.Intn(30); m < int(b.opt.Duration.Minutes()); m += 20 + b.rng.Intn(40) {
			at := b.t(time.Duration(m) * time.Minute)
			c := b.cols[b.rng.Intn(len(b.cols))]
			ups := []uint32{c.peerASN, uint32(151000 + b.rng.Intn(5)), origin}
			b.ev = append(b.ev, event{at: at, upd: model.Update{
				Collector: c.name, PeerASN: c.peerASN, Type: model.Announce,
				Prefix: p.String(), ASPath: ups, EventTime: at,
			}})
		}
	}
}

// ---- emission & materialisation ----

func (b *builder) announceAll(at time.Time, prefix netip.Prefix, origin uint32, upstreams []uint32, keep bool) {
	for _, c := range b.cols {
		ups := upstreams
		if ups == nil {
			ups = c.upstreams
		}
		b.emit(at, c.name, prefix, b.path(c, ups, origin), c.peerASN, keep)
	}
}

func (b *builder) emit(at time.Time, col string, prefix netip.Prefix, path []uint32, peer uint32, keep bool) {
	if len(path) == 0 {
		b.ev = append(b.ev, event{at: at, keep: keep, upd: model.Update{
			Collector: col, PeerASN: peer, Type: model.Withdraw,
			Prefix: prefix.String(), EventTime: at,
		}})
		return
	}
	b.ev = append(b.ev, event{at: at, keep: keep, upd: model.Update{
		Collector: col, PeerASN: peer,
		PeerIP:    fmt.Sprintf("192.0.2.%d", 10+len(col)),
		Type:      model.Announce,
		Prefix:    prefix.String(),
		ASPath:    append([]uint32(nil), path...),
		EventTime: at,
	}})
}

// materialize applies per-collector lag, jitter and drops, then orders the
// stream by arrival time the way a real collector feed would be seen.
func (b *builder) materialize() []model.Update {
	sort.SliceStable(b.ev, func(i, j int) bool { return b.ev[i].at.Before(b.ev[j].at) })
	out := make([]model.Update, 0, len(b.ev))
	for _, e := range b.ev {
		if e.at.After(b.opt.Start.Add(b.opt.Duration)) {
			continue
		}
		if e.upd.Collector != "" && b.suppressed(e.upd.Collector, e.at) && !e.keep {
			continue
		}
		c := b.byCol[e.upd.Collector]
		lag := c.lag
		if c.jitter > 0 {
			lag += time.Duration(b.rng.Int63n(int64(2*c.jitter))) - c.jitter
		}
		if lag < 0 {
			lag = 0
		}
		if !e.keep && c.dropRate > 0 && b.rng.Float64() < c.dropRate {
			continue
		}
		u := e.upd
		u.EventTime = e.at
		u.ReceivedAt = e.at.Add(lag)
		out = append(out, u)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].ReceivedAt.Equal(out[j].ReceivedAt) {
			return out[i].Prefix < out[j].Prefix
		}
		return out[i].ReceivedAt.Before(out[j].ReceivedAt)
	})
	for i := range out {
		out[i].Seq = i
	}
	return out
}
