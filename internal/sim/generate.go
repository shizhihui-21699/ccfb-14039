package sim

import (
	"fmt"
	"sort"
	"time"

	"routewatch/internal/model"
	"routewatch/internal/registry"
)

// Generator turns a Timeline into a feed of observations.
//
// The mechanics mirror how collectors actually behave:
//
//   - Every SnapshotInterval a collector emits its current best route for every
//     prefix it sees — a periodic RIB dump, not only on change. That is what
//     makes collector liveness measurable and what gives the detector a steady
//     baseline to compare against.
//   - A change reaches collectors after a per-collector latency, so the same
//     event appears at different ReceivedAt times across the fleet. Collection
//     latency is batching and export cadence, not network convergence.
//   - Some (collector, prefix) views go silent for a while and then emit a
//     backlog when they recover. A detector that reads silence as "no change"
//     breaks exactly here.
//   - When a route disappears the collector emits a withdrawal, so incident
//     recovery is observable rather than inferred.
//
// One collector reports one best route per prefix. That is why a hijack shows
// up as *some* collectors reporting the attacker while others still report us —
// the pattern the detector has to interpret.
type Generator struct {
	Reg *registry.Registry
	// Seed drives all randomness in path choice, latency jitter and outages.
	Seed int64
	// SnapshotInterval is the collector dump period.
	SnapshotInterval time.Duration
	// OutageFraction is the share of (VP, prefix) views that suffer a data gap.
	OutageFraction float64
	// ChurnPerHour is the rate at which each (VP, prefix) view picks a new
	// plausible path, modelling ordinary traffic engineering.
	ChurnPerHour float64
	rng          *rng
}

// Generate builds the observation stream and labels for a timeline.
func (g *Generator) Generate(tl Timeline) (model.Scenario, error) {
	if g.SnapshotInterval <= 0 {
		g.SnapshotInterval = 5 * time.Minute
	}
	if g.ChurnPerHour < 0 {
		g.ChurnPerHour = 0
	}
	g.rng = newRNG(g.Seed)
	sc := model.Scenario{Name: "simulated", Seed: g.Seed, Start: tl.Start, End: tl.End}

	// Every prefix the scenario can touch: ours, the customer's, and anything an
	// injection announces.
	set := map[model.Prefix]bool{}
	for _, p := range g.Reg.OurPrefixes {
		set[p] = true
	}
	set[model.MustPrefix("198.51.101.0/24")] = true
	for _, in := range tl.Injections {
		set[in.Prefix] = true
	}
	prefixes := make([]model.Prefix, 0, len(set))
	for p := range set {
		prefixes = append(prefixes, p)
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })

	gaps := g.planGaps(tl, prefixes)
	firstDump := tl.Start.Add(2 * time.Minute)

	vps := append([]registry.VPInfo(nil), g.Reg.VPs...)
	sort.Slice(vps, func(i, j int) bool { return vps[i].Name < vps[j].Name })

	for _, vp := range vps {
		for _, p := range prefixes {
			sc.Observations = append(sc.Observations, g.seriesFor(tl, vp, p, gaps[gapKey(vp.Name, p)], firstDump)...)
		}
	}

	model.SortObservations(sc.Observations)
	sc.Labels = tl.Labels()
	return sc, nil
}

type span struct{ start, end time.Time }

func (s span) contains(t time.Time) bool { return !t.Before(s.start) && t.Before(s.end) }

func gapKey(vp string, p model.Prefix) string { return vp + "|" + p.String() }

// planGaps decides which (collector, prefix) views lose data, and when.
func (g *Generator) planGaps(tl Timeline, prefixes []model.Prefix) map[string][]span {
	gaps := map[string][]span{}
	if g.OutageFraction <= 0 {
		return gaps
	}
	window := tl.End.Sub(tl.Start)
	total := len(g.Reg.VPs) * len(prefixes)
	want := int(float64(total) * g.OutageFraction)
	for i := 0; i < want; i++ {
		vp := g.Reg.VPs[g.rng.intn(len(g.Reg.VPs))]
		p := prefixes[g.rng.intn(len(prefixes))]
		dur := time.Duration(5+g.rng.intn(36)) * time.Minute
		if dur > window/3 {
			dur = window / 3
		}
		offset := time.Duration(g.rng.int63n(int64(window - dur)))
		start := tl.Start.Add(offset)
		k := gapKey(vp.Name, p)
		gaps[k] = append(gaps[k], span{start, start.Add(dur)})
	}
	return gaps
}

// baseline describes how a prefix is normally announced.
type baseline struct {
	origin  model.ASN
	pathFor func(region string, variant int) []model.ASN
	// announced reports whether the baseline exists at all. A covering
	// hijack's prefix has no baseline; ours always do.
	exists bool
}

// baselineFor returns the normal announcement for a prefix, if we make one.
//
// Only the prefixes we actually originate have a baseline. A prefix that only
// appears in an injection (an attacker's /24 or /22) has none: in the real
// world nobody announces it from us, and inventing a baseline for it would mask
// the very event the scenario is testing.
func (g *Generator) baselineFor(p model.Prefix) baseline {
	reg := g.Reg
	for _, ours := range reg.OurPrefixes {
		if ours == p {
			return baseline{origin: reg.SelfASN, exists: true, pathFor: g.upstreamPath}
		}
	}
	if p.String() == "198.51.101.0/24" {
		return baseline{
			origin: 400010,
			exists: true,
			pathFor: func(region string, v int) []model.ASN {
				path := g.upstreamPath(region, v)
				return append(append([]model.ASN{}, path...), 400010)
			},
		}
	}
	return baseline{}
}

// upstreamPath builds "<top> <transit> <us>" for a region, varying the transit
// by variant so a view can switch carriers during ordinary churn.
func (g *Generator) upstreamPath(region string, variant int) []model.ASN {
	ups := g.Reg.Lookup(g.Reg.SelfASN).Upstreams
	if len(ups) == 0 {
		return []model.ASN{g.Reg.SelfASN}
	}
	up := ups[variant%len(ups)]
	info := g.Reg.Lookup(up)
	if len(info.Upstreams) == 0 {
		return []model.ASN{up, g.Reg.SelfASN}
	}
	top := info.Upstreams[variant%len(info.Upstreams)]
	return []model.ASN{top, up, g.Reg.SelfASN}
}

// routeAt computes what one collector sees for one prefix at time t.
//
// An active injection that covers this collector wins over the baseline,
// because "the hijack is visible from here" means exactly that. If several
// injections overlap, the most recently started wins, matching a later
// announcement displacing an earlier one in the collector's table.
func (g *Generator) routeAt(tl Timeline, vp registry.VPInfo, p model.Prefix, base baseline, t time.Time) (model.Observation, bool) {
	var winner *Injection
	for i := range tl.Injections {
		in := &tl.Injections[i]
		if in.Prefix != p || !in.coversVP(vp.Name) || !in.activeAt(t) {
			continue
		}
		if winner == nil || in.Start.After(winner.Start) {
			winner = in
		}
	}

	// Maintenance is modelled as repeated withdraw/reannounce inside the
	// window. It is handled after winner selection: while the customer's
	// session is flapping, the collector has *no* route for that prefix. Falling
	// through to the baseline would emit an announcement instead of a
	// withdrawal, so the flap would be invisible in the feed -- which is what
	// made an earlier version of this simulator quietly lie.
	for i := range tl.Injections {
		in := &tl.Injections[i]
		if in.Kind != EvMaintenance || in.Prefix != p || !in.coversVP(vp.Name) || !in.activeAt(t) {
			continue
		}
		half := in.FlapEvery / 2
		if half <= 0 {
			half = 45 * time.Second
		}
		if t.Sub(in.Start)%(2*half) < half {
			return model.Observation{}, false
		}
		break
	}

	if winner != nil {
		path := append([]model.ASN{}, winner.Path...)
		if len(path) == 0 {
			path = g.upstreamPath(vp.Region, 0)
		}
		if path[len(path)-1] != winner.Origin {
			path = append(path, winner.Origin)
		}
		if winner.prependsVP(vp.Name, g.rng) {
			for i := 0; i < winner.Prepend; i++ {
				path = append(path, winner.Origin)
			}
		}
		return model.Observation{
			Prefix: p, Origin: winner.Origin, ASPath: path, VP: vp.Name, VPASN: vp.ASN,
			Communities: winner.Communities, GroundTruth: winner.Reason,
		}, true
	}

	if !base.exists {
		return model.Observation{}, false
	}
	path := base.pathFor(vp.Region, g.variantFor(vp.Name, p, t))
	// Prepend at some views, as a provider would to steer inbound traffic.
	if g.prependAt(vp.Name, p, t) {
		path = append(path, base.origin, base.origin)
	}
	return model.Observation{
		Prefix: p, Origin: base.origin, ASPath: path, VP: vp.Name, VPASN: vp.ASN,
		GroundTruth: "baseline",
	}, true
}

// variantFor picks a path variant for a view. Ordinary churn changes it every
// few hours per view, so the fleet always has some cascading path changes.
func (g *Generator) variantFor(vp string, p model.Prefix, t time.Time) int {
	const perms = 3
	// Each 2-hour slot independently either keeps the view's configured base
	// variant or takes one of the others. Sampling independently (rather than
	// walking a chain) means a higher ChurnPerHour always produces more distinct
	// paths, instead of cycling and cancelling its own changes.
	base := int(hashString(vp+"|"+p.String()) % perms)
	// Number of alternating slots expected per hour, capped at "always change".
	rate := g.ChurnPerHour / 2
	if rate <= 0 {
		return base
	}
	if rate > 1 {
		rate = 1
	}
	slot := t.Unix() / 7200
	if hashString(fmt.Sprintf("switch|%s|%s|%d", vp, p, slot))%1000 >= uint64(rate*1000) {
		return base
	}
	// Switch to a different variant, chosen deterministically for this slot.
	off := 1 + int(hashString(fmt.Sprintf("to|%s|%s|%d", vp, p, slot))%uint64(perms-1))
	return (base + off) % perms
}

// prependAt reports whether this view prepends on its current path. It is
// part of the churn budget, not extra churn: at zero churn no view prepends,
// so a churn=0 scenario is genuinely static.
func (g *Generator) prependAt(vp string, p model.Prefix, t time.Time) bool {
	if g.ChurnPerHour <= 0 {
		return false
	}
	slot := uint64(t.Unix()) / 7200
	return (hashString("prepend|"+vp+"|"+p.String())+slot*2654435761)%10 < 3
}

// pendingObs is an observation held back by a data gap; it is emitted when the
// gap closes, with a ReceivedAt of the recovery time.
type pendingObs struct {
	obs       model.Observation
	releaseAt time.Time
}

// seriesFor builds one collector's observation series for one prefix.
//
// Collectors are change-driven plus periodic: an announcement or withdrawal is
// emitted when the route actually changes, and a keepalive copy of the current
// route is emitted every SnapshotInterval so liveness is observable. A purely
// periodic sampler would alias against fast flap cycles (a 2.5-minute flap
// sampled every 5 minutes can look perfectly stable), which is exactly the kind
// of artefact that makes a test suite lie about itself.
func (g *Generator) seriesFor(tl Timeline, vp registry.VPInfo, p model.Prefix, gaps []span, firstDump time.Time) []model.Observation {
	base := g.baselineFor(p)
	lat := g.Reg.VPLatencyHint(vp.Name)

	var out []model.Observation
	var backlog []pendingObs

	gapAt := func(t time.Time) (span, bool) {
		for _, s := range gaps {
			if s.contains(t) {
				return s, true
			}
		}
		return span{}, false
	}
	deliver := func(rec model.Observation, at time.Time) {
		rec.ReceivedAt = at.Add(lat).Add(time.Duration(g.rng.int63n(8000)) * time.Millisecond)
		if sp, inGap := gapAt(rec.Timestamp); inGap {
			// The collector is not exporting right now: hold the record until
			// the gap closes, then replay it in a burst.
			rec.ReceivedAt = sp.end.Add(lat)
			backlog = append(backlog, pendingObs{rec, sp.end})
			return
		}
		out = append(out, rec)
	}

	start := firstDump.Add(g.phase(vp.Name, p))
	var lastOrigin model.ASN
	haveState := false
	current := func(t time.Time) (model.Observation, bool) {
		o, present := g.routeAt(tl, vp, p, base, t)
		return o, present
	}

	// Candidate change instants: injection boundaries and flap transitions. The
	// rest of the loop is periodic keepalives.
	var events []time.Time
	for _, in := range tl.Injections {
		if in.Prefix != p || !in.coversVP(vp.Name) {
			continue
		}
		if in.Start.After(tl.Start) && in.Start.Before(tl.End) {
			events = append(events, in.Start)
		}
		if !in.End.IsZero() && in.End.After(tl.Start) && in.End.Before(tl.End) {
			events = append(events, in.End)
		}
		if in.Kind == EvMaintenance {
			half := in.FlapEvery / 2
			if half <= 0 {
				half = 45 * time.Second
			}
			// Withdrawn for the first half of each cycle, present for the second.
			// A transition lands at every half-cycle boundary.
			for t := in.Start; t.Before(in.End); t = t.Add(half) {
				events = append(events, t)
			}
		}
	}
	sort.Slice(events, func(i, j int) bool { return events[i].Before(events[j]) })

	emit := func(t time.Time) {
		if t.Before(tl.Start) || !t.Before(tl.End) {
			return
		}
		o, present := current(t)
		if !present {
			if haveState {
				deliver(model.Observation{
					Prefix: p, Origin: lastOrigin, VP: vp.Name, VPASN: vp.ASN,
					Withdraw: true, Timestamp: t,
				}, t)
				haveState = false
			}
			return
		}
		o.Timestamp = t
		deliver(o, t)
		lastOrigin, haveState = o.Origin, true
	}

	// Merge change events with keepalive dumps on a single time line.
	ei := 0
	for tick := start; tick.Before(tl.End); tick = tick.Add(g.SnapshotInterval) {
		for ei < len(events) && !events[ei].After(tick) {
			emit(events[ei])
			ei++
		}
		// Keepalive: re-emit whatever the current route is, so the collector's
		// liveness is visible even when nothing changes.
		o, present := current(tick)
		if present {
			o.Timestamp = tick
			deliver(o, tick)
		} else if haveState {
			deliver(model.Observation{Prefix: p, Origin: lastOrigin, VP: vp.Name, VPASN: vp.ASN,
				Withdraw: true, Timestamp: tick}, tick)
			haveState = false
		}
	}
	for ei < len(events) {
		emit(events[ei])
		ei++
	}
	out = append(out, g.flush(&backlog, tl.End.Add(2*time.Hour), lat)...)
	return out
}

// flush emits backlogged observations whose gap has closed, as one burst at
// recovery time — what a collector does when its session comes back.
func (g *Generator) flush(backlog *[]pendingObs, now time.Time, lat time.Duration) []model.Observation {
	var out []model.Observation
	keep := (*backlog)[:0]
	for _, p := range *backlog {
		if p.releaseAt.After(now) {
			keep = append(keep, p)
			continue
		}
		out = append(out, g.stamp(p.obs, p.releaseAt, lat))
	}
	*backlog = keep
	return out
}

// phase gives each (collector, prefix) view a stable offset inside the dump
// period so the fleet is not synchronised.
func (g *Generator) phase(vp string, p model.Prefix) time.Duration {
	h := hashString("phase|" + vp + "|" + p.String())
	return time.Duration(h%uint64(g.SnapshotInterval.Seconds())) * time.Second
}

func (g *Generator) stamp(o model.Observation, dumpTime time.Time, lat time.Duration) model.Observation {
	// The collector exports on its own cadence; delivery adds latency plus
	// jitter. ReceivedAt is the only clock the detector has.
	o.ReceivedAt = dumpTime.Add(lat).Add(time.Duration(g.rng.int63n(8000)) * time.Millisecond)
	if o.Timestamp.IsZero() {
		o.Timestamp = dumpTime
	}
	o.ID = fmt.Sprintf("%s|%s|%s|%d", o.VP, o.Prefix, o.Origin, o.ReceivedAt.UnixNano())
	return o
}

// rng is a small deterministic xorshift PRNG. Scenario bytes must be identical
// across runs and platforms, which math/rand's top-level sequence does not
// guarantee.
type rng struct{ state uint64 }

func newRNG(seed int64) *rng {
	st := uint64(seed)
	if st == 0 {
		st = 0x9E3779B97F4A7C15
	}
	return &rng{state: st}
}

func (r *rng) next() uint64 {
	r.state ^= r.state >> 12
	r.state ^= r.state << 25
	r.state ^= r.state >> 27
	return r.state * 2685821657736338717
}

func (r *rng) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.next() % uint64(n))
}

func (r *rng) int63n(n int64) int64 {
	if n <= 0 {
		return 0
	}
	return int64(r.next() % uint64(n))
}

func hashString(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// canonPath collapses repeated consecutive ASNs so prepending does not make the
// same route look new.
func canonPath(path []model.ASN) string {
	var b []byte
	var prev model.ASN
	for _, a := range path {
		if a == prev && len(b) > 0 {
			continue
		}
		if len(b) > 0 {
			b = append(b, ' ')
		}
		b = append(b, a.String()...)
		prev = a
	}
	return string(b)
}
