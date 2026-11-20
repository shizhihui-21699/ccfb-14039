// Package detect implements route-hijack detection over multi-vantage-point
// BGP feeds.
//
// Design in one paragraph: collectors deliver per-VP best routes with their own
// latency and their own gaps. The engine keeps, per vantage point, the newest
// route it has seen for each prefix and a liveness timestamp. On each tick it
// looks at every prefix that is ours, covers ours, or sits inside ours; groups
// what the live vantage points currently say; and asks four questions in order:
//
//  1. Legitimacy — is this announcement explained by an authorization, an
//     active scrubbing session, or (for path anomalies) a known carrier?
//     Explained events become INFO audit entries, never pages.
//  2. Shape — is the route itself possible? Paths that loop, put a stub network
//     in transit, or attach our origin to an ASN that is not one of our
//     upstreams/peers were fabricated. This is the defence against a forged
//     path that uses real ASNs: the forgery still has to respect which ASNs
//     actually connect to which.
//  3. Scope — is the anomaly global (every collector changed together, the
//     shape of an operational re-route) or regional (a minority changed, the
//     shape of selective interception)?
//  4. Confidence — how many independent collectors agree, for how long, and is
//     our view complete or are collectors blind/late?
//
// Points combine additively; the score sets severity but never on its own
// pages. An anomaly must persist MinWindows consecutive ticks (one tick is a
// data glitch) and, if only one VP sees it, persist SingleVPWindows ticks
// (a single collector can be wrong in ways two cannot). Every decision is
// recorded as a phase transition on a stable incident ID, so downstream
// systems get a story rather than a stream of duplicates.
package detect

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"routewatch/internal/model"
	"routewatch/internal/registry"
)

// Engine is a single-threaded detection engine. Feed observations in
// ReceivedAt order and call Tick every EvalInterval. Not safe for concurrent
// use; the service layer serialises access.
type Engine struct {
	reg *registry.Registry
	cfg Config
	now time.Time

	prefixes map[model.Prefix]*prefixState
	baseline map[model.Prefix]*baseline
	vps      map[string]*vpHealth
	flaps    map[string]*flapRecord
	incid    map[string]*incident

	started  bool
	startAt  time.Time
	counters Counters
}

// Counters feed the metrics endpoint and the evaluator's noise accounting.
type Counters struct {
	Observations int64
	Withdrawals  int64
	Ignored      int64
	Suppressed   int64
	Raised       map[model.Severity]int64
	Resolved     int64
	Downgraded   int64
	Escalated    int64
}

type prefixState struct {
	prefix model.Prefix
	routes map[string]*vpRoute // newest route per VP
}

type vpRoute struct {
	obs        model.Observation
	withdrawn  bool
	routeSince time.Time // first time this exact path was seen
	changedAt  time.Time // last attribute change
}

// baseline is what we have learned about how a prefix is normally announced.
//
// Adjacency alone is not enough to catch a forged path that uses only real
// carriers with real adjacencies: such a path is structurally perfect. What
// remains observable is that it is *new* -- neither seen for this prefix before
// nor consistent with what this collector's region normally sees. The learned
// baseline is what makes that last question answerable.
type baseline struct {
	adjacents map[model.ASN]int // how often each adjacent ASN carried this prefix
	paths     map[string]int    // canonical path -> count
	origins   map[model.ASN]int
	// perVP records the canonical paths a given collector has reported for this
	// prefix, which is the right reference for "is this new *here*".
	perVP     map[string]map[string]int
	firstSeen time.Time
	lastSeen  time.Time
}

// knownPath reports whether a collector has reported this exact path for this
// prefix before.
func (b *baseline) knownPath(vp, path string) bool {
	if b == nil {
		return false
	}
	if _, ok := b.paths[path]; ok {
		return true
	}
	return b.perVP[vp][path] > 0
}

// observations is the total number of learning samples for this prefix.
func (b *baseline) observations() int {
	if b == nil {
		return 0
	}
	n := 0
	for _, c := range b.paths {
		n += c
	}
	return n
}

type vpHealth struct {
	lastReport time.Time
	delaySum   time.Duration
	delayN     int
}

type flapRecord struct {
	events       []time.Time
	lastWithdraw time.Time
	lastRoute    string
}

// incident is one live suspicion: a prefix plus what we think is wrong with it.
type incident struct {
	id        string
	key       string
	kind      model.Kind
	annPrefix model.Prefix
	ourPrefix *model.Prefix
	suspected model.ASN

	firstSeen time.Time // first observation of the anomalous route
	lastSeen  time.Time // last tick at which the anomaly was present
	windows   int       // consecutive ticks with the anomaly present
	vps       map[string]model.Observation
	routes    map[string]string
	regions   []string

	raised     bool
	alert      model.Alert
	lastScore  int
	visibility float64
	coverage   float64
}

// New builds an engine clocked at now.
func New(reg *registry.Registry, cfg Config, now time.Time) *Engine {
	if err := cfg.Validate(); err != nil {
		panic(err)
	}
	return &Engine{
		reg:      reg,
		cfg:      cfg,
		now:      now,
		prefixes: map[model.Prefix]*prefixState{},
		baseline: map[model.Prefix]*baseline{},
		vps:      map[string]*vpHealth{},
		flaps:    map[string]*flapRecord{},
		incid:    map[string]*incident{},
		counters: Counters{Raised: map[model.Severity]int64{}},
	}
}

func (e *Engine) Config() Config  { return e.cfg }
func (e *Engine) Now() time.Time  { return e.now }
func (e *Engine) Stats() Counters { return e.counters }

// Start marks the beginning of the learning period.
func (e *Engine) Start(t time.Time) {
	e.started = true
	e.startAt = t
	e.now = t
}

// OpenIncidents returns a snapshot of live incidents, for the status endpoint.
func (e *Engine) OpenIncidents() []model.Alert {
	out := make([]model.Alert, 0, len(e.incid))
	for _, inc := range e.incid {
		if inc.raised {
			out = append(out, inc.alert)
		}
	}
	sortAlerts(out)
	return out
}

// Ingest updates per-VP state and the baseline. No decisions are made here;
// keeping decision points in Tick makes the engine auditable and reproducible.
func (e *Engine) Ingest(obs []model.Observation) {
	model.SortObservations(obs)
	for _, o := range obs {
		e.ingestOne(o)
	}
}

func (e *Engine) ingestOne(o model.Observation) {
	e.counters.Observations++
	if o.Withdraw {
		e.counters.Withdrawals++
	}
	if o.ReceivedAt.After(e.now) {
		e.now = o.ReceivedAt
	}
	h := e.vps[o.VP]
	if h == nil {
		h = &vpHealth{}
		e.vps[o.VP] = h
	}
	h.lastReport = maxTime(h.lastReport, o.ReceivedAt)
	if d := o.ReceivedAt.Sub(o.Timestamp); d >= 0 && d < 10*time.Minute {
		h.delaySum += d
		h.delayN++
	}

	if !e.relevant(o.Prefix) {
		e.counters.Ignored++
		return
	}

	st := e.prefixes[o.Prefix]
	if st == nil {
		st = &prefixState{prefix: o.Prefix, routes: map[string]*vpRoute{}}
		e.prefixes[o.Prefix] = st
	}
	prev := st.routes[o.VP]
	canon := canonPath(o.ASPath)

	if o.Withdraw {
		if prev != nil {
			r := *prev
			r.withdrawn = true
			r.changedAt = o.ReceivedAt
			st.routes[o.VP] = &r
			if !prev.withdrawn {
				e.noteWithdraw(o.VP, o.Prefix, o.ReceivedAt, canon)
			}
		}
		return
	}

	if prev != nil && !prev.withdrawn && prev.obs.PathSignature() == o.PathSignature() && prev.obs.Origin == o.Origin {
		// Periodic refresh of the same route: keep routeSince so a stable
		// route is not mistaken for churn.
		r := *prev
		r.obs = o
		st.routes[o.VP] = &r
		e.learnBaseline(o)
		return
	}
	st.routes[o.VP] = &vpRoute{obs: o, routeSince: o.ReceivedAt, changedAt: o.ReceivedAt}
	e.learnBaseline(o)
}

// noteWithdraw records a withdraw for flap accounting; the matching reannounce
// closes the cycle in evaluateFlaps.
func (e *Engine) noteWithdraw(vp string, p model.Prefix, at time.Time, canon string) {
	key := vp + "|" + p.String()
	fr := e.flaps[key]
	if fr == nil {
		fr = &flapRecord{}
		e.flaps[key] = fr
	}
	fr.lastWithdraw = at
	fr.lastRoute = canon
}

func (e *Engine) learnBaseline(o model.Observation) {
	if o.Withdraw || !e.reg.LegitOrigin(o.Origin, o.Prefix) {
		return
	}
	if len(registry.HardIssues(e.reg.PlausibilityIssues(o.ASPath, o.Origin))) > 0 {
		return
	}
	b := e.baseline[o.Prefix]
	if b == nil {
		b = &baseline{adjacents: map[model.ASN]int{}, paths: map[string]int{},
			origins: map[model.ASN]int{}, perVP: map[string]map[string]int{}}
		e.baseline[o.Prefix] = b
	}
	if adj := o.Adjacent(); adj != 0 {
		b.adjacents[adj]++
	}
	cp := canonPath(o.ASPath)
	b.paths[cp]++
	if b.perVP[o.VP] == nil {
		b.perVP[o.VP] = map[string]int{}
	}
	b.perVP[o.VP][cp]++
	b.origins[o.Origin]++
	if b.firstSeen.IsZero() || o.ReceivedAt.Before(b.firstSeen) {
		b.firstSeen = o.ReceivedAt
	}
	b.lastSeen = maxTime(b.lastSeen, o.ReceivedAt)
}

// relevant reports whether a prefix can affect our traffic: it is ours, inside
// ours, or covers ours. Everything else is dropped early — at full-table scale
// this is the difference between thousands and millions of state entries.
func (e *Engine) relevant(p model.Prefix) bool {
	if e.reg.OurPrefix(p) != nil {
		return true
	}
	return len(e.reg.CoversOurs(p)) > 0
}

// canonPath collapses repeated consecutive ASNs so prepending does not make the
// same route look new.
func canonPath(path []model.ASN) string {
	var b strings.Builder
	var prev model.ASN
	for i, a := range path {
		if i > 0 && a == prev {
			continue
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(a.String())
		prev = a
	}
	return b.String()
}

// Tick evaluates all relevant prefixes at now and returns the decision.
func (e *Engine) Tick(now time.Time) model.Decision {
	if now.After(e.now) {
		e.now = now
	}
	d := model.Decision{}

	live := e.liveVPs()
	liveCount := len(live)

	prefixes := make([]model.Prefix, 0, len(e.prefixes))
	for p := range e.prefixes {
		prefixes = append(prefixes, p)
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].String() < prefixes[j].String() })

	// Track which incidents had evidence this tick; anything else ages out.
	present := map[string]bool{}
	for _, p := range prefixes {
		e.evaluatePrefix(p, live, liveCount, now, &d, present)
	}
	e.evaluateFlaps(now, &d)

	for key, inc := range e.incid {
		if present[key] {
			continue
		}
		if !inc.raised {
			if now.Sub(inc.lastSeen) > e.cfg.ResolveAfter {
				delete(e.incid, key)
			}
			continue
		}
		if now.Sub(inc.lastSeen) <= e.cfg.ResolveAfter {
			continue
		}
		// Judge blindness from the prefix's view *now*, not from the stored
		// visibility captured when the anomaly was last seen. If the collectors
		// went silent, the stored value says "perfect visibility" precisely
		// because no contradictory observation ever arrived.
		if v := e.visibility(inc.annPrefix, live); v < e.cfg.BlindRatio {
			inc.alert.Visibility = round2(v)
			// We cannot distinguish "the route vanished" from "we went blind".
			// Flag the blind spot instead of reporting a false recovery.
			if !hasFlag(inc.alert.DataQualityFlags, "blind_at_resolution") {
				inc.alert.DataQualityFlags = append(inc.alert.DataQualityFlags, "blind_at_resolution")
				inc.alert.LastSeen = inc.lastSeen
				d.Updated = append(d.Updated, inc.alert)
			}
			continue
		}
		t := now
		inc.alert.Phase = model.PhaseResolved
		inc.alert.ResolvedAt = &t
		inc.alert.LastSeen = inc.lastSeen
		d.Updated = append(d.Updated, inc.alert)
		e.counters.Resolved++
		delete(e.incid, key)
	}

	sortAlerts(d.NewAlerts)
	sortAlerts(d.Updated)
	return d
}

// visibility is the fraction of configured collectors currently reporting a
// prefix. Zero configured VPs is treated as fully blind, which is the safe
// reading: with no collectors nothing can be confirmed.
func (e *Engine) visibility(p model.Prefix, live map[string]bool) float64 {
	total := len(e.reg.VPs)
	if total == 0 {
		total = len(e.vps)
	}
	if total == 0 {
		return 0
	}
	reporting := 0
	if st := e.prefixes[p]; st != nil {
		for vp, r := range st.routes {
			if live[vp] && !r.withdrawn {
				reporting++
			}
		}
	}
	return float64(reporting) / float64(total)
}

// liveVPs returns vantage points whose data is fresh enough to use.
func (e *Engine) liveVPs() map[string]bool {
	live := map[string]bool{}
	stale := time.Duration(e.cfg.StaleVPFactor * float64(e.cfg.SnapshotInterval))
	for name, h := range e.vps {
		if !h.lastReport.IsZero() && e.now.Sub(h.lastReport) <= stale {
			live[name] = true
		}
	}
	return live
}

// candidate is one classified view of an announcement before scoring.
type candidate struct {
	kind      model.Kind
	annPrefix model.Prefix
	origin    model.ASN
	suspect   model.ASN

	benign bool
	reason string

	signals []model.Signal
	vps     map[string]model.Observation
	routes  map[string]string
	regions []string

	firstSeen time.Time
	lastSeen  time.Time

	reporting int // live VPs that report this prefix at all
	adjacent  model.ASN
	hardIssue bool
	// scope is the settled scope of the change. It is unsettled until the
	// propagation grace period has passed; scope-based escalation must wait
	// for it, or a fleet-wide change in its first minutes looks selective.
	scope scopeClass
}

type scopeClass int

const (
	scopeUnsettled scopeClass = iota
	scopeGlobal
	scopeRegional
	scopePartial
)

func (e *Engine) evaluatePrefix(p model.Prefix, live map[string]bool, liveCount int, now time.Time, d *model.Decision, present map[string]bool) {
	st := e.prefixes[p]
	cands := e.classifyPrefix(st, p, live, now)

	for _, c := range cands {
		// The incident key is prefix+kind+suspect. It must be stable across the
		// whole life of one ongoing announcement, so it cannot include a
		// timestamp that drifts as new collectors join the view. Two genuinely
		// separate occurrences are separated instead by resolution: the key is
		// only free for reuse once the previous incident has aged out.
		key := candidateKey(*c)
		present[key] = true

		inc, isNew := e.incid[key], false
		if inc == nil {
			inc = &incident{
				// The ID includes the first-seen instant, not just the key. Two
				// separate hijacks of the same prefix by the same ASN an hour
				// apart are two incidents; reusing one ID would let a downstream
				// deduplicator swallow the second, and would erase the audit
				// trail of the first.
				key: key, id: incidentID(key, c.firstSeen), kind: c.kind,
				annPrefix: c.annPrefix, suspected: c.suspect,
				vps: map[string]model.Observation{}, routes: map[string]string{},
			}
			inc.ourPrefix = e.reg.OurPrefix(c.annPrefix)
			if inc.ourPrefix == nil {
				if covered := e.reg.CoversOurs(c.annPrefix); len(covered) > 0 {
					inc.ourPrefix = &covered[0]
				}
			}
			e.incid[key] = inc
			isNew = true
		}
		inc.lastSeen = now
		if isNew || c.firstSeen.Before(inc.firstSeen) || inc.firstSeen.IsZero() {
			inc.firstSeen = c.firstSeen
		}
		for vp, o := range c.vps {
			inc.vps[vp] = o
			inc.routes[vp] = canonPath(o.ASPath)
		}
		inc.regions = sortedUnique(append(inc.regions, c.regions...))
		inc.windows++

		// Visibility: what fraction of the *configured* fleet can see this
		// prefix right now? It must be measured against the configured fleet,
		// not the live one: a fleet that has gone silent is 0 of 16, not 0 of 0
		// and certainly not 1.0. Measuring against live VPs would let an outage
		// masquerade as perfect visibility and resolve every open incident.
		inc.visibility = e.visibility(p, live)
		if c.reporting > 0 {
			inc.coverage = float64(len(c.vps)) / float64(c.reporting)
		} else {
			inc.coverage = 1
		}

		score, signals, flags := e.score(inc, c, now)
		sev, capped := e.severity(*c, score, len(c.vps), inc.visibility)
		if capped {
			flags = append(flags, "thin_evidence")
		}
		if sev == model.SevNone || !e.eligible(inc, *c, len(c.vps), now) {
			e.counters.Suppressed++
			continue
		}

		alert := e.buildAlert(inc, *c, sev, score, signals, flags, now)
		if !inc.raised {
			inc.raised = true
			inc.alert = alert
			inc.alert.Phase = model.PhaseRaised
			d.NewAlerts = append(d.NewAlerts, alert)
			e.counters.Raised[sev]++
			continue
		}

		prev := inc.alert
		alert.FirstSeen = prev.FirstSeen
		alert.AlertedAt = prev.AlertedAt
		changed := false
		switch {
		case alert.Severity > prev.Severity:
			alert.Phase = model.PhaseEscalated
			inc.alert = alert
			changed = true
			e.counters.Escalated++
		case alert.Severity < prev.Severity:
			alert.Phase = model.PhaseDowngraded
			inc.alert = alert
			changed = true
			e.counters.Downgraded++
		case len(alert.DataQualityFlags) != len(prev.DataQualityFlags),
			len(alert.VPs) != len(prev.VPs):
			alert.Phase = prev.Phase
			inc.alert = alert
			changed = true
		default:
			// Same story, fresher numbers: keep the open alert current without
			// generating an event.
			inc.alert.LastSeen = alert.LastSeen
			inc.alert.Visibility = alert.Visibility
			inc.alert.Coverage = alert.Coverage
			inc.alert.Score = score
			inc.alert.Signals = signals
		}
		if changed {
			d.Updated = append(d.Updated, inc.alert)
		}
	}
}

func candidateKey(c candidate) string {
	base := string(c.kind) + "|" + c.annPrefix.String()
	if c.benign {
		return base + "|" + c.reason
	}
	return base + "|" + c.suspect.String()
}

// classifyPrefix groups the current per-VP routes for one announced prefix and
// classifies each group. Grouping on (origin, path) means twenty VPs agreeing
// on one announcement produce one candidate, not twenty.
func (e *Engine) classifyPrefix(st *prefixState, p model.Prefix, live map[string]bool, now time.Time) []*candidate {
	type group struct {
		origin model.ASN
		obs    map[string]model.Observation
		issues []registry.PathIssue
	}
	groups := map[string]*group{}
	reporting := 0
	for vp, r := range st.routes {
		if !live[vp] {
			continue
		}
		if r.withdrawn {
			continue
		}
		reporting++
		o := r.obs
		key := o.Origin.String() + "|" + canonPath(o.ASPath)
		g := groups[key]
		if g == nil {
			g = &group{origin: o.Origin, obs: map[string]model.Observation{},
				issues: e.reg.PlausibilityIssues(o.ASPath, o.Origin)}
			groups[key] = g
		}
		g.obs[vp] = o
	}

	var out []*candidate
	for _, g := range groups {
		c := e.classifyGroup(p, g.origin, g.obs, g.issues, reporting, now)
		if c != nil {
			out = append(out, c)
		}
	}
	return out
}

func (e *Engine) classifyGroup(annPrefix model.Prefix, origin model.ASN, obs map[string]model.Observation, issues []registry.PathIssue, reporting int, now time.Time) *candidate {
	ours := e.reg.OurPrefix(annPrefix)
	covering := e.reg.CoversOurs(annPrefix)

	c := &candidate{
		kind: model.KindUnknown, annPrefix: annPrefix, origin: origin, suspect: origin,
		vps: obs, routes: map[string]string{}, reporting: reporting,
	}
	for vp, o := range obs {
		c.routes[vp] = canonPath(o.ASPath)
		c.regions = append(c.regions, e.reg.VPRegion(vp))
		if c.firstSeen.IsZero() || o.Timestamp.Before(c.firstSeen) {
			c.firstSeen = o.Timestamp
		}
		c.lastSeen = maxTime(c.lastSeen, o.ReceivedAt)
	}
	c.regions = sortedUnique(c.regions)
	c.hardIssue = len(registry.HardIssues(issues)) > 0

	legit := e.reg.LegitOrigin(origin, annPrefix)
	adj := adjacentOf(obs)

	// 1. Recognized operations, before any suspicion.
	if auth, ok := e.reg.Authorized(origin, annPrefix, now); ok {
		c.kind, c.benign = model.KindAuthorized, true
		c.reason = "matches authorization: " + auth.Reason
		return c
	}
	if e.reg.IsScrubber(origin) {
		if agr, ok := e.reg.ScrubAgreementFor(origin, annPrefix, now); ok && e.scrubConfirmed(obs, agr) {
			c.kind, c.benign = model.KindScrubbing, true
			c.reason = fmt.Sprintf("active scrubbing session with %s for %s (cleaning community present)", origin, agr.Prefix)
			return c
		}
		// A scrubber ASN we did not schedule, or one that is not signalling
		// cleaning: this is not a scrubbing session, it is a hijack.
	}

	if ours != nil {
		if legit {
			adjOK := e.reg.PlausibleAdjacent(origin, adj)
			if !c.hardIssue && adjOK {
				// Structurally fine. It may still be a path the collectors have
				// never seen, which is the only remaining handle on a forged
				// path built entirely from real carriers -- but novelty alone is
				// too weak to open an incident (carriers re-route constantly),
				// so it is scored, not classified, and can only lift a path that
				// another signal already flagged.
				return nil
			}
			if c.hardIssue || !adjOK {
				return e.classifyPathAnomaly(c, obs, issues, adjOK, reporting)
			}
			return nil
		}
		// Foreign origin inside our space.
		if annPrefix.Bits() == ours.Bits() && annPrefix.Addr() == ours.Addr() {
			c.kind = model.KindOriginHijack
		} else if annPrefix.Bits() < ours.Bits() {
			c.kind = model.KindCoveringHijack
		} else {
			c.kind = model.KindSubPrefixHijack
		}
		return c
	}

	// 2. Announcement covers our space.
	if len(covering) > 0 {
		if legit && !c.hardIssue {
			return nil
		}
		c.kind = model.KindCoveringHijack
		return c
	}
	return nil
}

// classifyPathAnomaly decides between the legitimate and hostile readings of a
// path that is not normal: a transit switch, an operational re-route, or
// interception. The discriminator is scope plus whether the new upstream is a
// real carrier.
func (e *Engine) classifyPathAnomaly(c *candidate, obs map[string]model.Observation, issues []registry.PathIssue, adjLegit bool, reporting int) *candidate {
	adj := adjacentOf(obs)
	c.adjacent = adj
	c.suspect = adj

	hard := registry.HardIssues(issues)
	// Paths that loop, end at the wrong origin, or run through a stub cannot
	// be operational re-routes. They are fabricated or badly broken.
	if len(hard) > 0 {
		for _, h := range hard {
			if h.Code == registry.IssueStubInTransit {
				if s := stubASN(e.reg, firstPath(obs)); s != 0 {
					c.suspect = s
				}
			}
		}
		c.kind = model.KindPathHijack
		return c
	}
	// A path whose adjacent ASN we have never heard of cannot be a legitimate
	// upstream of ours.
	if !e.reg.Known(adj) {
		c.kind = model.KindPathHijack
		return c
	}
	// A known but non-carrier adjacent ASN: only our real upstreams or peers
	// can attach to us. A small eyeball network cannot.
	if !e.reg.IsTransitCapable(adj) {
		c.kind = model.KindPathHijack
		return c
	}
	// The adjacent AS is legitimate, but the path above it is not what these
	// collectors normally see. A fleet-wide change is a transit switch. A change
	// confined to a minority that persists is the signature of a selective
	// re-route or interception: the origin is right and the path is plausible,
	// so this can only be a WARNING, never a proven hijack.
	coverage := 0.0
	if reporting > 0 {
		coverage = float64(len(obs)) / float64(reporting)
	}
	if coverage >= e.cfg.GlobalCoverage {
		c.kind = model.KindTransitChange
		c.benign = true
		c.reason = fmt.Sprintf("path to %s changed at %d/%d vantage points to a known carrier (%s); consistent with a transit switch",
			c.annPrefix, len(obs), reporting, adj)
		return c
	}
	c.kind = model.KindPathHijack
	c.suspect = outsizedHop(e.reg, obs, adj)
	return c
}

func (e *Engine) scrubConfirmed(obs map[string]model.Observation, agr registry.ScrubAgreement) bool {
	if len(agr.Reasons) == 0 {
		return true
	}
	for _, o := range obs {
		for _, reason := range agr.Reasons {
			if o.HasCommunity(reason) {
				return true
			}
		}
	}
	return false
}

// severity maps a classified, scored candidate to a severity. The kind-based
// floors encode how unambiguous each pattern is; the score gate keeps weak
// evidence from paging.
// severity returns the alert severity and whether the evidence behind it was
// too thin to justify a page on its own (one collector, or a blind view).
func (e *Engine) severity(c candidate, score, anomVPs int, visibility float64) (model.Severity, bool) {
	if c.benign {
		return model.SevInfo, false
	}
	if score < e.cfg.WarningScore {
		return model.SevNone, false
	}
	sev := model.SevWarning
	// Origin-class hijacks rest on positive evidence: independent collectors
	// reporting that a foreign ASN originates our space is an impossible fact,
	// and each extra collector confirms it. Lack of broad visibility does not
	// weaken it -- nobody has to be covering the prefix for the announcement to
	// be damning. Only absence-based reasoning (path anomalies) depends on how
	// much of the fleet can see the prefix.
	originClass := false
	switch c.kind {
	case model.KindOriginHijack, model.KindCoveringHijack:
		originClass = true
		if anomVPs >= e.cfg.MinVPs {
			sev = model.SevCritical
		}
	case model.KindSubPrefixHijack:
		originClass = true
		if score >= e.cfg.CriticalScore && anomVPs >= e.cfg.MinVPs {
			sev = model.SevCritical
		}
	case model.KindPathHijack:
		switch {
		case c.hardIssue && anomVPs >= e.cfg.MinVPs:
			// A structurally impossible path is proof regardless of scope.
			sev = model.SevCritical
		case c.scope == scopeRegional && score >= e.cfg.CriticalScore && anomVPs >= e.cfg.MinVPs:
			// A plausible path seen by a minority of collectors, long after the
			// change had time to propagate: selective interception.
			sev = model.SevCritical
		case c.scope == scopeRegional:
			sev = model.SevWarning
		case c.scope == scopeUnsettled:
			// Not enough information to tell a fleet-wide re-route still in
			// flight from selective interception. Stay quiet; a real
			// interception persists and will be judged once settled.
			sev = model.SevNone
		}
	}
	// Thin evidence caps at WARNING. A single collector can be wrong in ways
	// two cannot, for every kind. A mostly blind view additionally caps
	// absence-based reasoning, because "nobody else sees this path" is exactly
	// what a blind fleet also looks like.
	thin := anomVPs < e.cfg.MinVPs
	blind := visibility < e.cfg.BlindRatio
	capped := false
	if thin || (blind && !originClass) {
		if sev > model.SevWarning {
			sev = model.SevWarning
			capped = true
		}
	}
	return sev, capped
}

// eligible decides whether an anomaly has persisted long enough to raise.
// Two thresholds apply: a window count (one odd tick is a data glitch) and, for
// evidence from a single collector, a minimum age.
func (e *Engine) eligible(inc *incident, c candidate, anomVPs int, now time.Time) bool {
	if c.benign {
		return true
	}
	if inc.windows < e.cfg.MinWindows {
		return false
	}
	if anomVPs < e.cfg.MinVPs && now.Sub(inc.firstSeen) < e.cfg.SingleVPMinAge {
		return false
	}
	return true
}

// score produces the additive score and the human-readable evidence list.
func (e *Engine) score(inc *incident, c *candidate, now time.Time) (int, []model.Signal, []string) {
	w := e.cfg.Weights
	score := 0
	signals := make([]model.Signal, 0, 6)
	var flags []string
	add := func(name string, delta int, note string) {
		if delta == 0 {
			return
		}
		score += delta
		signals = append(signals, model.Signal{Name: name, Delta: delta, Note: note})
	}

	anomVPs := len(c.vps)
	age := now.Sub(inc.firstSeen)

	switch c.kind {
	case model.KindOriginHijack:
		add("foreign_origin", w.ForeignOrigin,
			fmt.Sprintf("origin %s is not an authorized originator of %s", c.origin, c.annPrefix))
	case model.KindSubPrefixHijack:
		add("foreign_origin", w.ForeignOrigin,
			fmt.Sprintf("origin %s is not authorized for %s", c.origin, c.annPrefix))
		add("subprefix", w.SubPrefix,
			fmt.Sprintf("%s is more specific than %s and wins forwarding", c.annPrefix, oursString(inc.ourPrefix)))
	case model.KindCoveringHijack:
		add("foreign_origin", w.ForeignOrigin,
			fmt.Sprintf("origin %s is not authorized for %s", c.origin, c.annPrefix))
		if len(e.reg.CoversOurs(c.annPrefix)) > 0 {
			add("covering_prefix", w.CoveringPrefix,
				fmt.Sprintf("%s is shorter than and contains %s", c.annPrefix, oursString(inc.ourPrefix)))
		} else {
			add("covering_prefix", w.CoveringPrefix, "announcement is shorter than our prefix")
		}
	case model.KindPathHijack:
		add("unknown_upstream", w.PathUnknownAdjacent,
			fmt.Sprintf("path attaches our origin to %s, which is not one of our upstreams or peers", c.suspect))
	}

	// RPKI: a violating announcement against an existing ROA is proof of
	// misconfiguration at best. Unregistered space is no evidence either way.
	if !c.benign {
		sample := firstObs(c.vps)
		switch e.reg.ROA(c.annPrefix, sample.Origin) {
		case registry.ROAInvalid:
			add("rpki_invalid", w.RPKIInvalid, "announcement violates an existing ROA")
		case registry.ROANone:
			add("rpki_none", w.RPKINone, "no ROA covers this space")
		}
	}

	// Novelty: has anyone ever seen this exact path for this prefix?
	//
	// This is the last line of defence against a forged path that is
	// structurally perfect -- real carriers, real adjacencies, our own origin.
	// Such a route cannot be disproved, but it is new, and novelty that
	// persists across many collectors is evidence regardless of how plausible
	// the path looks. The penalty is deliberately modest and never decisive on
	// its own: carriers re-route all the time, so novelty is a weak signal that
	// only matters in combination with scope and persistence.
	if !c.benign && c.kind == model.KindPathHijack {
		base := e.baseline[inc.annPrefix]
		if base != nil && base.observations() >= e.cfg.BaselineMinSamples && !base.knownPath(firstVP(c.vps), canonPath(firstObs(c.vps).ASPath)) {
			add("unseen_path", w.NovelPath, fmt.Sprintf("path %s has never been observed for %s",
				canonPath(firstObs(c.vps).ASPath), inc.annPrefix))
		}
	}

	// Structural path problems. This is what defeats a forged path built from
	// real ASNs: the forgery still has to respect real connectivity.
	if !c.benign {
		issues := e.reg.PlausibilityIssues(firstObs(c.vps).ASPath, firstObs(c.vps).Origin)
		adjPenalty := 0
		for _, iss := range issues {
			switch iss.Code {
			case registry.IssuePathLoop:
				add("path_loop", w.PathLoop, iss.Detail)
			case registry.IssueStubInTransit:
				add("stub_in_transit", w.PathStub, iss.Detail)
			case registry.IssueOriginNotTerminal:
				add("origin_not_terminal", w.PathLoop/2, iss.Detail)
			case registry.IssueTooLong:
				add("path_too_long", w.PathTooLong, iss.Detail)
			case registry.IssueUnknownASNInTransit:
				add("unknown_asn_in_transit", w.UnknownASN, iss.Detail)
			case registry.IssueUnknownAdjacency:
				if adjPenalty < w.AdjacencyUnknownCap {
					adjPenalty += w.AdjacencyUnknown
					signals = append(signals, model.Signal{Name: "unknown_adjacency", Delta: w.AdjacencyUnknown, Note: iss.Detail})
				}
			}
		}
		score += adjPenalty
	}

	// Corroboration: independent collectors are the main defence against a
	// single collector's bad data.
	if anomVPs >= e.cfg.MinVPs && !c.benign {
		add("corroboration", w.Corroboration, fmt.Sprintf("%d independent vantage points agree", anomVPs))
	}

	// Scope. Global change across all collectors is the signature of an
	// operational event, so it discounts path anomalies. Regional change is the
	// signature of selective interception, so it adds.
	//
	// Scope is only meaningful once the change has had time to propagate: a
	// fleet-wide transit switch is visible at two collectors in its first
	// minutes and at all of them ten minutes later, so judging it early calls a
	// maintenance window "selective interception". Before the grace period the
	// engine records the scope as unsettled and applies neither adjustment.
	coverage := 0.0
	if c.reporting > 0 {
		coverage = float64(anomVPs) / float64(c.reporting)
	}
	switch c.kind {
	case model.KindPathHijack, model.KindTransitChange:
		switch {
		case age < e.cfg.PropagationGrace:
			c.scope = scopeUnsettled
			flags = append(flags, "scope_unsettled")
		case c.reporting > 0 && coverage >= e.cfg.GlobalCoverage:
			c.scope = scopeGlobal
			add("global_path_change", -w.GlobalPathChangeDiscount,
				fmt.Sprintf("%d of %d reporting vantage points changed together", anomVPs, c.reporting))
		case c.reporting > 0 && coverage <= e.cfg.RegionalCoverage && anomVPs >= 1:
			c.scope = scopeRegional
			add("regional_scope", w.RegionalBoost,
				fmt.Sprintf("seen at only %d of %d vantage points (%s): shape of selective interception",
					anomVPs, c.reporting, strings.Join(c.regions, ",")))
		default:
			c.scope = scopePartial
		}
	}

	// Persistence: a hijack that holds is materially worse than a glitch.
	if steps := int(age / (30 * time.Minute)); steps > 0 && !c.benign {
		p := steps * w.Persistence
		if p > w.PersistenceCap {
			p = w.PersistenceCap
		}
		add("persistence", p, fmt.Sprintf("observed continuously for %s", age.Round(time.Minute)))
	}

	// Data quality. Missing or late collectors make everything above less
	// certain, and that must be visible on the alert, not hidden.
	if c.reporting < e.liveCount() {
		flags = append(flags, fmt.Sprintf("only_%d_of_%d_vps_report_prefix", c.reporting, e.liveCount()))
	}
	if inc.visibility < e.cfg.BlindRatio && inc.visibility > 0 {
		flags = append(flags, "reduced_visibility")
	}
	late := 0
	for vp := range c.vps {
		if h := e.vps[vp]; h != nil && h.delayN > 0 && h.delaySum/time.Duration(h.delayN) > e.cfg.DelayWarn {
			late++
		}
	}
	if late > 0 {
		flags = append(flags, fmt.Sprintf("%d_vps_with_high_collection_delay", late))
	}
	if e.started && age < e.cfg.Warmup {
		flags = append(flags, "within_warmup")
	}

	if c.benign {
		add("recognized_operation", w.Authorized, c.reason)
	}
	if score < 0 {
		score = 0
	}
	return score, signals, flags
}

func (e *Engine) liveCount() int {
	n := 0
	stale := time.Duration(e.cfg.StaleVPFactor * float64(e.cfg.SnapshotInterval))
	for _, h := range e.vps {
		if !h.lastReport.IsZero() && e.now.Sub(h.lastReport) <= stale {
			n++
		}
	}
	return n
}

// evaluateFlaps turns bursty withdraw/reannounce cycles into one INFO event.
func (e *Engine) evaluateFlaps(now time.Time, d *model.Decision) {
	for key, fr := range e.flaps {
		if fr.lastWithdraw.IsZero() {
			continue
		}
		parts := strings.SplitN(key, "|", 2)
		if len(parts) != 2 {
			continue
		}
		vp := parts[0]
		p, err := model.ParsePrefix(parts[1])
		if err != nil {
			continue
		}
		st := e.prefixes[p]
		if st == nil {
			continue
		}
		r := st.routes[vp]
		if r == nil || r.withdrawn {
			continue
		}
		// The route came back after a withdraw: close one flap cycle.
		if !r.changedAt.Before(fr.lastWithdraw) {
			fr.events = append(fr.events, r.changedAt)
			fr.lastWithdraw = time.Time{}
		}
		cut := now.Add(-e.cfg.FlapWindow)
		keep := fr.events[:0]
		for _, ev := range fr.events {
			if ev.After(cut) {
				keep = append(keep, ev)
			}
		}
		fr.events = keep
		if len(fr.events) < e.cfg.FlapCount {
			continue
		}
		ikey := "flap|" + p.String() + "|" + vp
		inc := e.incid[ikey]
		if inc == nil {
			inc = &incident{key: ikey, id: incidentID(ikey, fr.events[0]), kind: model.KindFlap, annPrefix: p,
				ourPrefix: e.reg.OurPrefix(p), firstSeen: fr.events[0],
				vps: map[string]model.Observation{}, routes: map[string]string{}}
			e.incid[ikey] = inc
		}
		inc.lastSeen = now
		if inc.raised {
			continue
		}
		inc.raised = true
		alert := model.Alert{
			ID: inc.id, Kind: model.KindFlap, Phase: model.PhaseRaised, Severity: model.SevInfo,
			Prefix: p, OurPrefix: inc.ourPrefix, FirstSeen: fr.events[0], AlertedAt: now, LastSeen: now,
			VPs: []string{vp},
			Summary: fmt.Sprintf("%d withdraw/reannounce cycles for %s from %s within %s",
				len(fr.events), p, vp, e.cfg.FlapWindow),
			Signals: []model.Signal{{Name: "flaps", Delta: len(fr.events)}},
		}
		inc.alert = alert
		d.NewAlerts = append(d.NewAlerts, alert)
		e.counters.Raised[model.SevInfo]++
	}
}

func (e *Engine) buildAlert(inc *incident, c candidate, sev model.Severity, score int, signals []model.Signal, flags []string, now time.Time) model.Alert {
	vps := make([]string, 0, len(inc.vps))
	for vp := range inc.vps {
		vps = append(vps, vp)
	}
	sort.Strings(vps)
	paths := make([]string, 0, len(inc.routes))
	seen := map[string]bool{}
	for _, vp := range vps {
		rt := inc.routes[vp]
		if seen[rt] {
			continue
		}
		seen[rt] = true
		paths = append(paths, rt)
	}
	if len(paths) > e.cfg.MaxPathSamples {
		paths = paths[:e.cfg.MaxPathSamples]
	}
	origins := []model.ASN{}
	oSeen := map[model.ASN]bool{}
	for _, o := range inc.vps {
		if !oSeen[o.Origin] {
			oSeen[o.Origin] = true
			origins = append(origins, o.Origin)
		}
	}
	sort.Slice(origins, func(i, j int) bool { return origins[i] < origins[j] })

	a := model.Alert{
		ID: inc.id, Kind: c.kind, Phase: model.PhaseRaised, Severity: sev,
		Prefix: c.annPrefix, OurPrefix: inc.ourPrefix,
		SuspectedOrigin: c.suspect, ObservedOrigins: origins,
		VPs: vps, VPRegions: sortedUnique(append([]string{}, c.regions...)),
		PathSamples: paths, Score: score, Signals: signals,
		FirstSeen: c.firstSeen, AlertedAt: now, LastSeen: c.lastSeen,
		Visibility: round2(inc.visibility), Coverage: round2(inc.coverage),
		DataQualityFlags: flags,
	}
	if c.benign {
		a.Reason = c.reason
	}
	a.Summary = summarize(a, c, inc)
	return a
}

func summarize(a model.Alert, c candidate, inc *incident) string {
	ours := oursString(inc.ourPrefix)
	switch c.kind {
	case model.KindOriginHijack:
		return fmt.Sprintf("%s originated by %s, not an authorized originator (score %d, %d VP(s))",
			c.annPrefix, c.origin, a.Score, len(a.VPs))
	case model.KindSubPrefixHijack:
		return fmt.Sprintf("%s (inside %s) originated by %s; more-specific wins forwarding (score %d, %d VP(s))",
			c.annPrefix, ours, c.origin, a.Score, len(a.VPs))
	case model.KindCoveringHijack:
		return fmt.Sprintf("%s covers our %s and is originated by %s, not authorized (score %d, %d VP(s))",
			c.annPrefix, ours, c.origin, a.Score, len(a.VPs))
	case model.KindPathHijack:
		return fmt.Sprintf("traffic to %s (origin %s) attaches through %s, which is not a legitimate upstream (score %d, %d VP(s))",
			c.annPrefix, c.origin, c.suspect, a.Score, len(a.VPs))
	case model.KindTransitChange:
		return fmt.Sprintf("path to %s changed to carrier %s at %d/%d vantage points: transit switch, not a hijack",
			c.annPrefix, c.suspect, len(a.VPs), c.reporting)
	case model.KindScrubbing:
		return fmt.Sprintf("%s diverted to scrubbing center %s (expected while mitigation is active)", c.annPrefix, c.origin)
	case model.KindAuthorized:
		return fmt.Sprintf("%s announced by %s under an authorization", c.annPrefix, c.origin)
	default:
		return fmt.Sprintf("%s origin %s, %d VP(s), score %d", c.annPrefix, c.origin, len(a.VPs), a.Score)
	}
}

func adjacentOf(obs map[string]model.Observation) model.ASN {
	for _, o := range obs {
		if a := o.Adjacent(); a != 0 {
			return a
		}
	}
	return 0
}

func adjacentLegit(reg *registry.Registry, origin, adj model.ASN) bool {
	return reg.LegitAdjacent(origin)[adj]
}

// outsizedHop names the ASN most likely doing the intercepting when the
// adjacent AS is legitimate: the first transit ASN above the adjacent one that
// is not one of ours. It is used only for alert text and incident identity.
func outsizedHop(reg *registry.Registry, obs map[string]model.Observation, adjacent model.ASN) model.ASN {
	o := firstObs(obs)
	clean := registry.NormalizePath(o.ASPath)
	for i := len(clean) - 2; i >= 0; i-- {
		a := clean[i]
		if a == adjacent || a == o.Origin {
			continue
		}
		if reg.Known(a) {
			return a
		}
	}
	return adjacent
}

func stubASN(reg *registry.Registry, path []model.ASN) model.ASN {
	for i := 1; i < len(path)-1; i++ {
		if reg.Lookup(path[i]).NoTransit {
			return path[i]
		}
	}
	return 0
}

func firstVP(obs map[string]model.Observation) string {
	vps := make([]string, 0, len(obs))
	for vp := range obs {
		vps = append(vps, vp)
	}
	sort.Strings(vps)
	return vps[0]
}

func firstObs(obs map[string]model.Observation) model.Observation {
	vps := make([]string, 0, len(obs))
	for vp := range obs {
		vps = append(vps, vp)
	}
	sort.Strings(vps)
	return obs[vps[0]]
}

func firstPath(obs map[string]model.Observation) []model.ASN { return firstObs(obs).ASPath }

func incidentID(key string, firstSeen time.Time) string {
	sum := sha1.Sum([]byte(key + "|" + firstSeen.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(sum[:8])
}

func sortedUnique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func sortAlerts(a []model.Alert) {
	sort.SliceStable(a, func(i, j int) bool {
		if a[i].AlertedAt.Equal(a[j].AlertedAt) {
			return a[i].ID < a[j].ID
		}
		return a[i].AlertedAt.Before(a[j].AlertedAt)
	})
}

func hasFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}

func maxTime(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func round2(f float64) float64 {
	return float64(int(f*100+0.5)) / 100
}

func oursString(p *model.Prefix) string {
	if p == nil {
		return "(none)"
	}
	return p.String()
}
