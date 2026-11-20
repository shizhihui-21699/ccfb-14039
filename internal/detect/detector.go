package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"hijackwatch/internal/model"
	"hijackwatch/internal/policy"
)

// Detector consumes the multi-collector update stream and turns it into
// incidents and alerts.
//
// Pipeline for one announcement:
//
//  1. normalise & filter (ignored collector, malformed, unrelated prefix)
//  2. classify relation to our registered space (exact / more / less specific)
//  3. score origin and path structure into evidence
//  4. merge evidence for the same prefix+origin across collectors
//  5. wait a corroboration window (NeighborRTT) so we do not page on a single
//     collector's flap or a late duplicate
//  6. finalise: corroboration, policy mitigations, severity caps, fire/discard
//  7. keep upgrading a firing alert as evidence arrives; auto-resolve after
//     ResolutionWindow of silence.
//
// The detector takes an explicit clock driven by ReceivedAt so late and
// out-of-order updates are handled the same way live and offline.
type Detector struct {
	cfg  policy.Config
	regs []policy.RegisteredPrefix
	now  time.Time

	mu     sync.RWMutex
	base   *baseline
	scope  *scopeTracker
	rib    map[string]map[string]announcement // collector -> prefix string -> latest
	cands  map[string]*candidate
	alerts map[string]*model.Alert
	order  []string
	stats  Stats
	sink   func(model.Alert)
}

type announcement struct {
	prefix    netip.Prefix
	peerASN   uint32
	origin    uint32
	path      []uint32
	eventTime time.Time
	recvTime  time.Time
}

// Stats are counters exposed for /metrics.
type Stats struct {
	Received          int64
	Ignored           int64
	Unrelated         int64
	Malformed         int64
	Candidates        int64
	AlertsFired       int64
	AlertsUpgraded    int64
	AlertsResolved    int64
	CandidatesDropped int64
}

type candidate struct {
	key       string
	prefix    netip.Prefix
	prefixStr string
	parent    string
	origin    uint32
	relation  model.Relation
	kind      string

	firstRecv time.Time
	lastRecv  time.Time

	collectors map[string]time.Time
	peers      map[uint32]bool
	evidence   map[string]model.Evidence
	paths      [][]uint32
	badPath    map[string]bool // pathKey -> true, the paths that triggered this candidate
	// badUpstream holds upstream ASNs seen in an anomalous path (insertion
	// candidates), so the alert stays active only while that upstream is
	// actually in front of the prefix.
	badUpstream     map[uint32]bool
	upstreamChanges []upstreamChange
	maxScore        int
	hard            bool
	strong          bool
	approved        bool // more-specific by an approved scrubber
	known           bool
	fired           bool
	alertID         string
}

// New builds a detector from policy.
func New(cfg policy.Config) *Detector {
	return &Detector{
		cfg:    cfg,
		regs:   cfg.Registered(),
		base:   newBaseline(),
		scope:  newScopeTracker(),
		rib:    map[string]map[string]announcement{},
		cands:  map[string]*candidate{},
		alerts: map[string]*model.Alert{},
	}
}

// SetSink installs a callback invoked whenever an alert fires, changes, or
// resolves.  The callback is invoked without the detector lock held.
func (d *Detector) SetSink(fn func(model.Alert)) {
	d.mu.Lock()
	d.sink = fn
	d.mu.Unlock()
}

// Now returns the detector's clock.
func (d *Detector) Now() time.Time {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.now
}

func (d *Detector) emit(a model.Alert) {
	fn := d.sink
	if fn != nil {
		fn(a)
	}
}

// Process ingests one update and returns alerts that fired or changed as a
// direct result.
func (d *Detector) Process(u model.Update) []model.Alert {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.stats.Received++
	if u.ReceivedAt.After(d.now) {
		d.now = u.ReceivedAt
	}
	if d.cfg.IgnoredCollector(u.Collector) {
		d.stats.Ignored++
		return nil
	}
	if err := validateLite(u); err != nil {
		d.stats.Malformed++
		return nil
	}
	prefix, _ := u.ParsedPrefix()
	rp, rel, ok := d.cfg.MatchPrefix(prefix, d.regs)
	if !ok {
		d.stats.Unrelated++
		return nil
	}
	if d.rib[u.Collector] == nil {
		d.rib[u.Collector] = map[string]announcement{}
	}

	pending := d.maturedLocked(d.now)

	if u.Type == model.Withdraw {
		delete(d.rib[u.Collector], prefix.String())
		return d.drain(append(pending, d.resolveStaleLocked(d.now)...))
	}

	origin, _ := u.Origin()
	path := append([]uint32(nil), u.ASPath...)
	d.rib[u.Collector][prefix.String()] = announcement{
		prefix: prefix, peerASN: u.PeerASN, origin: origin, path: path,
		eventTime: u.EventTime, recvTime: u.ReceivedAt,
	}

	obs := d.score(u, rp, rel, origin, path)
	if obs.benign {
		// A legitimate, explained announcement: teach the baseline and the
		// peer/upstream scope model so that later deviations are visible.
		d.base.observe(u.Collector, path, origin, prefix.String())
		d.base.learnPeer(u.Collector, u.PeerASN)
		d.scope.note(penult(path), prefix.String(), u.ReceivedAt)
		return d.drain(append(pending, d.resolveStaleLocked(d.now)...))
	}
	if c := d.cands[prefix.String()+"|"+u32(origin)]; c == nil && !obs.anySignal() {
		// Nothing to learn from and nothing to alert on (e.g. an unrelated
		// less-specific we cannot use).
		return d.drain(append(pending, d.resolveStaleLocked(d.now)...))
	}

	d.stats.Candidates++
	c := d.upsertCandidate(u, prefix, rel, origin, obs)
	if c.parent == "" && rel != model.Exact {
		// For a more- or less-specific, record the registered block it belongs
		// to so the operator knows which allocation is affected.  For an exact
		// match the prefix already is the registered block.
		c.parent = rp.Prefix.String()
	}
	pending = append(pending, d.maybeFinalizeLocked(c, d.now)...)
	return d.drain(append(pending, d.resolveStaleLocked(d.now)...))
}

// Tick advances the clock, finalises matured candidates and resolves stale
// alerts.  Live deployments call it on a timer; replay calls it at intervals.
func (d *Detector) Tick(now time.Time) []model.Alert {
	d.mu.Lock()
	defer d.mu.Unlock()
	if now.After(d.now) {
		d.now = now
	}
	res := d.maturedLocked(d.now)
	res = append(res, d.resolveStaleLocked(d.now)...)
	return d.drain(res)
}

// Flush finalises every pending candidate immediately.  Used at end of replay.
func (d *Detector) Flush() []model.Alert {
	d.mu.Lock()
	defer d.mu.Unlock()
	var res []model.Alert
	keys := sortedCandidateKeys(d.cands)
	for _, k := range keys {
		if c := d.cands[k]; c != nil && !c.fired {
			res = append(res, d.finalizeLocked(c, d.now, true)...)
		}
	}
	return d.drain(res)
}

func (d *Detector) drain(in []model.Alert) []model.Alert {
	// Deduplicate by ID+UpdatedAt for callers that get the same alert twice
	// through two paths (pending finalisation + stale resolution).
	if len(in) < 2 {
		return in
	}
	seen := map[string]bool{}
	out := in[:0]
	for _, a := range in {
		k := a.ID + "|" + string(a.Status) + "|" + strconv.FormatInt(a.UpdatedAt.UnixNano(), 10)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, a)
	}
	return out
}

func (d *Detector) maturedLocked(now time.Time) []model.Alert {
	var res []model.Alert
	for _, k := range sortedCandidateKeys(d.cands) {
		c := d.cands[k]
		if c.fired {
			continue
		}
		if now.Sub(c.firstRecv) >= d.cfg.NeighborRTT {
			res = append(res, d.finalizeLocked(c, now, false)...)
		}
	}
	return res
}

func (d *Detector) resolveStaleLocked(now time.Time) []model.Alert {
	var res []model.Alert
	for _, id := range d.order {
		a := d.alerts[id]
		if a == nil || a.Status != model.StatusFiring {
			continue
		}
		// While any observation point still holds the anomalous route, the
		// incident is live: refresh LastSeen so it does not auto-resolve out
		// from under the operator.
		if c := d.cands[a.CandKey]; c != nil {
			if active := d.activeCollectors(c); len(active) > 0 {
				a.LastSeen = now
				continue
			}
		}
		if now.Sub(a.LastSeen) >= d.cfg.ResolutionWindow {
			t := now
			a.Status = model.StatusResolved
			a.ResolvedAt = &t
			a.UpdatedAt = now
			a.Timeline = append(a.Timeline, model.TimelineEntry{
				At: now, Event: "resolved", Severity: a.Severity, Score: a.Score,
				Detail: "no new evidence for " + d.cfg.ResolutionWindow.String(),
			})
			d.stats.AlertsResolved++
			res = append(res, *a)
			d.emit(*a)
			// Detach the candidate so a later recurrence of the same
			// (prefix,origin) opens a fresh incident instead of being absorbed
			// into a resolved alert that would never page again.
			if c := d.cands[a.CandKey]; c != nil {
				delete(d.cands, c.key)
			}
		}
	}
	return res
}

// ---- scoring ----

type obsResult struct {
	kind     string
	score    int
	hard     bool
	strong   bool
	approved bool
	benign   bool
	// ownMoreSpecific marks a more-specific announced with our own origin; it
	// is benign unless a forgery signal (unseen peer) also fires.
	ownMoreSpecific bool
	// upstreamChanges records the (collector,prefix) upstream changes seen for
	// this announcement, so the caller can evaluate scope at finalisation.
	upstreamChanges []upstreamChange
	ev              []model.Evidence
}

// upstreamChange is one observation that a collector's upstream for a prefix
// changed to asn (from prev).
type upstreamChange struct {
	collector, prefix string
	asn, prev         uint32
	intruder          bool // asn was never seen anywhere before
}

func (o obsResult) anySignal() bool { return o.score > 0 || len(o.ev) > 0 }

// score classifies one announcement.  The order of checks matters: the
// "is this explained?" tests run first, and only an unexplained structure goes
// on to accumulate signal.  A legitimate announcement is *benign* and teaches
// the baseline; everything else becomes a candidate.
//
// The hard problem this function is built around is that several legitimate
// operations produce a route that is indistinguishable from an attack in a
// single update: the detector therefore only ever *classifies*, and leaves the
// decision of whether to page to corroboration and scope in finalizeLocked.
func (d *Detector) score(u model.Update, rp policy.RegisteredPrefix, rel model.Relation, origin uint32, path []uint32) obsResult {
	w := d.cfg.Weights
	res := obsResult{kind: model.KindPathChange}
	add := func(e model.Evidence) {
		if e.Weight == 0 {
			return
		}
		res.score += e.Weight
		res.hard = res.hard || e.Hard
		res.strong = res.strong || e.Strong
		res.ev = append(res.ev, e)
	}

	expectedOrigin := rp.Origins[origin]
	approvedCleaner := rp.CleaningASNs[origin]

	// 1. Origin correctness.  This is the one axis where a single update can be
	//    conclusive, so a wrong origin is hard evidence.
	wrongOrigin := false
	switch rel {
	case model.Exact:
		if !expectedOrigin {
			wrongOrigin = true
			res.kind = model.KindBogusOrigin
			add(model.Evidence{Code: "origin.unexpected", Weight: w.WeightWrongOrigin, Hard: true,
				Detail: "exact prefix announced by unexpected origin AS" + u32(origin)})
		}
	case model.MoreSpecific:
		res.kind = model.KindSubprefix
		switch {
		case approvedCleaner:
			res.approved = true
			// Authorised scrubbing: benign *if* the path also looks sane.
			add(model.Evidence{Code: "prefix.approved_cleanup", Weight: w.WeightApprovedCleanup,
				Detail: "more-specific " + u.Prefix + " announced by approved scrubber AS" + u32(origin)})
		case expectedOrigin:
			// Our own origin carving out a more-specific: normally TE.  But a
			// hijacker can forge the origin too, so a more-specific by *our*
			// origin over a path whose peer has never been seen for us is the
			// forged-path shape.  Defer that judgement to the new-peer check
			// below; here we simply do not treat it as automatically benign.
			add(model.Evidence{Code: "prefix.more_specific_own_origin", Weight: w.WeightMoreSpecific,
				Detail: "more-specific " + u.Prefix + " by expected origin AS" + u32(origin)})
			res.ownMoreSpecific = true
		default:
			wrongOrigin = true
			add(model.Evidence{Code: "prefix.more_specific", Weight: w.WeightMoreSpecific,
				Detail: "more-specific " + u.Prefix + " of " + rp.Prefix.String()})
			add(model.Evidence{Code: "origin.unexpected", Weight: w.WeightWrongOrigin, Hard: true,
				Detail: "origin AS" + u32(origin) + " is not expected for " + rp.Prefix.String()})
		}
	case model.LessSpecific:
		// Background aggregates that merely contain us are common and harmless
		// (they lose to our more-specifics).  Only an aggregate announced by an
		// unexpected origin *and* seen as a covering route is interesting.
		if expectedOrigin {
			return obsResult{benign: true}
		}
		res.kind = model.KindBogusOrigin
		add(model.Evidence{Code: "prefix.covering_aggregate", Weight: w.WeightMoreSpecific / 2, Strong: true,
			Detail: "covering aggregate " + u.Prefix + " announced by AS" + u32(origin)})
		add(model.Evidence{Code: "origin.unexpected", Weight: w.WeightWrongOrigin, Hard: true,
			Detail: "origin AS" + u32(origin) + " is not expected to cover " + rp.Prefix.String()})
	}

	// 2. Path structure.  Applies to everything that touches our space.
	if why := d.absurdPath(path, origin); why != "" {
		add(model.Evidence{Code: "path.absurd", Weight: w.WeightAbsurdPath, Hard: true, Detail: why})
		res.kind = model.KindForgedPath
	}
	if n, asn := prependLoop(path); n > 0 && !d.base.isKnownASN(asn) {
		add(model.Evidence{Code: "path.prepended_loop", Weight: w.WeightPrependedLoop, Strong: true,
			Detail: "unknown AS" + u32(asn) + " prepended " + strconv.Itoa(n) + " times in " + pathString(path)})
	}
	if asn, ok := firstSuspiciousASN(path); ok {
		add(model.Evidence{Code: "path.suspicious_asn", Weight: w.WeightSuspiciousASN,
			Detail: "AS" + u32(asn) + " is " + string(model.ClassifyASN(asn)) + "; path " + pathString(path)})
	}
	if asn, ok := d.recentSuspiciousIn(path); ok {
		add(model.Evidence{Code: "path.known_malicious_asn", Weight: w.WeightSuspiciousASN,
			Detail: "AS" + u32(asn) + " was recently involved in hijacks; path " + pathString(path)})
	}

	// 3. Structural novelty relative to learned normal.  Weak on its own: a
	//    carrier switch creates a completely new path too.  It explains *why*
	//    an unexpected structure is unexpected.
	_, nev := d.base.noveltyCapped(path, origin)
	for _, e := range nev {
		add(e)
	}

	// 4. The central path-anomaly test: same collector, same prefix, upstream
	//    changed from what that collector has been using.  This is what both a
	//    legitimate transit change and a stealth insertion look like.  The only
	//    honest discriminator is scope — how many of our prefixes this upstream
	//    fronts right now.  Scope is evaluated at finalisation, once every
	//    collector in the corroboration window has reported, because a provider
	//    change arrives from many collectors at once while an insertion only
	//    needs one victim block.
	if changed, prev, _ := d.base.upstreamChange(u.Collector, u.Prefix, path); changed {
		pen := penult(path)
		// An upstream we have never seen anywhere before is an intruder; an
		// upstream we have seen is either a legitimate provider or a return to
		// normal.  Only record the intruder as a "bad upstream", otherwise the
		// recovery itself would keep the alert alive forever.
		intruder := !d.base.isKnownASN(pen)
		res.upstreamChanges = append(res.upstreamChanges, upstreamChange{
			collector: u.Collector, prefix: u.Prefix, asn: pen, prev: prev, intruder: intruder,
		})
		res.strong = intruder
		res.ev = append(res.ev, model.Evidence{Code: "path.upstream_changed", Weight: 0, Strong: intruder,
			Detail: "AS" + u32(pen) + " replaces AS" + u32(prev) + " in front of " + u.Prefix +
				" for " + u.Collector})
	}

	// 5. A path arriving from a peer this collector has never reported for us.
	//    A genuinely new session is common, so on its own this is weak.  But a
	//    more-specific announced with *our* origin over an unseen peer is the
	//    forged-path shape: whoever injects a more-specific must also inject a
	//    path, and a forged path usually keeps the real origin.
	if u.PeerASN != 0 && !d.base.peerKnown(u.Collector, u.PeerASN) {
		e := model.Evidence{Code: "path.new_peer", Weight: w.WeightNewUpstreamASN / 2,
			Detail: "collector " + u.Collector + " has never reported peer AS" + u32(u.PeerASN)}
		if res.ownMoreSpecific {
			e.Weight = w.WeightNewUpstreamASN * 2
			e.Strong = true
			e.Detail += "; more-specific of our block with our origin over an unseen peer (possible forged path)"
		}
		add(e)
	}

	// Decide.  A more-specific by an approved scrubber, or by our own origin,
	// with no hard or strong signal, is benign and safe to learn from.  A route
	// with an expected origin but only weak novelty is also benign: that is
	// what a normal path change looks like and we must not page on it.
	if !res.hard && !res.strong {
		if res.approved || expectedOrigin {
			if !wrongOrigin {
				return obsResult{benign: true}
			}
		}
	}
	if res.kind == model.KindPathChange && res.strong && expectedOrigin {
		res.kind = model.KindPathInsertion
	}
	if res.kind == model.KindPathChange && res.hard {
		res.kind = model.KindForgedPath
	}
	if res.ownMoreSpecific && res.strong {
		res.kind = model.KindForgedPath
	}
	return res
}

func (d *Detector) absurdPath(path []uint32, origin uint32) string {
	if len(path) > d.cfg.MaxPlausibleASPathLen {
		return "AS path length " + strconv.Itoa(len(path)) + " exceeds plausible maximum " +
			strconv.Itoa(d.cfg.MaxPlausibleASPathLen)
	}
	seen := map[uint32]bool{}
	for i, a := range path {
		// Our own origin repeated mid-path: we are used as our own transit.
		if a == origin && origin != 0 && i < len(path)-1 {
			return "origin AS" + u32(origin) + " appears mid-path at position " +
				strconv.Itoa(i) + " of " + strconv.Itoa(len(path)) + ": " + pathString(path)
		}
		// Very tight cycles of real ASes are not a thing.
		if i >= 2 && path[i] == path[i-2] && path[i] != path[i-1] && !seen[path[i]] {
			return "AS path contains a tight cycle at position " + strconv.Itoa(i) + ": " + pathString(path)
		}
		seen[a] = true
	}
	return ""
}

func prependLoop(path []uint32) (int, uint32) {
	counts := map[uint32]int{}
	var maxASN uint32
	max := 0
	for _, a := range path {
		counts[a]++
		if counts[a] > max {
			max = counts[a]
			maxASN = a
		}
	}
	if max >= 4 {
		return max, maxASN
	}
	return 0, 0
}

func firstSuspiciousASN(path []uint32) (uint32, bool) {
	for _, a := range path {
		if model.IsSuspiciousASN(a) {
			return a, true
		}
	}
	return 0, false
}

func (d *Detector) recentSuspiciousIn(path []uint32) (uint32, bool) {
	for _, a := range path {
		for _, s := range d.cfg.SuspiciousRecentASNs {
			if a == s {
				return a, true
			}
		}
	}
	return 0, false
}

// ---- candidate lifecycle ----

func (d *Detector) upsertCandidate(u model.Update, prefix netip.Prefix, rel model.Relation, origin uint32, obs obsResult) *candidate {
	key := prefix.String() + "|" + u32(origin)
	c := d.cands[key]
	if c == nil {
		c = &candidate{
			key: key, prefix: prefix, prefixStr: prefix.String(), origin: origin,
			relation: rel, kind: obs.kind,
			firstRecv: u.ReceivedAt, lastRecv: u.ReceivedAt,
			collectors: map[string]time.Time{}, peers: map[uint32]bool{},
			evidence: map[string]model.Evidence{}, badPath: map[string]bool{}, badUpstream: map[uint32]bool{},
		}
		d.cands[key] = c
	}
	if u.ReceivedAt.After(c.lastRecv) {
		c.lastRecv = u.ReceivedAt
	}
	if u.ReceivedAt.Before(c.firstRecv) {
		c.firstRecv = u.ReceivedAt
	}
	c.collectors[u.Collector] = u.ReceivedAt
	if u.PeerASN != 0 {
		c.peers[u.PeerASN] = true
	}
	c.hard = c.hard || obs.hard
	c.strong = c.strong || obs.strong
	c.approved = c.approved || obs.approved
	if len(obs.upstreamChanges) > 0 {
		c.upstreamChanges = append(c.upstreamChanges, obs.upstreamChanges...)
	}
	if obs.score > c.maxScore {
		c.maxScore = obs.score
	}
	for _, e := range obs.ev {
		if old, ok := c.evidence[e.Code]; !ok || e.Weight > old.Weight {
			c.evidence[e.Code] = e
		}
	}
	if len(c.paths) < 16 {
		c.paths = append(c.paths, append([]uint32(nil), u.ASPath...))
	}
	if obs.hard || obs.strong {
		c.badPath[pathKey(u.ASPath)] = true
	}
	for _, uc := range obs.upstreamChanges {
		if uc.intruder {
			c.badUpstream[uc.asn] = true
		}
	}
	if kindRank(obs.kind) > kindRank(c.kind) {
		c.kind = obs.kind
	}
	if c.fired {
		d.upgradeLocked(c, u.ReceivedAt)
	}
	return c
}

func kindRank(k string) int {
	switch k {
	case model.KindSubprefix, model.KindBogusOrigin:
		return 4
	case model.KindForgedPath:
		return 3
	case model.KindPathInsertion:
		return 2
	case model.KindPathChange:
		return 1
	}
	return 0
}

// maybeFinalizeLocked decides whether a candidate has enough corroboration to
// be judged before its NeighborRTT window closes.
func (d *Detector) maybeFinalizeLocked(c *candidate, now time.Time) []model.Alert {
	if c.fired {
		return nil
	}
	active := d.activeCollectors(c)
	switch {
	case c.hard && len(active) >= d.cfg.MinCollectors:
		return d.finalizeLocked(c, now, false)
	case c.hard && len(active) >= 1 && c.maxScore >= d.cfg.Weights.ScoreHigh:
		// One collector independently holding a conclusive wrong origin is
		// worth judging now; being wrong costs only a High page.
		return d.finalizeLocked(c, now, false)
	}
	return nil
}

func (d *Detector) finalizeLocked(c *candidate, now time.Time, force bool) []model.Alert {
	if c.fired {
		return d.upgradeLocked(c, now)
	}
	active := d.activeCollectors(c)

	if !force && len(active) == 0 && !c.hard {
		// Every collector that ever showed the anomaly has reverted: flap.
		d.stats.CandidatesDropped++
		delete(d.cands, c.key)
		return nil
	}
	if !force && now.Sub(c.firstRecv) < d.cfg.NeighborRTT {
		return nil
	}

	score, ev, mitigated := d.aggregate(c, len(active))
	sev := d.severity(score, len(active), c)
	if sev < d.cfg.MinAlertSeverity {
		delete(d.cands, c.key)
		d.stats.CandidatesDropped++
		return nil
	}

	id := stableID(c)
	a := &model.Alert{
		ID: id, IncidentID: "inc-" + id, Kind: c.kind,
		Prefix: c.prefixStr, Parent: c.parent, Origin: c.origin,
		Status: model.StatusFiring, Severity: sev, Score: score,
		Confidence: confidence(len(active), c.hard, c.strong, mitigated),
		FirstSeen:  c.firstRecv, LastSeen: c.lastRecv, UpdatedAt: now,
		Collectors: sortedKeys(c.collectors),
		Evidence:   ev,
		Summary:    summary(c.kind, c.prefixStr, c.origin, sev, len(active)),
		CandKey:    c.key,
		Timeline: []model.TimelineEntry{{
			At: now, Event: "fired", Severity: sev, Score: score,
			Detail: fmt.Sprintf("%d observation point(s), %d evidence signals", len(active), len(ev)),
		}},
	}
	d.alerts[id] = a
	d.order = append(d.order, id)
	c.fired = true
	c.alertID = id
	d.stats.AlertsFired++
	d.emit(*a)
	return []model.Alert{*a}
}

func (d *Detector) upgradeLocked(c *candidate, now time.Time) []model.Alert {
	a := d.alerts[c.alertID]
	if a == nil || a.Status != model.StatusFiring {
		return nil
	}
	if !c.lastRecv.After(now) && !now.After(a.UpdatedAt) {
		// No newer observation than the alert already reflects.
	}
	active := d.activeCollectors(c)
	score, ev, mitigated := d.aggregate(c, len(active))
	sev := d.severity(score, len(active), c)

	changed := false
	if sev > a.Severity {
		a.Timeline = append(a.Timeline, model.TimelineEntry{
			At: now, Event: "upgraded", Severity: sev, Score: score,
			Detail: fmt.Sprintf("severity %s -> %s", a.Severity, sev),
		})
		a.Severity = sev
		changed = true
	}
	if len(ev) > len(a.Evidence) || score > a.Score {
		changed = true
	}
	a.Evidence = ev
	if score > a.Score {
		a.Score = score
	}
	if cf := confidence(len(active), c.hard, c.strong, mitigated); cf > a.Confidence {
		a.Confidence = cf
	}
	if c.lastRecv.After(a.LastSeen) {
		a.LastSeen = c.lastRecv
		changed = true
	}
	a.Collectors = sortedKeys(c.collectors)
	a.UpdatedAt = now
	a.Summary = summary(c.kind, c.prefixStr, c.origin, a.Severity, len(active))
	if changed {
		d.stats.AlertsUpgraded++
		d.emit(*a)
		return []model.Alert{*a}
	}
	return nil
}

// aggregate folds candidate evidence into a final score and applies
// corrobation bonuses and policy mitigations.
func (d *Detector) aggregate(c *candidate, activeCollectors int) (int, []model.Evidence, bool) {
	w := d.cfg.Weights
	score := 0
	ev := make([]model.Evidence, 0, len(c.evidence)+3)
	for _, e := range c.evidence {
		score += e.Weight
		ev = append(ev, e)
	}
	sort.SliceStable(ev, func(i, j int) bool { return ev[i].Weight > ev[j].Weight })

	mitigated := false
	if c.approved {
		mitigated = true
	}

	// Resolve upstream changes now that every collector in the corroboration
	// window has reported: a change that fronts several of our prefixes is a
	// provider re-homing; a change that fronts exactly one is the insertion
	// shape.  Scope is measured across all our prefixes, not just this one.
	if len(c.upstreamChanges) > 0 {
		var narrow *upstreamChange
		wide := 0
		seenASN := map[uint32]bool{}
		for i := range c.upstreamChanges {
			uc := &c.upstreamChanges[i]
			if !uc.intruder || seenASN[uc.asn] {
				continue
			}
			seenASN[uc.asn] = true
			scope := d.scope.scopeLive(uc.asn, d.rib, d.now, d.cfg.PathHistoryWindow)
			if scope <= 1 {
				if narrow == nil {
					narrow = uc
				}
			} else {
				wide++
			}
		}
		if narrow != nil {
			score += w.WeightNewUpstreamASN * 3
			ev = append(ev, model.Evidence{Code: "path.upstream_replaced_narrow", Weight: w.WeightNewUpstreamASN * 3, Strong: true,
				Detail: "AS" + u32(narrow.asn) + " replaced AS" + u32(narrow.prev) + " in front of " +
					narrow.prefix + " for " + narrow.collector + " and fronts no other prefix"})
		}
		if wide > 0 {
			score -= w.WeightNewUpstreamASN
			ev = append(ev, model.Evidence{Code: "path.upstream_replaced_wide", Weight: -w.WeightNewUpstreamASN, Mitigation: true,
				Detail: fmt.Sprintf("%d new upstream(s) front several of our prefixes (carrier-wide change)", wide)})
			mitigated = true
		}
	}

	for _, e := range ev {
		if e.Mitigation && e.Weight < 0 {
			mitigated = true
		}
	}
	if activeCollectors >= d.cfg.MinCollectors {
		score += w.WeightMultiCollector
		ev = append(ev, model.Evidence{Code: "corroboration.multi_collector", Weight: w.WeightMultiCollector,
			Detail: fmt.Sprintf("%d independent observation points agree", activeCollectors)})
	}
	if len(c.collectors) >= 3 {
		score += w.WeightCrossCollector
		ev = append(ev, model.Evidence{Code: "corroboration.wide", Weight: w.WeightCrossCollector,
			Detail: fmt.Sprintf("%d observation points reported the anomaly", len(c.collectors))})
	}
	if d.matchKnown(c) {
		c.known = true
		score -= w.WeightKnownIncident
		ev = append(ev, model.Evidence{Code: "policy.known_incident", Weight: -w.WeightKnownIncident,
			Mitigation: true, Detail: "matches an operator-registered known incident"})
		mitigated = true
	}
	if score < 0 {
		score = 0
	}
	return score, ev, mitigated
}

func (d *Detector) matchKnown(c *candidate) bool {
	for peer := range c.peers {
		if _, ok := d.cfg.MatchKnownIncident(peer, c.prefix, d.now); ok {
			return true
		}
	}
	// A known incident may name an ASN that appears in the path (an approved
	// transit during a migration) rather than the collector's peer.  Match
	// those too, since that is what the operator actually registered.
	for _, path := range c.paths {
		for _, asn := range path {
			if _, ok := d.cfg.MatchKnownIncident(asn, c.prefix, d.now); ok {
				return true
			}
		}
	}
	_, ok := d.cfg.MatchKnownIncident(0, c.prefix, d.now)
	return ok
}

// severity maps a score to a severity with structural caps:
//
//   - a single observation point can never page above High, and only with
//     hard evidence; soft single-collector signals cap at Low;
//   - an approved scrubbing more-specific caps at Low unless hard evidence
//     also fired;
//   - no active observation point means no alert.
func (d *Detector) severity(score int, activeCollectors int, c *candidate) model.Severity {
	w := d.cfg.Weights
	var sev model.Severity
	switch {
	case score >= w.ScoreCritical:
		sev = model.SevCritical
	case score >= w.ScoreHigh:
		sev = model.SevHigh
	case score >= w.ScoreMedium:
		sev = model.SevMedium
	case score >= w.ScoreLow:
		sev = model.SevLow
	default:
		sev = model.SevInfo
	}
	if c.approved && !c.hard && sev > model.SevLow {
		sev = model.SevLow
	}
	// An operator-registered change window is triage-only: it should still be
	// visible and explained, but never page.
	if c.known && sev > model.SevLow {
		sev = model.SevLow
	}
	if activeCollectors <= 1 {
		if c.hard {
			if sev > model.SevHigh {
				sev = model.SevHigh
			}
		} else if sev > model.SevLow {
			sev = model.SevLow
		}
	}
	if len(c.collectors) == 0 {
		sev = model.SevInfo
	}
	return sev
}

// activeCollectors returns collectors whose current RIB still shows the
// anomalous announcement for this candidate.  For an origin hijack that means
// the prefix is present under the wrong origin; for a path anomaly (where the
// origin is legitimately ours) it means the exact bad path is still present.
func (d *Detector) activeCollectors(c *candidate) []string {
	var out []string
	for col := range c.collectors {
		rib := d.rib[col]
		if rib == nil {
			continue
		}
		a, ok := rib[c.prefixStr]
		if !ok || a.origin != c.origin {
			continue
		}
		if len(c.badPath) > 0 && c.badPath[pathKey(a.path)] {
			out = append(out, col)
			continue
		}
		if len(c.badUpstream) > 0 && len(a.path) >= 2 && c.badUpstream[a.path[len(a.path)-2]] {
			out = append(out, col)
			continue
		}
	}
	return out
}

// ---- helpers ----

func validateLite(u model.Update) error {
	if _, err := u.ParsedPrefix(); err != nil {
		return err
	}
	if u.Type == model.Announce && len(u.ASPath) == 0 {
		return fmt.Errorf("announce without as_path")
	}
	return nil
}

func stableID(c *candidate) string {
	h := sha256.Sum256([]byte(c.key + "|" + strconv.FormatInt(c.firstRecv.Unix(), 10)))
	return hex.EncodeToString(h[:8])
}

func summary(kind, prefix string, origin uint32, sev model.Severity, collectors int) string {
	switch kind {
	case model.KindBogusOrigin:
		return fmt.Sprintf("%s: %s announced by unexpected origin AS%d from %d observation point(s)", sev, prefix, origin, collectors)
	case model.KindSubprefix:
		return fmt.Sprintf("%s: more-specific %s announced by AS%d from %d observation point(s)", sev, prefix, origin, collectors)
	case model.KindPathInsertion:
		return fmt.Sprintf("%s: path to %s changed through an unknown upstream from %d observation point(s)", sev, prefix, collectors)
	case model.KindForgedPath:
		return fmt.Sprintf("%s: implausible or forged AS path for %s from %d observation point(s)", sev, prefix, collectors)
	default:
		return fmt.Sprintf("%s: path change for %s from %d observation point(s)", sev, prefix, collectors)
	}
}

func confidence(collectors int, hard, strong, mitigated bool) float64 {
	c := 0.30 + 0.12*float64(collectors)
	if hard {
		c += 0.30
	}
	if strong {
		c += 0.15
	}
	if mitigated {
		c -= 0.15
	}
	if c < 0.05 {
		c = 0.05
	}
	if c > 0.99 {
		c = 0.99
	}
	return float64(int(c*100+0.5)) / 100
}

func sortedCandidateKeys(m map[string]*candidate) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func u32(v uint32) string { return strconv.FormatUint(uint64(v), 10) }

func pathString(path []uint32) string {
	parts := make([]string, len(path))
	for i, a := range path {
		parts[i] = strconv.FormatUint(uint64(a), 10)
	}
	return strings.Join(parts, " ")
}

func penult(path []uint32) uint32 {
	if len(path) < 2 {
		return 0
	}
	return path[len(path)-2]
}

// ---- accessors ----

// Alerts returns a snapshot of all alerts, most recently updated first.
func (d *Detector) Alerts() []model.Alert {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]model.Alert, 0, len(d.alerts))
	for _, a := range d.alerts {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt.Equal(out[j].UpdatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].UpdatedAt.After(out[j].UpdatedAt)
	})
	return out
}

// Alert returns one alert by ID.
func (d *Detector) Alert(id string) (model.Alert, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	a, ok := d.alerts[id]
	if !ok {
		return model.Alert{}, false
	}
	return *a, true
}

// StatsSnapshot returns a copy of the counters.
func (d *Detector) StatsSnapshot() Stats {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.stats
}

// CandidateCount returns how many candidates are still being evaluated.
func (d *Detector) CandidateCount() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.cands)
}
