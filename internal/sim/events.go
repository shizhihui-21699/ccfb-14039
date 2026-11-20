package sim

import (
	"sort"
	"time"

	"routewatch/internal/model"
)

// Injection is one scripted change to the simulated routing state. The
// generator applies injections to a per-VP view of each prefix and emits the
// resulting observations, stamping the configured collection latency. Labels
// are derived from the injections, never from the observations.
type Injection struct {
	Kind EventKind
	// Prefix is the prefix announced (not necessarily one of ours: a covering
	// hijack announces a shorter prefix).
	Prefix model.Prefix
	// Origin is the announcing ASN.
	Origin model.ASN
	// Path is the full AS path as it should appear. Nil means "build a normal
	// path for this prefix and origin".
	Path []model.ASN
	// VPs limits the injection to some collectors. Empty means all.
	VPs []string
	// Start and End bound visibility. A zero End means "until scenario end".
	Start time.Time
	End   time.Time
	// Communities ride along on the announcement.
	Communities []string
	// Reason is human text used in labels and logs.
	Reason string
	// Label, when set, marks this injection as ground truth in the evaluator.
	// Baseline and ambient churn carry no label.
	Label *model.Label
	// Prepend adds extra copies of Origin at the tail on some VPs, modelling
	// traffic engineering.
	Prepend    int
	PrependVPs []string
	// FlapEvery is, for maintenance injections, the interval between the
	// withdraw and the reannounce. Zero means the default (90s).
	FlapEvery time.Duration
}

func (in Injection) coversVP(vp string) bool {
	if len(in.VPs) == 0 {
		return true
	}
	for _, v := range in.VPs {
		if v == vp {
			return true
		}
	}
	return false
}

func (in Injection) prependsVP(vp string, rng intn) bool {
	if in.Prepend <= 0 {
		return false
	}
	if len(in.PrependVPs) > 0 {
		for _, v := range in.PrependVPs {
			if v == vp {
				return true
			}
		}
		return false
	}
	// Default: roughly 40% of collectors see the longer path, which is what a
	// real traffic-engineering prepend looks like from a collector fleet.
	return rng.intn(10) < 4
}

func (in Injection) activeAt(t time.Time) bool {
	if t.Before(in.Start) {
		return false
	}
	if !in.End.IsZero() && !t.Before(in.End) {
		return false
	}
	return true
}

// Timeline is a scenario under construction.
type Timeline struct {
	Start      time.Time
	End        time.Time
	Injections []Injection
}

// Add appends injections and keeps the slice ordered by start time.
func (tl *Timeline) Add(in ...Injection) {
	tl.Injections = append(tl.Injections, in...)
	sort.SliceStable(tl.Injections, func(i, j int) bool {
		return tl.Injections[i].Start.Before(tl.Injections[j].Start)
	})
}

// Labels derives ground truth from labelled injections.
func (tl *Timeline) Labels() []model.Label {
	var out []model.Label
	for _, in := range tl.Injections {
		if in.Label == nil {
			continue
		}
		l := *in.Label
		if l.End.IsZero() {
			l.End = tl.End
		}
		if l.Start.IsZero() {
			l.Start = in.Start
		}
		// A label whose window started after the scenario ended (or which the
		// scenario truncates to nothing) describes an event the feed cannot
		// contain. Emitting it would score the scenario against something it
		// never simulated, which is how short scenarios produce phantom misses.
		if !l.Start.Before(tl.End) {
			continue
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

// intn is the tiny RNG surface the script builders need, so they can be
// unit-tested with a deterministic stub.
type intn interface{ intn(n int) int }

// buildHijackScripts lays out the injected attacks. The spacing is irregular on
// purpose: attackers do not attack on round numbers, and the detector must not
// depend on neat timing.
func buildHijackScripts(w *World, tl *Timeline, rng intn) []Injection {
	d := tl.End.Sub(tl.Start)
	reg := w.Reg
	self := reg.SelfASN

	primary := reg.OurPrefixes[0]
	legacy := reg.OurPrefixes[len(reg.OurPrefixes)-1]
	anycast := model.MustPrefix("203.0.113.0/24")
	for _, p := range reg.OurPrefixes {
		if p.String() == anycast.String() {
			anycast = p
		}
	}

	at := func(frac float64) time.Time { return tl.Start.Add(time.Duration(float64(d) * frac)) }

	var out []Injection

	// ---- Incident A: origin hijack of the legacy block -----------------
	// The legacy block has no ROA, so the only check that can catch this is
	// the origin/authorization one. The attacker uses a real hosting ASN and a
	// clean two-AS path, and announces globally: an attacker wants all traffic.
	aStart := at(0.12).Add(time.Duration(rng.intn(1200)) * time.Second)
	aEnd := aStart.Add(3*time.Hour + 20*time.Minute)
	out = append(out, Injection{
		Kind: EvOriginHijack, Prefix: legacy, Origin: 400666,
		Path:  []model.ASN{1299, 400666},
		Start: aStart, End: aEnd,
		Reason: "QuickHost-LLC originates our legacy /24",
		Label: &model.Label{
			ID: "hijack-origin-legacy", Kind: model.KindOriginHijack, Prefix: legacy,
			AttackerASN: 400666, Start: aStart, End: aEnd,
			Description: "origin hijack of the legacy /24 (no ROA protects it)", MustAlert: true,
		},
	})

	// ---- Incident B: regional sub-prefix hijack ------------------------
	// Carves a /24 out of our /23 and announces it only to APAC collectors.
	// More-specific wins forwarding there. A global-scope heuristic misses it
	// entirely; only persistence plus a small, consistent VP set catches it.
	bStart := at(0.34).Add(time.Duration(rng.intn(1500)) * time.Second)
	bEnd := bStart.Add(5 * time.Hour)
	out = append(out, Injection{
		Kind: EvSubPrefix, Prefix: model.MustPrefix("198.51.100.0/24"), Origin: 400666,
		Path:  []model.ASN{3491, 4637, 400666},
		VPs:   []string{"vp-singapore", "vp-tokyo", "vp-hongkong", "vp-mumbai"},
		Start: bStart, End: bEnd,
		Reason: "sub-prefix 198.51.100.0/24 hijacked toward APAC collectors",
		Label: &model.Label{
			ID: "hijack-subprefix-apac", Kind: model.KindSubPrefixHijack,
			Prefix: model.MustPrefix("198.51.100.0/24"), AttackerASN: 400666,
			Start: bStart, End: bEnd,
			Description: "regional sub-prefix hijack, APAC collectors only", MustAlert: true,
		},
	})

	// ---- Incident C: forged path with a stub in transit ----------------
	// Our origin stays correct, so every origin and ROA check passes. The
	// attacker builds a believable carrier chain and then inserts SmallBizNet,
	// a network that never transits. Only connectivity reasoning exposes it.
	cStart := at(0.55).Add(time.Duration(rng.intn(1200)) * time.Second)
	cEnd := cStart.Add(2*time.Hour + 10*time.Minute)
	out = append(out, Injection{
		Kind: EvPathHijack, Prefix: anycast, Origin: self,
		Path:  []model.ASN{3356, 174, 400777, self},
		Start: cStart, End: cEnd,
		Reason: "forged path with a stub network in transit",
		Label: &model.Label{
			ID: "hijack-forged-path", Kind: model.KindPathHijack, Prefix: anycast,
			AttackerASN: 400777, Start: cStart, End: cEnd,
			Description: "forged AS path through a non-transiting stub", MustAlert: true,
		},
	})

	// ---- Incident D: covering prefix -----------------------------------
	// Announce 198.51.100.0/22, which swallows our 198.51.100.0/23. It is
	// shorter, so it does not win longest-prefix match against our /23, but it
	// captures any of our space we do not explicitly announce and is a
	// stepping stone to blackholing the neighbourhood.
	dStart := at(0.76).Add(time.Duration(rng.intn(900)) * time.Second)
	dEnd := dStart.Add(90 * time.Minute)
	out = append(out, Injection{
		Kind: EvCovering, Prefix: model.MustPrefix("198.51.100.0/22"), Origin: 400666,
		Path:  []model.ASN{174, 209, 400666},
		Start: dStart, End: dEnd,
		Reason: "covering /22 announced by QuickHost-LLC",
		Label: &model.Label{
			ID: "hijack-covering", Kind: model.KindCoveringHijack,
			Prefix: model.MustPrefix("198.51.100.0/22"), AttackerASN: 400666,
			Start: dStart, End: dEnd,
			Description: "covering prefix /22 absorbs our /23", MustAlert: true,
		},
	})

	// ---- Incident E: subtle path hijack through a real carrier ---------
	// The nastiest one. Origin is correct; the path uses real carriers with
	// real adjacencies; only three distant collectors see it. Nothing about
	// the route is impossible -- the detector has to weigh scope, persistence,
	// and the fact that AS209 is a carrier we do not buy transit from.
	eStart := at(0.44).Add(time.Duration(rng.intn(1500)) * time.Second)
	eEnd := eStart.Add(4 * time.Hour)
	out = append(out, Injection{
		Kind: EvPathHijack, Prefix: primary, Origin: self,
		// The collector sees traffic reaching our origin through AS209, a real
		// transit carrier we do not buy from. Legitimate re-routes happen
		// *upstream* of our transit and leave our adjacent AS unchanged; an
		// announcement claiming to attach to us through a carrier we never
		// bought from is a forged path.
		Path:  []model.ASN{174, 209, self},
		VPs:   []string{"vp-madrid", "vp-saopaulo", "vp-johannesburg"},
		Start: eStart, End: eEnd,
		Reason: "traffic pulled through AS209 at three distant collectors",
		Label: &model.Label{
			ID: "hijack-subtle-path", Kind: model.KindPathHijack, Prefix: primary,
			AttackerASN: 209, Start: eStart, End: eEnd,
			Description: "subtle path hijack via a real carrier, three VPs only", MustAlert: true,
		},
	})

	// ---- Incident F: single-collector interception ----------------------
	// Seen from exactly one collector. A single collector is wrong in ways two
	// are not -- a stale session, a misconfiguration, a collector bug -- so the
	// detector must not page immediately. It must also not ignore it: a real
	// interception aimed at one region looks exactly like this. The answer is
	// time: hold until the route has persisted well past any plausible
	// collector glitch.
	fStart := at(0.66).Add(time.Duration(rng.intn(1500)) * time.Second)
	fEnd := fStart.Add(3 * time.Hour)
	out = append(out, Injection{
		Kind: EvPathHijack, Prefix: primary, Origin: self,
		Path:  []model.ASN{174, 209, self},
		VPs:   []string{"vp-hongkong"},
		Start: fStart, End: fEnd,
		Reason: "single-collector interception via AS209",
		Label: &model.Label{
			ID: "hijack-single-vp", Kind: model.KindPathHijack, Prefix: primary,
			AttackerASN: 209, Start: fStart, End: fEnd,
			Description: "interception visible from one collector only", MustAlert: true,
		},
	})

	// ---- Incident G: short origin hijack ---------------------------------
	// A 25-minute origin hijack of our anycast /24. Short enough that a
	// conservative detector which waits for long persistence misses it, long
	// enough that it is not a single bad dump. Origin evidence is positive, so
	// it must page quickly; there is no reason to wait an hour.
	// It uses the legacy block, and starts after the first legacy hijack has
	// fully cleared: two unrelated hijacks of the same prefix at the same time is
	// a scheduling artefact, not a scenario, and would conflate "the detector
	// re-raised" with "a second attacker arrived".
	gStart := at(0.84).Add(time.Duration(rng.intn(900)) * time.Second)
	gEnd := gStart.Add(25 * time.Minute)
	out = append(out, Injection{
		Kind: EvOriginHijack, Prefix: legacy, Origin: 400666,
		Path:  []model.ASN{174, 400666},
		Start: gStart, End: gEnd,
		Reason: "brief hijack of the legacy /24",
		Label: &model.Label{
			ID: "hijack-brief-origin", Kind: model.KindOriginHijack, Prefix: legacy,
			AttackerASN: 400666, Start: gStart, End: gEnd,
			Description: "25-minute origin hijack of the legacy /24", MustAlert: true,
		},
	})

	// ---- Incident H: fully plausible forged path -------------------------
	// The hardest case in the set. The attacker announces from our own ASN (so
	// origin and ROA are perfect) and the path attaches to us through one of our
	// *real* upstreams (so the adjacency is entirely plausible too). There is no
	// structural lie to detect and no unauthorized origin. What remains is that
	// the adjacent AS changes at a minority of collectors and stays that way --
	// which looks like interception but is also what a regional re-route looks
	// like, so it can only be a WARNING requiring a human. The contrast with the
	// benign fibre-cut re-route is deliberate: there the *adjacent* AS stays put
	// and only the chain above it changes, which is a normal upstream event.
	hStart := at(0.90).Add(time.Duration(rng.intn(600)) * time.Second)
	hEnd := hStart.Add(5 * time.Hour)
	out = append(out, Injection{
		Kind: EvPathHijack, Prefix: anycast, Origin: self,
		Path:  []model.ASN{3356, self},
		VPs:   []string{"vp-sanjose", "vp-toronto"},
		Start: hStart, End: hEnd,
		Reason: "plausible forged path, deviation only",
		Label: &model.Label{
			ID: "hijack-plausible-path", Kind: model.KindPathHijack, Prefix: anycast,
			Start: hStart, End: hEnd,
			Description: "forged path indistinguishable from a real two-hop route",
			// AS3356 -> us is a registered, legitimate adjacency, so this path
			// is byte-for-byte what our own traffic can legitimately look like.
			// No BGP-only detector can separate it from the real thing; it is
			// the documented blind spot that motivates RPKI ASPA / path
			// validation, and out-of-band checks like traffic volume.
			UndetectableFromBGP: true,
		},
	})

	return out
}

// Each is labelled Benign=true: a WARNING or worse on any of them is a false
// positive and is scored as such.
// buildBenignScripts lays out legitimate operations that look like attacks.
// Each is labelled Benign=true: a WARNING or worse on any of them is a false
// positive and is scored as such.
func buildBenignScripts(w *World, tl *Timeline, rng intn) []Injection {
	d := tl.End.Sub(tl.Start)
	reg := w.Reg
	primary := reg.OurPrefixes[0]
	anycast := model.MustPrefix("203.0.113.0/24")
	at := func(frac float64) time.Time { return tl.Start.Add(time.Duration(float64(d) * frac)) }

	var out []Injection

	// ---- Scrubbing session ---------------------------------------------
	// Our scrubbing center announces our /23 from its own ASN, carrying the
	// agreed cleaning community. Without the community check this is
	// indistinguishable from a foreign-origin hijack.
	s1 := at(0.20).Add(time.Duration(rng.intn(900)) * time.Second)
	out = append(out, Injection{
		Kind: EvScrub, Prefix: primary, Origin: 400999,
		Start: s1, End: s1.Add(2 * time.Hour),
		Communities: []string{"64500:666"},
		Reason:      "DDoS mitigation: /23 diverted to scrubbing center",
		Label: &model.Label{
			ID: "benign-scrub", Kind: model.KindScrubbing, Prefix: primary, AttackerASN: 400999,
			Start: s1, End: s1.Add(2 * time.Hour), Benign: true,
			Description: "expected scrub diversion carrying the cleaning community",
		},
	})

	// ---- Transit switch ------------------------------------------------
	// A carrier takes maintenance and traffic moves to another transit, at
	// every collector, within minutes, and stays for a day. This is precisely
	// what a path hijack looks like except for its breadth and the identity of
	// the new upstream.
	s2 := at(0.28).Add(time.Duration(rng.intn(600)) * time.Second)
	out = append(out, Injection{
		Kind: EvTransitSwitch, Prefix: primary, Origin: reg.SelfASN,
		Path:  []model.ASN{174, reg.SelfASN},
		Start: s2, End: s2.Add(26 * time.Hour),
		Reason: "AS1299 maintenance: traffic shifts to AS174",
		Label: &model.Label{
			ID: "benign-transit-switch", Kind: model.KindTransitChange, Prefix: primary,
			Start: s2, End: s2.Add(26 * time.Hour), Benign: true,
			Description: "fleet-wide transit switch during carrier maintenance",
		},
	})

	// ---- Anycast sibling -----------------------------------------------
	// Our APAC PoP ASN originates the anycast /24 for a week. It is listed in
	// the anycast registry, so a second origin is expected -- for this prefix
	// and this ASN only.
	s3 := at(0.15).Add(time.Duration(rng.intn(600)) * time.Second)
	out = append(out, Injection{
		Kind: EvAnycastJoin, Prefix: anycast, Origin: 400002,
		Path:  []model.ASN{1299, 400002},
		Start: s3, End: s3.Add(7 * 24 * time.Hour),
		Reason: "APAC anycast PoP joins",
		Label: &model.Label{
			ID: "benign-anycast", Kind: model.KindAuthorized, Prefix: anycast, AttackerASN: 400002,
			Start: s3, End: s3.Add(7 * 24 * time.Hour), Benign: true,
			Description: "registered anycast sibling originates the service /24",
		},
	})

	// ---- Maintenance flaps ---------------------------------------------
	// A customer's /24 withdraws and reannounces repeatedly inside a short
	// maintenance window. Bursty churn alarms naive detectors; here it is
	// routine and must at most be an INFO audit entry. Eight cycle pairs at 70s
	// intervals land inside the detector's 10-minute flap window.
	s4 := at(0.62).Add(time.Duration(rng.intn(900)) * time.Second)
	out = append(out, Injection{
		Kind: EvMaintenance, Prefix: model.MustPrefix("198.51.101.0/24"), Origin: 400010,
		Start: s4, End: s4.Add(11 * time.Minute),
		FlapEvery: 70 * time.Second,
		Reason:    "CustomerX CDN edge maintenance window",
		Label: &model.Label{
			ID: "benign-maintenance", Kind: model.KindFlap,
			Prefix: model.MustPrefix("198.51.101.0/24"), Start: s4, End: s4.Add(11 * time.Minute),
			Benign: true, Description: "planned customer maintenance flap burst",
		},
	})

	// ---- Regional re-route ---------------------------------------------
	// A fibre cut changes the path at European collectors only. Regional
	// scope plus the global-coverage discount is what keeps this quiet.
	s5 := at(0.50).Add(time.Duration(rng.intn(900)) * time.Second)
	out = append(out, Injection{
		Kind: EvReRoute, Prefix: anycast, Origin: reg.SelfASN,
		// A fibre cut changes which carriers AS1299 hands us traffic from. Our
		// own adjacent AS stays AS1299, which is the whole point: legitimate
		// re-routes happen upstream of the AS we buy transit from.
		Path:  []model.ASN{3356, 7018, 1299, reg.SelfASN},
		VPs:   []string{"vp-amsterdam", "vp-frankfurt", "vp-stockholm", "vp-madrid"},
		Start: s5, End: s5.Add(5 * time.Hour),
		Reason: "fibre cut: EU collectors see an alternate path",
		Label: &model.Label{
			ID: "benign-reroute-eu", Kind: model.KindTransitChange, Prefix: anycast,
			Start: s5, End: s5.Add(5 * time.Hour), Benign: true,
			Description: "regional re-route after a fibre cut",
		},
	})

	return out
}
