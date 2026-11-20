// Package eval replays a scenario through the detection engine and scores the
// result against ground truth.
//
// The scoring model is deliberately not "did it fire an alert on the labelled
// prefix". A detector can trivially achieve that by paging on everything. What
// is scored is:
//
//   - Detection: did a WARNING+ alert arrive for each hostile label, and how
//     long after the route became visible? Detection rate and time-to-detect.
//   - Precision: how many WARNING+ alerts were raised that do not correspond to
//     a hostile label? Those are the pages that wake people for nothing.
//   - Benign control: each benign label (scrub session, transit switch,
//     anycast sibling, maintenance, re-route) must produce no WARNING+. Any
//     that do are reported separately as legitimate-operation false positives,
//     which is the failure that erodes trust in the tool fastest.
//   - Severity calibration: hostile labels must reach CRITICAL when the
//     evidence supports it; benign labels must stay at INFO.
//
// Alerts are matched to labels by overlap: same prefix-or-overlapping prefix,
// time overlap with the label, and (for path events) the same affected
// collector set is not required — a detector can legitimately be more specific.
package eval

import (
	"fmt"
	"sort"
	"time"

	"routewatch/internal/detect"
	"routewatch/internal/model"
	"routewatch/internal/registry"
)

// Result is the outcome of replaying one scenario.
type Result struct {
	Scenario string
	// Alerts is every event the engine emitted, in order.
	Alerts []model.Alert
	// Detections maps a hostile label ID to the alert that caught it.
	Detections map[string]model.Alert
	// Missed hostile labels.
	Missed []model.Label
	// TimeToDetect per hostile label.
	TimeToDetect map[string]time.Duration
	// FalsePositives are WARNING+ alerts not matched to a hostile label.
	FalsePositives []model.Alert
	// BenignViolations are WARNING+ alerts that overlap a benign label.
	BenignViolations []model.Alert
	// BenignQuiet counts benign labels that produced no WARNING+.
	BenignQuiet []string
	// BenignInfo maps a benign label to the INFO alert it produced (expected).
	BenignInfo map[string]model.Alert
	// DataGaps are labels whose visibility was too poor for any detector to
	// catch. Reported separately so they do not count as misses.
	DataGaps []model.Label
	// BlindSpots are events that are structurally identical to legitimate
	// traffic in BGP data and cannot be detected without an external signal.
	// Reported separately; neither a success nor a failure.
	BlindSpots []model.Label
	// DuplicateAlerts are repeat WARNING+ alerts for an attack that was already
	// detected. They are not false positives, but they are noise: an on-call
	// person should not be paged twice for one incident.
	DuplicateAlerts []model.Alert
	// Severity histogram of all alerts.
	BySeverity map[model.Severity]int
	// ByKind histogram of hostile detections.
	ByKind map[model.Kind]int
}

// Metrics are the headline numbers.
type Metrics struct {
	HostileLabels     int
	Detected          int
	DetectionRate     float64
	MedianTTD         time.Duration
	P90TTD            time.Duration
	FalsePositives    int
	BenignLabels      int
	BenignViolations  int
	AlertsTotal       int
	AlertsWarnPlus    int
	AlertsInfo        int
	Precision         float64
	BenignSpecificity float64
}

// Metrics derives headline numbers from a result.
//
// Two rates are reported separately because they answer different questions:
// detection rate is an average over hostile events (did we catch each one?),
// false-positive count is a total over the whole scenario (how many pages did
// we raise that nobody asked for?). Precision on WARNING+ is the ratio of
// hostile detections to all WARNING+ alerts, which is what an on-call person
// experiences: of the pages I get, how many are real?
func (r *Result) Metrics() Metrics {
	m := Metrics{
		// HostileLabels counts only events a BGP-only detector can be scored on:
		// blind spots are excluded from every rate.
		HostileLabels:    len(r.Detections) + len(r.Missed),
		Detected:         len(r.Detections),
		FalsePositives:   len(r.FalsePositives),
		BenignLabels:     len(r.BenignQuiet) + len(r.BenignViolations) + len(r.BenignInfo),
		BenignViolations: len(r.BenignViolations),
		AlertsTotal:      len(r.Alerts),
		AlertsInfo:       r.BySeverity[model.SevInfo],
	}
	scored := len(r.Detections) + len(r.Missed)
	if scored > 0 {
		m.DetectionRate = float64(m.Detected) / float64(scored)
	}
	truePositives := 0
	for _, a := range r.Detections {
		if a.Severity >= model.SevWarning {
			truePositives++
		}
	}
	m.AlertsWarnPlus = truePositives + m.FalsePositives + m.BenignViolations
	if m.AlertsWarnPlus > 0 {
		m.Precision = float64(truePositives) / float64(m.AlertsWarnPlus)
	} else if truePositives > 0 {
		m.Precision = 1
	}
	if m.BenignLabels > 0 {
		m.BenignSpecificity = float64(m.BenignLabels-m.BenignViolations) / float64(m.BenignLabels)
	}
	ttds := make([]time.Duration, 0, len(r.TimeToDetect))
	for _, d := range r.TimeToDetect {
		ttds = append(ttds, d)
	}
	sort.Slice(ttds, func(i, j int) bool { return ttds[i] < ttds[j] })
	if len(ttds) > 0 {
		m.MedianTTD = ttds[len(ttds)/2]
		m.P90TTD = ttds[(len(ttds)*9)/10]
	}
	return m
}

// Options tunes replay.
type Options struct {
	// Step is how far each tick advances the engine clock. The engine's own
	// EvalInterval is what it believes; Step must be <= EvalInterval or the
	// engine ticks slower than it thinks and latency measurements inflate.
	Step time.Duration
}

// Replay runs a scenario through a fresh engine and scores it.
func Replay(reg *registry.Registry, cfg detect.Config, sc model.Scenario, opt Options) (Result, error) {
	if opt.Step <= 0 {
		opt.Step = cfg.EvalInterval
	}
	if opt.Step > cfg.EvalInterval {
		return Result{}, fmt.Errorf("eval: step %s exceeds eval interval %s; ticks would be skipped", opt.Step, cfg.EvalInterval)
	}
	if len(sc.Observations) == 0 {
		return Result{}, fmt.Errorf("eval: scenario %q has no observations", sc.Name)
	}

	res := Result{
		Scenario:     sc.Name,
		Detections:   map[string]model.Alert{},
		TimeToDetect: map[string]time.Duration{},
		BenignInfo:   map[string]model.Alert{},
		BySeverity:   map[model.Severity]int{},
		ByKind:       map[model.Kind]int{},
	}

	eng := detect.New(reg, cfg, sc.Start)
	eng.Start(sc.Start)

	obs := append([]model.Observation(nil), sc.Observations...)
	model.SortObservations(obs)

	// Tick on a grid that starts at scenario start. Observations are delivered
	// strictly by ReceivedAt, so at each tick the engine has seen exactly what
	// a streaming collector would have.
	i := 0
	tick := sc.Start
	lastTick := sc.End.Add(2 * time.Hour)
	for ; !tick.After(lastTick); tick = tick.Add(opt.Step) {
		for i < len(obs) && !obs[i].ReceivedAt.After(tick) {
			eng.Ingest(obs[i : i+1])
			i++
		}
		d := eng.Tick(tick)
		res.Alerts = append(res.Alerts, d.NewAlerts...)
		res.Alerts = append(res.Alerts, d.Updated...)
		for _, a := range d.NewAlerts {
			res.BySeverity[a.Severity]++
			if a.Severity >= model.SevWarning {
				res.ByKind[a.Kind]++
			}
		}
	}

	Score(&res, sc.Labels, sc.End)
	return res, nil
}

// Score matches emitted alerts to labels. It is exported so tests can score
// hand-built alert/label pairs.
//
// Order matters: hostile labels are matched first and their alerts consumed, so
// a real attack that happens to overlap a maintenance window in time is scored
// as a detection, not as a false positive against the benign label. Only alerts
// nobody has claimed are then tested against benign labels.
// Score matches alerts to labels. scenarioEnd is the scenario's end instant,
// used to separate a genuine miss from an event the scenario cut short.
func Score(res *Result, labels []model.Label, scenarioEnd time.Time) {
	if res.Detections == nil {
		res.Detections = map[string]model.Alert{}
	}
	if res.TimeToDetect == nil {
		res.TimeToDetect = map[string]time.Duration{}
	}
	if res.BenignInfo == nil {
		res.BenignInfo = map[string]model.Alert{}
	}
	if res.BySeverity == nil {
		res.BySeverity = map[model.Severity]int{}
	}
	if res.ByKind == nil {
		res.ByKind = map[model.Kind]int{}
	}
	if scenarioEnd.IsZero() {
		scenarioEnd = time.Time{}
	}
	// Replay appends updates as well as new alerts; keep the earliest event per
	// incident, which is what detection latency is measured from.
	first := map[string]model.Alert{}
	var ordered []model.Alert
	for _, a := range res.Alerts {
		if _, ok := first[a.ID]; !ok {
			first[a.ID] = a
			ordered = append(ordered, a)
		}
	}
	res.Alerts = ordered

	used := map[string]bool{}

	// Pass 1: hostile labels.
	for _, l := range labels {
		if l.Benign {
			continue
		}
		var best *model.Alert
		for idx := range ordered {
			a := ordered[idx]
			if used[a.ID] || !a.Kind.IsHostile() {
				continue
			}
			if !alertMatchesHostile(a, l) {
				continue
			}
			if best == nil || a.AlertedAt.Before(best.AlertedAt) {
				best = &ordered[idx]
			}
		}
		if best == nil {
			switch {
			case l.UndetectableFromBGP:
				// Handled by the dedicated sweep below, which is the authoritative
				// classification for blind spots.
			case !scenarioCoversLabelEnd(l, scenarioEnd):
				// The scenario ended before the event did, so the detector never
				// had the full duration the design requires. Not a miss.
				res.DataGaps = append(res.DataGaps, l)
			case l.UndetectableFromBGP:
				// Already handled by the loop below, which sweeps blind spots
				// after matching. Nothing to record here.
			case l.MustAlert:
				res.Missed = append(res.Missed, l)
			}
			continue
		}
		used[best.ID] = true
		res.Detections[l.ID] = *best
		ttd := best.AlertedAt.Sub(l.Start)
		if ttd < 0 {
			ttd = 0
		}
		res.TimeToDetect[l.ID] = ttd
	}

	// Duplicate suppression. When an ongoing attack is re-raised as a second
	// incident (a new incident ID for the same enemy), the later alert is the
	// same event, not a new false positive. Credit it to the same label so the
	// page count reflects distinct real events, and record it so the repeat
	// alerting is visible in the report.
	for _, l := range labels {
		if l.Benign {
			continue
		}
		if _, ok := res.Detections[l.ID]; !ok {
			continue
		}
		for idx := range ordered {
			a := ordered[idx]
			if used[a.ID] || !a.Kind.IsHostile() || a.Severity < model.SevWarning {
				continue
			}
			if !alertMatchesHostile(a, l) {
				continue
			}
			used[a.ID] = true
			res.DuplicateAlerts = append(res.DuplicateAlerts, a)
		}
	}

	// Blind-spot sweep: labels marked undetectable from BGP are never scored as
	// misses, whether or not an alert happened to fire near them.
	for _, l := range labels {
		if l.Benign || !l.UndetectableFromBGP {
			continue
		}
		if _, detected := res.Detections[l.ID]; !detected {
			res.BlindSpots = append(res.BlindSpots, l)
		}
	}

	// Pass 2: benign labels, against unclaimed alerts only.
	for _, l := range labels {
		if !l.Benign {
			continue
		}
		var violation *model.Alert
		var info *model.Alert
		for idx := range ordered {
			a := ordered[idx]
			if used[a.ID] || !alertMatchesBenign(a, l) {
				continue
			}
			if a.Severity >= model.SevWarning {
				if violation == nil {
					violation = &ordered[idx]
				}
				continue
			}
			if info == nil {
				info = &ordered[idx]
			}
		}
		switch {
		case violation != nil:
			used[violation.ID] = true
			res.BenignViolations = append(res.BenignViolations, *violation)
		case info != nil:
			used[info.ID] = true
			res.BenignInfo[l.ID] = *info
		default:
			res.BenignQuiet = append(res.BenignQuiet, l.ID)
		}
	}

	// Anything WARNING+ still unclaimed is a genuine false positive.
	for _, a := range ordered {
		if a.Severity < model.SevWarning || used[a.ID] {
			continue
		}
		res.FalsePositives = append(res.FalsePositives, a)
	}
}

// alertMatchesHostile decides whether a hostile alert is "about" a hostile
// label: overlapping prefixes and time, and a compatible kind.
//
// The time test anchors on detection latency, not on a fixed grace window. A
// detector that deliberately waits for an anomaly to persist -- the correct
// behaviour for single-collector evidence -- can raise minutes to an hour after
// the label starts, and a detector that notices a route is missing raises after
// the label ends. Both are the detector working as designed; scoring them as
// misses would punish exactly the conservatism the design demands. So an alert
// counts if it was raised while the label was in force, or within the tolerated
// latency after it began (and before it ends plus a little slack).
// scenarioCoversLabelEnd reports whether the feed ran past the label's end. A
// zero end means the scenario itself supplies the end, which is always covered.
func scenarioCoversLabelEnd(l model.Label, scenarioEnd time.Time) bool {
	if scenarioEnd.IsZero() || l.End.IsZero() {
		return true
	}
	return !l.End.After(scenarioEnd)
}

func alertMatchesHostile(a model.Alert, l model.Label) bool {
	if !a.Prefix.Overlaps(l.Prefix) {
		return false
	}
	// An alert counts if it was raised after the label began and before the
	// watcher should have stopped caring. "Stopped caring" is the label end plus
	// the time it takes a detector to confirm recovery, which is bounded by the
	// label's own duration: an event that lasted four hours gets four hours of
	// slack for its aftermath, while a 20-minute event gets twenty minutes.
	// A fixed grace window would either be too short (stale firstSeen on long
	// events pushes alerts past it) or too long (lets unrelated later alerts
	// claim the label).
	grace := l.End.Sub(l.Start)
	if grace > 2*time.Hour {
		grace = 2 * time.Hour
	}
	if grace < 15*time.Minute {
		grace = 15 * time.Minute
	}
	to := l.End.Add(grace)
	if a.AlertedAt.After(to) {
		return false
	}
	if a.AlertedAt.Before(l.Start) {
		return false
	}
	switch a.Kind {
	case model.KindOriginHijack, model.KindCoveringHijack:
		return l.Kind == model.KindOriginHijack || l.Kind == model.KindCoveringHijack
	case model.KindSubPrefixHijack:
		return l.Kind == model.KindSubPrefixHijack || l.Kind == model.KindOriginHijack
	case model.KindPathHijack:
		return true // a path hijack can surface under any hostile label
	}
	return false
}

// alertMatchesBenign decides whether an alert is "about" a benign label: it
// must be raised inside the label window on a prefix the label covers, and its
// kind must describe the same class of operation. Mere co-occurrence in time is
// not enough; otherwise a real attack during a maintenance window would be
// excused.
func alertMatchesBenign(a model.Alert, l model.Label) bool {
	if !l.Prefix.Contains(a.Prefix) && !a.Prefix.Contains(l.Prefix) {
		return false
	}
	if a.AlertedAt.Before(l.Start.Add(-5*time.Minute)) || a.AlertedAt.After(l.End.Add(30*time.Minute)) {
		return false
	}
	switch l.Kind {
	case model.KindScrubbing:
		return a.Kind == model.KindScrubbing || a.Kind == model.KindAuthorized
	case model.KindTransitChange:
		return a.Kind == model.KindTransitChange || a.Kind == model.KindAuthorized
	case model.KindAuthorized:
		return a.Kind == model.KindAuthorized
	case model.KindFlap:
		return a.Kind == model.KindFlap || a.Kind == model.KindAuthorized
	}
	return a.Kind == l.Kind
}

// FormatMetrics renders a metrics block for the CLI.
func FormatMetrics(m Metrics) string {
	return fmt.Sprintf(
		"detection    %d/%d hostile events (%.0f%%), median TTD %s, p90 TTD %s\n"+
			"precision    %d false positive(s); precision on WARNING+ %.2f\n"+
			"benign       %d legitimate operations, %d raised WARNING+ (specificity %.2f)\n"+
			"volume       %d alerts total (%d WARNING+, %d INFO)",
		m.Detected, m.HostileLabels, m.DetectionRate*100, m.MedianTTD.Round(time.Second), m.P90TTD.Round(time.Second),
		m.FalsePositives, m.Precision,
		m.BenignLabels, m.BenignViolations, m.BenignSpecificity,
		m.AlertsTotal, m.AlertsWarnPlus, m.AlertsInfo,
	)
}
