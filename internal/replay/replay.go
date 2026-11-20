// Package replay drives a Detector from a Dataset and scores the result
// against ground truth.
package replay

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"hijackwatch/internal/detect"
	"hijackwatch/internal/model"
	"hijackwatch/internal/sim"
)

// Result is the outcome of replaying a dataset once.
type Result struct {
	Alerts []model.Alert
	Fired  map[string]model.Alert // alert ID -> final snapshot
	Truth  []sim.Incident
	Stats  detect.Stats
	// Detection results per incident.
	Outcomes []Outcome
	Latency  map[string]time.Duration // incident ID -> first alert delay
}

// Outcome maps one ground-truth incident to what the detector did.
type Outcome struct {
	Incident    sim.Incident
	Detected    bool
	AlertIDs    []string
	MaxSeverity model.Severity
	Latency     time.Duration // from incident start to first matching alert's FirstSeen
	FalsePage   bool          // benign incident paged above its ceiling
}

// Run replays every update, ticking the detector regularly so quiet periods
// age out, then flushes.
func Run(ds sim.Dataset, det *detect.Detector) Result {
	res := Result{
		Fired:   map[string]model.Alert{},
		Truth:   ds.Incidents,
		Latency: map[string]time.Duration{},
	}
	det.SetSink(func(a model.Alert) { res.Fired[a.ID] = a })

	tickEvery := 5 * time.Minute
	lastTick := ds.Start
	for _, u := range ds.Updates {
		for !u.ReceivedAt.Before(lastTick.Add(tickEvery)) {
			lastTick = lastTick.Add(tickEvery)
			det.Tick(lastTick)
		}
		det.Process(u)
	}
	det.Tick(ds.End)
	det.Flush()

	for _, a := range det.Alerts() {
		res.Fired[a.ID] = a
		res.Alerts = append(res.Alerts, a)
	}
	res.Stats = det.StatsSnapshot()
	res.Outcomes = match(ds.Incidents, res.Fired)
	for _, o := range res.Outcomes {
		if o.Detected {
			res.Latency[o.Incident.ID] = o.Latency
		}
	}
	return res
}

// match pairs each ground-truth incident with alerts that overlap it in time
// and address the same prefix (exact or related).
func match(truth []sim.Incident, alerts map[string]model.Alert) []Outcome {
	alertList := make([]model.Alert, 0, len(alerts))
	for _, a := range alerts {
		alertList = append(alertList, a)
	}
	sort.Slice(alertList, func(i, j int) bool { return alertList[i].FirstSeen.Before(alertList[j].FirstSeen) })

	out := make([]Outcome, 0, len(truth))
	for _, inc := range truth {
		o := Outcome{Incident: inc, MaxSeverity: model.SevInfo}
		incStart := inc.Start.Add(-5 * time.Minute)
		incEnd := inc.End.Add(25 * time.Minute)
		for _, a := range alertList {
			if !overlaps(a, incStart, incEnd) {
				continue
			}
			if !sameTarget(a, inc) {
				continue
			}
			o.Detected = true
			o.AlertIDs = append(o.AlertIDs, a.ID)
			if a.Severity > o.MaxSeverity {
				o.MaxSeverity = a.Severity
			}
			d := a.FirstSeen.Sub(inc.Start)
			if d < 0 {
				d = 0
			}
			if o.Latency == 0 || d < o.Latency {
				o.Latency = d
			}
		}
		if !inc.ExpectAlert {
			ceiling, _ := model.ParseSeverity(inc.MaxSeverity)
			if o.MaxSeverity > ceiling {
				o.FalsePage = true
			}
			// For a benign incident, "correct" means it did not page.  It may
			// legitimately produce info/low visibility alerts.
			o.Detected = o.MaxSeverity >= model.SevMedium
		}
		out = append(out, o)
	}
	return out
}

func overlaps(a model.Alert, start, end time.Time) bool {
	return !a.FirstSeen.After(end) && !a.LastSeen.Before(start)
}

func parseSeverity(s string) (model.Severity, error) { return model.ParseSeverity(s) }

func sameTarget(a model.Alert, inc sim.Incident) bool {
	ap, err1 := model.ParsePrefixOK(a.Prefix)
	ip, err2 := model.ParsePrefixOK(inc.Prefix)
	if err1 != nil || err2 != nil {
		return false
	}
	if ap == ip {
		return true
	}
	// An alert on a more-specific or covering prefix of the incident counts.
	return ap.Overlaps(ip) && (a.Origin == inc.Origin || inc.Origin == 0)
}

// Metrics summarises a Result for regression tests and reports.
type Metrics struct {
	TruePositives  int
	FalsePositives int
	FalseNegatives int
	TrueNegatives  int
	MissedIDs      []string
	FalseIDs       []string
	AmbiguousHits  []string
	MedianLatency  time.Duration
	P95Latency     time.Duration
}

// Score computes metrics.  Benign incidents are the negatives; attacks are the
// positives.  Ambiguous benign events are reported separately because a
// Medium on them is defensible rather than wrong.
func Score(r Result) Metrics {
	var m Metrics
	var lat []time.Duration
	for _, o := range r.Outcomes {
		if o.Incident.Ambiguous {
			if o.MaxSeverity >= model.SevMedium {
				m.AmbiguousHits = append(m.AmbiguousHits, o.Incident.ID)
			}
			continue
		}
		if o.Incident.ExpectAlert {
			if o.Detected {
				m.TruePositives++
				lat = append(lat, o.Latency)
			} else {
				m.FalseNegatives++
				m.MissedIDs = append(m.MissedIDs, o.Incident.ID)
			}
		} else {
			if o.MaxSeverity >= model.SevMedium {
				m.FalsePositives++
				m.FalseIDs = append(m.FalseIDs, o.Incident.ID)
			} else {
				m.TrueNegatives++
			}
		}
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	if len(lat) > 0 {
		m.MedianLatency = lat[len(lat)/2]
		m.P95Latency = lat[(len(lat)*95)/100]
	}
	return m
}

// String renders a compact one-line metric summary.
func (m Metrics) String() string {
	return fmt.Sprintf("TP=%d FP=%d FN=%d TN=%d median=%s p95=%s",
		m.TruePositives, m.FalsePositives, m.FalseNegatives, m.TrueNegatives,
		round(m.MedianLatency), round(m.P95Latency))
}

func round(d time.Duration) time.Duration { return d.Round(time.Second) }

// Report renders a human-readable evaluation including per-incident results.
func Report(r Result) string {
	var sb strings.Builder
	m := Score(r)
	sb.WriteString("=== evaluation with default policy ===\n")
	sb.WriteString(m.String() + "\n")
	if len(m.MissedIDs) > 0 {
		sb.WriteString("missed: " + strings.Join(m.MissedIDs, ", ") + "\n")
	}
	if len(m.FalseIDs) > 0 {
		sb.WriteString("false positives: " + strings.Join(m.FalseIDs, ", ") + "\n")
	}
	if len(m.AmbiguousHits) > 0 {
		sb.WriteString("ambiguous benign events that reached Medium+ (accepted): " +
			strings.Join(m.AmbiguousHits, ", ") + "\n")
	}
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("%-26s %-22s %-9s %-11s %-10s %s\n",
		"incident", "prefix", "detected", "max sev", "latency", "alerts"))
	for _, o := range r.Outcomes {
		sev := o.MaxSeverity.String()
		lat := "-"
		if o.Detected {
			lat = round(o.Latency).String()
		}
		sb.WriteString(fmt.Sprintf("%-26s %-22s %-9v %-11s %-10s %d\n",
			o.Incident.ID, o.Incident.Prefix, o.Detected, sev, lat, len(o.AlertIDs)))
	}
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("updates=%d fired=%d resolved=%d dropped-candidates=%d\n",
		r.Stats.Received, r.Stats.AlertsFired, r.Stats.AlertsResolved, r.Stats.CandidatesDropped))
	return sb.String()
}

// AlertLine renders one alert as a terminal line.
func AlertLine(a model.Alert) string {
	return fmt.Sprintf("%s %-8s %-16s %-22s origin=AS%-6d pts=%-2d score=%-3d conf=%.2f %s",
		a.FirstSeen.UTC().Format("01-02 15:04"), a.Severity, a.Status, a.Prefix,
		a.Origin, len(a.Collectors), a.Score, a.Confidence, a.Summary)
}
