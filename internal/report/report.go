// Package report renders evaluation results for humans.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"routewatch/internal/eval"
	"routewatch/internal/model"
	"routewatch/internal/registry"
)

// Options tunes the report.
type Options struct {
	// Verbose prints every alert and every benign control result.
	Verbose bool
}

// Print writes a human-readable report.
func Print(w io.Writer, res eval.Result, reg *registry.Registry, opt Options) {
	m := res.Metrics()
	fmt.Fprintf(w, "scenario: %s\n\n", res.Scenario)
	fmt.Fprintln(w, eval.FormatMetrics(m))
	fmt.Fprintln(w)

	fmt.Fprintln(w, "hostile events")
	if len(res.Detections) == 0 && len(res.Missed) == 0 && len(res.DataGaps) == 0 && len(res.BlindSpots) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	ids := make([]string, 0, len(res.Detections))
	for id := range res.Detections {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		a := res.Detections[id]
		fmt.Fprintf(w, "  DETECTED  %-24s %-8s %-18s %s  ttd=%s\n",
			id, a.Severity, a.Kind, a.Prefix, res.TimeToDetect[id].Round(time.Second))
		if !opt.Verbose {
			continue
		}
		printAlert(w, a, "            ")
	}
	for _, l := range res.Missed {
		fmt.Fprintf(w, "  MISSED    %-24s %s %s\n", l.ID, l.Kind, l.Description)
	}
	for _, l := range res.DataGaps {
		fmt.Fprintf(w, "  DATA-GAP  %-24s %s\n", l.ID, l.Description)
	}
	for _, l := range res.BlindSpots {
		fmt.Fprintf(w, "  BLIND-SPOT %-24s %s\n", l.ID, l.Description)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "legitimate operations (must stay quiet)")
	benignIDs := make([]string, 0, len(res.BenignInfo)+len(res.BenignQuiet)+len(res.BenignViolations))
	for id := range res.BenignInfo {
		benignIDs = append(benignIDs, id)
	}
	benignIDs = append(benignIDs, res.BenignQuiet...)
	sort.Strings(benignIDs)
	for _, id := range benignIDs {
		if a, ok := res.BenignInfo[id]; ok {
			fmt.Fprintf(w, "  INFO      %-24s %-18s %s\n", id, a.Kind, truncate(a.Summary, 100))
		} else {
			fmt.Fprintf(w, "  QUIET     %-24s\n", id)
		}
	}
	for _, a := range res.BenignViolations {
		fmt.Fprintf(w, "  VIOLATION %-24s %-8s %-18s %s\n", "benign-label", a.Severity, a.Kind, a.Summary)
	}

	if len(res.DuplicateAlerts) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "repeat alerts (same attack re-raised; not false positives, but noise)")
		for _, a := range res.DuplicateAlerts {
			fmt.Fprintf(w, "  %-8s %-18s %-22s at %s\n", a.Severity, a.Kind, a.Prefix, a.AlertedAt.Format("15:04:05"))
		}
	}

	if len(res.FalsePositives) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "false positives (WARNING+ unrelated to any hostile label)")
		for _, a := range res.FalsePositives {
			fmt.Fprintf(w, "  %-8s %-18s %-22s score=%d  %s\n", a.Severity, a.Kind, a.Prefix, a.Score, truncate(a.Summary, 90))
			if opt.Verbose {
				printAlert(w, a, "    ")
			}
		}
	}
}

func printAlert(w io.Writer, a model.Alert, indent string) {
	fmt.Fprintf(w, "%ssummary  %s\n", indent, a.Summary)
	fmt.Fprintf(w, "%svps      %s (%s)\n", indent, strings.Join(a.VPs, ", "), strings.Join(a.VPRegions, ","))
	fmt.Fprintf(w, "%svisibility %.2f  coverage %.2f  score %d\n", indent, a.Visibility, a.Coverage, a.Score)
	if len(a.DataQualityFlags) > 0 {
		fmt.Fprintf(w, "%sdata     %s\n", indent, strings.Join(a.DataQualityFlags, ", "))
	}
	if a.Reason != "" {
		fmt.Fprintf(w, "%sreason   %s\n", indent, a.Reason)
	}
	for _, s := range a.Signals {
		fmt.Fprintf(w, "%ssignal   %+d %-22s %s\n", indent, s.Delta, s.Name, s.Note)
	}
	for _, p := range a.PathSamples {
		fmt.Fprintf(w, "%spath     %s\n", indent, p)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
