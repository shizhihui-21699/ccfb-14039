// Package sim assembles a full scenario: baseline routing, ordinary
// operational churn, data gaps and injected events.
package sim

import (
	"fmt"
	"time"

	"routewatch/internal/model"
	"routewatch/internal/registry"
)

// Options controls scenario construction.
type Options struct {
	Seed int64
	// Duration is the simulated wall-clock window.
	Duration time.Duration
	// Start is the scenario's start instant.
	Start time.Time
	// SnapshotInterval is the collector dump period.
	SnapshotInterval time.Duration
	// OutageFraction is the share of (collector, prefix) views that lose data.
	OutageFraction float64
	// ChurnPerHour tunes ordinary path churn.
	ChurnPerHour float64
	// NoPay: when true, the scenario deliberately excludes all benign
	// look-alike operations, leaving only attacks and baseline. Useful for
	// isolating detection rate from false-positive rate.
	AttacksOnly bool
}

// DefaultOptions returns a 36-hour scenario, the length of a real on-call
// rotation: long enough to contain a carrier maintenance window, a scrubbing
// session and several attacks, short enough to evaluate in seconds.
func DefaultOptions() Options {
	return Options{
		Seed:             20261120,
		Duration:         36 * time.Hour,
		Start:            time.Date(2026, 11, 18, 0, 0, 0, 0, time.UTC),
		SnapshotInterval: 5 * time.Minute,
		OutageFraction:   0.08,
		ChurnPerHour:     0.35,
	}
}

// Build creates the scenario named by opts. The name is carried into the
// scenario file so a reviewer can tell where a feed came from.
func Build(reg *registry.Registry, name string, opts Options) (model.Scenario, error) {
	if opts.Duration <= 0 {
		return model.Scenario{}, fmt.Errorf("sim: duration must be positive")
	}
	if opts.SnapshotInterval <= 0 {
		opts.SnapshotInterval = 5 * time.Minute
	}
	tl := Timeline{Start: opts.Start, End: opts.Start.Add(opts.Duration)}
	world := BuildWorld(reg, opts.Seed)
	rng := newRNG(opts.Seed ^ 0x5DEECE66D)

	// Interleave attacks and benign operations so the scenario is not neatly
	// sorted by "attack, then normal".
	tl.Add(buildHijackScripts(world, &tl, rng)...)
	if !opts.AttacksOnly {
		tl.Add(buildBenignScripts(world, &tl, rng)...)
	}

	gen := &Generator{
		Reg:              reg,
		Seed:             opts.Seed,
		SnapshotInterval: opts.SnapshotInterval,
		OutageFraction:   opts.OutageFraction,
		ChurnPerHour:     opts.ChurnPerHour,
	}
	sc, err := gen.Generate(tl)
	if err != nil {
		return model.Scenario{}, err
	}
	sc.Name = name
	return sc, nil
}

// OrderObservations is exposed so callers that merge scenarios keep the feed
// ordered by ReceivedAt.
func OrderObservations(obs []model.Observation) { model.SortObservations(obs) }
