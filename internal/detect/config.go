package detect

import (
	"fmt"
	"time"
)

// Config holds every tunable in one place. All durations are wall-clock and
// all scores are additive integers, so a reviewer can reason about exactly why
// a route did or did not alert.
type Config struct {
	// EvalInterval is how often the engine sweeps. It bounds alert latency:
	// an alert can be at most a few intervals old.
	EvalInterval time.Duration `yaml:"eval_interval"`
	// SnapshotInterval is how often collectors are expected to deliver a full
	// RIB dump per vantage point. Liveness and visibility are measured against
	// it, so a VP that misses two dumps is treated as blind, not calm.
	SnapshotInterval time.Duration `yaml:"snapshot_interval"`
	// Warmup is how long after start the engine learns per-prefix baselines
	// (normal origins and adjacent ASNs) before it trusts them.
	Warmup time.Duration `yaml:"warmup"`
	// MinVPs is how many distinct vantage points must corroborate an anomaly
	// before it can be a WARNING or higher on its own.
	MinVPs int `yaml:"min_vps"`
	// MinWindows is how many evaluation windows an anomaly must persist before
	// it may alert. One window of odd data is a glitch; two in a row is news.
	MinWindows int `yaml:"min_windows"`
	// WarningScore and CriticalScore are the additive score thresholds.
	WarningScore  int `yaml:"warning_score"`
	CriticalScore int `yaml:"critical_score"`
	// ResolveAfter is how long an incident must be absent from a VP's RIB
	// before it is resolved.
	ResolveAfter time.Duration `yaml:"resolve_after"`
	// BlindRatio: if fewer than this fraction of the VPs that normally report
	// a prefix are reporting it, the engine flags reduced confidence and
	// refuses to resolve incidents for that prefix (absorbs outages).
	BlindRatio float64 `yaml:"blind_ratio"`
	// StaleVPFactor: a VP whose last dump is older than this multiple of
	// SnapshotInterval is considered stale.
	StaleVPFactor float64 `yaml:"stale_vp_factor"`
	// DelayWarn is the per-VP collection delay above which data-quality flags
	// are attached to alerts (delayed data makes a stale path look current).
	DelayWarn time.Duration `yaml:"delay_warn"`
	// FlapCount is how many withdraw/reannounce cycles inside FlapWindow are
	// worth an informational event.
	FlapCount  int           `yaml:"flap_count"`
	FlapWindow time.Duration `yaml:"flap_window"`
	// MaxPathSamples bounds alert payload size.
	MaxPathSamples int `yaml:"max_path_samples"`
	// BaselineMinSamples is how many legitimate observations a prefix needs
	// before path novelty is meaningful. Below this the engine stays silent
	// rather than calling every path new during warmup.
	BaselineMinSamples int `yaml:"baseline_min_samples"`
	// SingleVPMinAge is how long an anomaly seen by fewer than MinVPs must
	// persist before it may alert. This is a duration, not a window count, on
	// purpose: expressing it in ticks silently weakens it whenever the eval
	// interval is lowered (4 windows is two minutes at a 30s tick but nearly
	// an hour at 15m). A single collector is wrong in ways two are not, so it
	// must be observed for a long time before anyone is paged.
	SingleVPMinAge time.Duration `yaml:"single_vp_min_age"`
	// GlobalCoverage is the fraction of reporting VPs that must agree before a
	// path change is treated as fleet-wide (operational) rather than regional.
	GlobalCoverage float64 `yaml:"global_coverage"`
	// RegionalCoverage is the fraction at or below which a change is treated as
	// selective interception.
	RegionalCoverage float64 `yaml:"regional_coverage"`
	// PropagationGrace is how long after a route change the engine waits before
	// judging its scope. A fleet-wide change races across collectors over
	// minutes: early on it is visible at two of them and looks precisely like
	// selective interception. Judging scope before propagation settles produces
	// exactly the wrong call, so the engine refuses to apply scope adjustments
	// before the grace period and requires more persistence to escalate.
	PropagationGrace time.Duration `yaml:"propagation_grace"`

	Weights Weights `yaml:"weights"`
}

// Weights are the additive score contributions. They live in config so the
// operator can re-tune without a rebuild; the defaults encode the reasoning
// documented next to each field.
type Weights struct {
	// ForeignOrigin is applied when a prefix we protect is originated by an
	// ASN that is neither ours nor registered as allowed. This is the single
	// strongest signal: it is the definition of an origin hijack.
	ForeignOrigin int `yaml:"foreign_origin"`
	// CoveringPrefix applies when the foreign announcement is *shorter* than
	// ours and swallows it: it can blackhole every one of our addresses.
	CoveringPrefix int `yaml:"covering_prefix"`
	// SubPrefix applies for a more-specific inside our space. More-specifics
	// win forwarding, so they steal traffic, but they are also everyday
	// customer practice; legitimacy checks decide the outcome.
	SubPrefix int `yaml:"subprefix"`
	// RPKIInvalid applies when a covering ROA exists but the announcement
	// violates it. Proof of misconfiguration or malice.
	RPKIInvalid int `yaml:"rpki_invalid"`
	// RPKINone applies to unregistered space: no evidence either way.
	RPKINone int `yaml:"rpki_none"`
	// PathUnknownAdjacent applies to a path with our origin but an upstream
	// that is neither ours nor a registered peer.
	PathUnknownAdjacent int `yaml:"path_unknown_adjacent"`
	// PathStub applies when an AS that never transits appears mid-path.
	PathStub int `yaml:"path_stub"`
	// PathLoop applies when an AS appears twice: BGP paths cannot loop.
	PathLoop int `yaml:"path_loop"`
	// PathTooLong applies to paths longer than the registry allows.
	PathTooLong int `yaml:"path_too_long"`
	// AdjacencyUnknown applies per consecutive pair with no known relationship.
	// Weak: public AS graphs are incomplete.
	AdjacencyUnknown int `yaml:"adjacency_unknown"`
	// AdjacencyUnknownCap bounds the summed adjacency penalty.
	AdjacencyUnknownCap int `yaml:"adjacency_unknown_cap"`
	// UnknownASN applies per ASN mid-path that appears in no public AS table.
	UnknownASN int `yaml:"unknown_asn"`
	// NovelPath applies to a path that has never been observed for the prefix.
	// Weak on its own: carriers re-route legitimately.
	NovelPath int `yaml:"novel_path"`
	// GlobalPathChangeDiscount is subtracted when a path change is observed
	// from most vantage points at once. A change the whole Internet makes
	// simultaneously is much more likely an operational re-route than an
	// interception of specific traffic.
	GlobalPathChangeDiscount int `yaml:"global_path_change_discount"`
	// RegionalBoost is added when an anomaly is seen from a minority of VPs,
	// the shape of selective interception.
	RegionalBoost int `yaml:"regional_boost"`
	// Persistence is added per full day-ish of continuous observation, capped.
	Persistence    int `yaml:"persistence"`
	PersistenceCap int `yaml:"persistence_cap"`
	// Corroboration adds points when the same anomaly is seen by more than
	// MinVPs independent collectors.
	Corroboration int `yaml:"corroboration"`
	// Authorized is subtracted when an authorization matches, pushing the
	// incident to INFO rather than dropping it, so it stays auditable.
	Authorized int `yaml:"authorized"`
}

// Defaults returns the shipping configuration with reasoning-friendly values.
func Defaults() Config {
	return Config{
		EvalInterval:       30 * time.Second,
		SnapshotInterval:   5 * time.Minute,
		Warmup:             30 * time.Minute,
		MinVPs:             2,
		MinWindows:         2,
		WarningScore:       45,
		CriticalScore:      80,
		ResolveAfter:       10 * time.Minute,
		BlindRatio:         0.5,
		StaleVPFactor:      2.5,
		DelayWarn:          20 * time.Second,
		FlapCount:          6,
		FlapWindow:         10 * time.Minute,
		MaxPathSamples:     5,
		SingleVPMinAge:     45 * time.Minute,
		BaselineMinSamples: 200,
		GlobalCoverage:     0.75,
		RegionalCoverage:   0.5,
		PropagationGrace:   20 * time.Minute,
		Weights: Weights{
			ForeignOrigin:            45,
			CoveringPrefix:           25,
			SubPrefix:                10,
			RPKIInvalid:              20,
			RPKINone:                 5,
			PathUnknownAdjacent:      40,
			PathStub:                 15,
			PathLoop:                 40,
			PathTooLong:              8,
			AdjacencyUnknown:         6,
			AdjacencyUnknownCap:      18,
			UnknownASN:               12,
			NovelPath:                18,
			GlobalPathChangeDiscount: 14,
			RegionalBoost:            8,
			Persistence:              2,
			PersistenceCap:           12,
			Corroboration:            8,
			Authorized:               -60,
		},
	}
}

// Validate fills defaults for unset fields and checks invariants. A config
// that would silently never alert is treated as an error, not a warning.
func (c *Config) Validate() error {
	d := Defaults()
	if c.EvalInterval <= 0 {
		c.EvalInterval = d.EvalInterval
	}
	if c.SnapshotInterval <= 0 {
		c.SnapshotInterval = d.SnapshotInterval
	}
	if c.Warmup < 0 {
		c.Warmup = d.Warmup
	}
	if c.MinVPs <= 0 {
		c.MinVPs = d.MinVPs
	}
	if c.MinWindows <= 0 {
		c.MinWindows = d.MinWindows
	}
	if c.WarningScore <= 0 {
		c.WarningScore = d.WarningScore
	}
	if c.CriticalScore <= 0 {
		c.CriticalScore = d.CriticalScore
	}
	if c.WarningScore >= c.CriticalScore {
		return fmt.Errorf("detector: warning_score %d must be below critical_score %d", c.WarningScore, c.CriticalScore)
	}
	if c.ResolveAfter <= 0 {
		c.ResolveAfter = d.ResolveAfter
	}
	if c.BlindRatio <= 0 || c.BlindRatio > 1 {
		c.BlindRatio = d.BlindRatio
	}
	if c.StaleVPFactor <= 0 {
		c.StaleVPFactor = d.StaleVPFactor
	}
	if c.DelayWarn <= 0 {
		c.DelayWarn = d.DelayWarn
	}
	if c.FlapCount <= 0 {
		c.FlapCount = d.FlapCount
	}
	if c.FlapWindow <= 0 {
		c.FlapWindow = d.FlapWindow
	}
	if c.MaxPathSamples <= 0 {
		c.MaxPathSamples = d.MaxPathSamples
	}
	if c.SingleVPMinAge <= 0 {
		c.SingleVPMinAge = d.SingleVPMinAge
	}
	if c.BaselineMinSamples <= 0 {
		c.BaselineMinSamples = d.BaselineMinSamples
	}
	if c.GlobalCoverage <= 0 || c.GlobalCoverage > 1 {
		c.GlobalCoverage = d.GlobalCoverage
	}
	if c.RegionalCoverage <= 0 || c.RegionalCoverage > 1 {
		c.RegionalCoverage = d.RegionalCoverage
	}
	if c.PropagationGrace <= 0 {
		c.PropagationGrace = d.PropagationGrace
	}
	c.Weights = mergeWeights(c.Weights, d.Weights)
	if c.Weights.ForeignOrigin <= 0 {
		return fmt.Errorf("detector: foreign_origin weight must be positive")
	}
	if c.Weights.Authorized >= 0 {
		return fmt.Errorf("detector: authorized weight must be negative (it discounts)")
	}
	return nil
}

// mergeWeights fills zero fields from defaults so a partial YAML override
// cannot silently disable a signal.
func mergeWeights(w, d Weights) Weights {
	zero := Weights{}
	if w == zero {
		return d
	}
	pick := func(v, def int) int {
		if v == 0 {
			return def
		}
		return v
	}
	w.ForeignOrigin = pick(w.ForeignOrigin, d.ForeignOrigin)
	w.CoveringPrefix = pick(w.CoveringPrefix, d.CoveringPrefix)
	w.SubPrefix = pick(w.SubPrefix, d.SubPrefix)
	w.RPKIInvalid = pick(w.RPKIInvalid, d.RPKIInvalid)
	w.RPKINone = pick(w.RPKINone, d.RPKINone)
	w.PathUnknownAdjacent = pick(w.PathUnknownAdjacent, d.PathUnknownAdjacent)
	w.PathStub = pick(w.PathStub, d.PathStub)
	w.PathLoop = pick(w.PathLoop, d.PathLoop)
	w.PathTooLong = pick(w.PathTooLong, d.PathTooLong)
	w.AdjacencyUnknown = pick(w.AdjacencyUnknown, d.AdjacencyUnknown)
	w.AdjacencyUnknownCap = pick(w.AdjacencyUnknownCap, d.AdjacencyUnknownCap)
	w.UnknownASN = pick(w.UnknownASN, d.UnknownASN)
	w.NovelPath = pick(w.NovelPath, d.NovelPath)
	w.GlobalPathChangeDiscount = pick(w.GlobalPathChangeDiscount, d.GlobalPathChangeDiscount)
	w.RegionalBoost = pick(w.RegionalBoost, d.RegionalBoost)
	w.Persistence = pick(w.Persistence, d.Persistence)
	w.PersistenceCap = pick(w.PersistenceCap, d.PersistenceCap)
	w.Corroboration = pick(w.Corroboration, d.Corroboration)
	if w.Authorized == 0 {
		w.Authorized = d.Authorized
	}
	return w
}
