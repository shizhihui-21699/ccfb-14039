// Package policy defines the operator-controlled knobs of the detector: our
// address space, expected origins, known-good cleanings, suppression windows
// and the weights/relations that map evidence to a page.
package policy

import (
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"hijackwatch/internal/model"
)

// Prefix is one registered address block.
type Prefix struct {
	CIDR string `yaml:"cidr"`

	// ExpectedOrigins lists the origin ASNs that may legitimately announce
	// this prefix.  Any other origin on an exact/sub-prefix announcement is a
	// hard signal (bogus origin / sub-prefix hijack).
	ExpectedOrigins []uint32 `yaml:"expected_origins"`

	// ApprovedCleanings lists upstream ASNs that may legitimately announce
	// more-specifics of this prefix for DDoS scrubbing.  A matching more
	// specific is downgraded to informational unless other hard signals fire.
	ApprovedCleanings []uint32 `yaml:"approved_cleanings"`
}

// KnownIncident pins a peer ASN or prefix that has been formally approved by
// network operations (e.g. a migration window).  It lowers severity but never
// hides the alert.
type KnownIncident struct {
	PeerASN uint32    `yaml:"peer_asn"`
	CIDR    string    `yaml:"cidr"`
	Reason  string    `yaml:"reason"`
	Expires time.Time `yaml:"expires"`
}

// Weights converts raw evidence into severity.  All values are tunable; the
// defaults are documented in config.example.yaml.
type Weights struct {
	// Score at which each severity starts.  Ordered critical, high, medium, low.
	ScoreCritical int `yaml:"score_critical"`
	ScoreHigh     int `yaml:"score_high"`
	ScoreMedium   int `yaml:"score_medium"`
	ScoreLow      int `yaml:"score_low"`

	// Evidence weights.
	WeightWrongOrigin       int `yaml:"weight_wrong_origin"`
	WeightExactOrigin       int `yaml:"weight_exact_origin"`
	WeightMoreSpecific      int `yaml:"weight_more_specific"`
	WeightCleanupUnapproved int `yaml:"weight_cleanup_unapproved"`
	WeightSuspiciousASN     int `yaml:"weight_suspicious_asn"`
	WeightNewUpstreamASN    int `yaml:"weight_new_upstream_asn"`
	WeightAbsurdPath        int `yaml:"weight_absurd_path"`
	WeightPrependedLoop     int `yaml:"weight_prepended_loop"`
	WeightCrossCollector    int `yaml:"weight_cross_collector"`
	WeightMultiCollector    int `yaml:"weight_multi_collector"`
	WeightPeerAllowed       int `yaml:"weight_peer_allowed"`
	WeightApprovedCleanup   int `yaml:"weight_approved_cleanup"`
	WeightKnownIncident     int `yaml:"weight_known_incident"`
	WeightObservedUpstream  int `yaml:"weight_observed_upstream"`
}

// Config is the full detector policy.
type Config struct {
	OrgName string `yaml:"org_name"`

	Prefixes       []Prefix        `yaml:"prefixes"`
	KnownIncidents []KnownIncident `yaml:"known_incidents"`

	// SuspiciousRecentASNs are ASNs seen in real hijacks recently; their
	// appearance in a path is a weak signal.  Populated by the operator.
	SuspiciousRecentASNs []uint32 `yaml:"suspicious_recent_asns"`

	// NeighborRTT bounds how long we wait for other collectors to corroborate
	// an update.  Updates are only judged with the update stream that arrived
	// within this window (by ReceivedAt).
	NeighborRTT time.Duration `yaml:"neighbor_rtt"`

	// DedupWindow collapses repeated updates from the same collector/prefix.
	DedupWindow time.Duration `yaml:"dedup_window"`

	// PathHistoryWindow is how much observed path history we keep for a
	// prefix when judging "new upstream ASN" and path novelty.
	PathHistoryWindow time.Duration `yaml:"path_history_window"`

	// ResolutionWindow: an incident auto-resolves after the last evidence of
	// it is older than this.
	ResolutionWindow time.Duration `yaml:"resolution_window"`

	// SuppressionWindow (per prefix + origin) suppresses re-paging for the same
	// incident while evidence keeps arriving.
	SuppressionWindow time.Duration `yaml:"suppression_window"`

	Weights Weights `yaml:"weights"`

	// IgnoreCollectors are collectors with known-bad feeds (maintenance).
	IgnoreCollectors []string `yaml:"ignore_collectors"`

	// MinCollectors is how many distinct observation points a corroboration
	// signal requires.
	MinCollectors int `yaml:"min_collectors"`

	// MinAlertSeverity is the lowest severity that is materialised as an alert.
	// Evidence below this threshold is counted but not stored or paged.  It
	// keeps the alert queue focused on what an operator would act on.
	MinAlertSeverity model.Severity `yaml:"-"`
	// MinSeverity is the YAML spelling of MinAlertSeverity.
	MinSeverity string `yaml:"min_severity"`

	// CleanupCooldown is how long an approved-cleaning more-specific keeps its
	// downgrade after it first appears.
	CleanupCooldown time.Duration `yaml:"cleanup_cooldown"`

	// MaxPlausibleASPathLen is the path length above which a pattern repeats
	// (path prepending) too much to be a normal TE decision.
	MaxPlausibleASPathLen int `yaml:"max_plausible_as_path_len"`
}

// Defaults returns a conservative, documented default policy.
func Defaults() Config {
	return Config{
		OrgName:               "example-net",
		NeighborRTT:           90 * time.Second,
		DedupWindow:           30 * time.Second,
		PathHistoryWindow:     24 * time.Hour,
		ResolutionWindow:      10 * time.Minute,
		SuppressionWindow:     30 * time.Minute,
		CleanupCooldown:       4 * time.Hour,
		MinCollectors:         2,
		MaxPlausibleASPathLen: 16,
		MinAlertSeverity:      model.SevLow,
		Weights: Weights{
			ScoreCritical:           100,
			ScoreHigh:               70,
			ScoreMedium:             45,
			ScoreLow:                20,
			WeightWrongOrigin:       60,
			WeightExactOrigin:       15,
			WeightMoreSpecific:      35,
			WeightCleanupUnapproved: 25,
			WeightSuspiciousASN:     20,
			WeightNewUpstreamASN:    10,
			WeightAbsurdPath:        30,
			WeightPrependedLoop:     35,
			WeightCrossCollector:    15,
			WeightMultiCollector:    15,
			WeightPeerAllowed:       25,
			WeightApprovedCleanup:   40,
			WeightKnownIncident:     30,
			WeightObservedUpstream:  8,
		},
	}
}

// Load reads and normalizes a config file, applying defaults for unset fields.
func Load(path string) (Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	cfg := Defaults()
	cfg.Prefixes = nil
	cfg.KnownIncidents = nil
	cfg.SuspiciousRecentASNs = nil
	cfg.IgnoreCollectors = nil
	// Start from defaults so zero-valued optional fields are meaningful, then
	// overwrite.
	cfg = Defaults()
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", path, err)
	}
	cfg.normalize()
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c *Config) normalize() {
	if c.NeighborRTT <= 0 {
		c.NeighborRTT = 90 * time.Second
	}
	if c.DedupWindow <= 0 {
		c.DedupWindow = 30 * time.Second
	}
	if c.PathHistoryWindow <= 0 {
		c.PathHistoryWindow = 24 * time.Hour
	}
	if c.ResolutionWindow <= 0 {
		c.ResolutionWindow = 10 * time.Minute
	}
	if c.SuppressionWindow <= 0 {
		c.SuppressionWindow = 30 * time.Minute
	}
	if c.CleanupCooldown <= 0 {
		c.CleanupCooldown = 4 * time.Hour
	}
	if c.MinCollectors <= 0 {
		c.MinCollectors = 2
	}
	if c.MaxPlausibleASPathLen <= 0 {
		c.MaxPlausibleASPathLen = 16
	}
	if strings.TrimSpace(c.MinSeverity) != "" {
		if sev, err := model.ParseSeverity(c.MinSeverity); err == nil {
			c.MinAlertSeverity = sev
		}
	}
	d := Defaults().Weights
	w := &c.Weights
	if w.ScoreCritical == 0 {
		w.ScoreCritical = d.ScoreCritical
	}
	if w.ScoreHigh == 0 {
		w.ScoreHigh = d.ScoreHigh
	}
	if w.ScoreMedium == 0 {
		w.ScoreMedium = d.ScoreMedium
	}
	if w.ScoreLow == 0 {
		w.ScoreLow = d.ScoreLow
	}
	if w.WeightWrongOrigin == 0 {
		w.WeightWrongOrigin = d.WeightWrongOrigin
	}
	if w.WeightExactOrigin == 0 {
		w.WeightExactOrigin = d.WeightExactOrigin
	}
	if w.WeightMoreSpecific == 0 {
		w.WeightMoreSpecific = d.WeightMoreSpecific
	}
	if w.WeightCleanupUnapproved == 0 {
		w.WeightCleanupUnapproved = d.WeightCleanupUnapproved
	}
	if w.WeightSuspiciousASN == 0 {
		w.WeightSuspiciousASN = d.WeightSuspiciousASN
	}
	if w.WeightNewUpstreamASN == 0 {
		w.WeightNewUpstreamASN = d.WeightNewUpstreamASN
	}
	if w.WeightAbsurdPath == 0 {
		w.WeightAbsurdPath = d.WeightAbsurdPath
	}
	if w.WeightPrependedLoop == 0 {
		w.WeightPrependedLoop = d.WeightPrependedLoop
	}
	if w.WeightCrossCollector == 0 {
		w.WeightCrossCollector = d.WeightCrossCollector
	}
	if w.WeightMultiCollector == 0 {
		w.WeightMultiCollector = d.WeightMultiCollector
	}
	if w.WeightPeerAllowed == 0 {
		w.WeightPeerAllowed = d.WeightPeerAllowed
	}
	if w.WeightApprovedCleanup == 0 {
		w.WeightApprovedCleanup = d.WeightApprovedCleanup
	}
	if w.WeightKnownIncident == 0 {
		w.WeightKnownIncident = d.WeightKnownIncident
	}
	if w.WeightObservedUpstream == 0 {
		w.WeightObservedUpstream = d.WeightObservedUpstream
	}
}

// Validate checks that the config is usable.
func (c *Config) Validate() error {
	if len(c.Prefixes) == 0 {
		return fmt.Errorf("no prefixes configured")
	}
	seen := map[string]bool{}
	for i := range c.Prefixes {
		p := &c.Prefixes[i]
		pref, err := netip.ParsePrefix(strings.TrimSpace(p.CIDR))
		if err != nil {
			return fmt.Errorf("prefix[%d] %q: %w", i, p.CIDR, err)
		}
		key := pref.Masked().String()
		if seen[key] {
			return fmt.Errorf("duplicate prefix %s", key)
		}
		seen[key] = true
		if len(p.ExpectedOrigins) == 0 {
			return fmt.Errorf("prefix %s has no expected_origins", key)
		}
	}
	for i := range c.KnownIncidents {
		k := &c.KnownIncidents[i]
		if k.CIDR != "" {
			if _, err := netip.ParsePrefix(strings.TrimSpace(k.CIDR)); err != nil {
				return fmt.Errorf("known_incidents[%d] %q: %w", i, k.CIDR, err)
			}
		}
		if k.PeerASN == 0 && k.CIDR == "" {
			return fmt.Errorf("known_incidents[%d] needs peer_asn or cidr", i)
		}
	}
	return nil
}

// RegisteredPrefix pairs a policy block with its parsed form.
type RegisteredPrefix struct {
	Policy       Prefix
	Prefix       netip.Prefix
	Origins      map[uint32]bool
	CleaningASNs map[uint32]bool
}

// Registered returns the parsed prefix registry.
func (c *Config) Registered() []RegisteredPrefix {
	out := make([]RegisteredPrefix, 0, len(c.Prefixes))
	for _, p := range c.Prefixes {
		pref, _ := netip.ParsePrefix(strings.TrimSpace(p.CIDR))
		rp := RegisteredPrefix{
			Policy:       p,
			Prefix:       pref.Masked(),
			Origins:      map[uint32]bool{},
			CleaningASNs: map[uint32]bool{},
		}
		for _, o := range p.ExpectedOrigins {
			rp.Origins[o] = true
		}
		for _, a := range p.ApprovedCleanings {
			rp.CleaningASNs[a] = true
		}
		out = append(out, rp)
	}
	return out
}

// MatchPrefix finds the registered prefix that relates to p.  Exact matches
// win over less-specific containment so a hijack of a registered /24 is not
// shadowed by its parent /16.
func (c *Config) MatchPrefix(p netip.Prefix, regs []RegisteredPrefix) (RegisteredPrefix, model.Relation, bool) {
	for _, r := range regs {
		if model.Relate(r.Prefix, p) == model.Exact {
			return r, model.Exact, true
		}
	}
	for _, r := range regs {
		if rel := model.Relate(r.Prefix, p); rel == model.MoreSpecific {
			return r, rel, true
		}
	}
	for _, r := range regs {
		if rel := model.Relate(r.Prefix, p); rel == model.LessSpecific {
			return r, rel, true
		}
	}
	return RegisteredPrefix{}, model.Unrelated, false
}

// IsApprovedCleaning reports whether the AS is allowed to scrub for this block.
func (c *Config) IsApprovedCleaning(rp RegisteredPrefix, asn uint32) bool {
	return rp.CleaningASNs[asn]
}

// MatchKnownIncident returns the first non-expired known incident matching the
// peer ASN or the prefix.
func (c *Config) MatchKnownIncident(peerASN uint32, p netip.Prefix, now time.Time) (KnownIncident, bool) {
	for _, k := range c.KnownIncidents {
		if !k.Expires.IsZero() && now.After(k.Expires) {
			continue
		}
		if k.PeerASN != 0 && k.PeerASN == peerASN {
			return k, true
		}
		if k.CIDR != "" {
			if kp, err := netip.ParsePrefix(strings.TrimSpace(k.CIDR)); err == nil {
				kp = kp.Masked()
				// Match the registered block or anything inside it, but not a
				// broader aggregate that merely contains it.
				if kp.Contains(p.Addr()) && p.Bits() >= kp.Bits() {
					return k, true
				}
			}
		}
	}
	return KnownIncident{}, false
}

// IgnoredCollector reports whether a collector is configured out.
func (c *Config) IgnoredCollector(name string) bool {
	for _, n := range c.IgnoreCollectors {
		if n == name {
			return true
		}
	}
	return false
}
