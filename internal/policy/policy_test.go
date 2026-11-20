package policy

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"hijackwatch/internal/model"
)

const sampleConfig = `
org_name: test-net
prefixes:
  - cidr: 203.0.113.0/24
    expected_origins: [133900]
    approved_cleanings: [129900]
  - cidr: 198.51.100.0/24
    expected_origins: [133900, 133901]
known_incidents:
  - peer_asn: 129500
    reason: change window
    expires: 2026-03-03T12:00:00Z
suspicious_recent_asns: [204800]
neighbor_rtt: 90s
min_collectors: 3
min_severity: high
`

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "cfg.yaml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	cfg, err := Load(writeTemp(t, sampleConfig))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Prefixes) != 2 {
		t.Fatalf("prefixes = %d, want 2", len(cfg.Prefixes))
	}
	if cfg.MinCollectors != 3 {
		t.Errorf("min_collectors = %d, want 3", cfg.MinCollectors)
	}
	if cfg.MinAlertSeverity != model.SevHigh {
		t.Errorf("min_severity = %s, want high", cfg.MinAlertSeverity)
	}
	if cfg.NeighborRTT != 90*time.Second {
		t.Errorf("neighbor_rtt = %s, want 90s", cfg.NeighborRTT)
	}
	// Unset values fall back to documented defaults.
	if cfg.ResolutionWindow != 10*time.Minute {
		t.Errorf("resolution_window default = %s", cfg.ResolutionWindow)
	}
	if cfg.Weights.WeightWrongOrigin == 0 {
		t.Error("weights not defaulted")
	}
}

func TestLoadRejectsBad(t *testing.T) {
	bad := []string{
		``, // no prefixes
		`prefixes:
  - cidr: not-a-prefix
    expected_origins: [1]`,
		`prefixes:
  - cidr: 203.0.113.0/24
    expected_origins: []`,
		`prefixes:
  - cidr: 203.0.113.0/24
    expected_origins: [1]
  - cidr: 203.0.113.0/24
    expected_origins: [2]`,
	}
	for i, b := range bad {
		if _, err := Load(writeTemp(t, b)); err == nil {
			t.Errorf("bad config %d accepted", i)
		}
	}
}

func TestMatchPrefixExactBeatsLessSpecific(t *testing.T) {
	cfg := Defaults()
	cfg.Prefixes = []Prefix{
		{CIDR: "203.0.0.0/16", ExpectedOrigins: []uint32{1}},
		{CIDR: "203.0.113.0/24", ExpectedOrigins: []uint32{2}},
	}
	regs := cfg.Registered()
	_, rel, ok := cfg.MatchPrefix(netip.MustParsePrefix("203.0.113.0/24"), regs)
	if !ok || rel != model.Exact {
		t.Errorf("rel = %s ok=%v, want exact", rel, ok)
	}
}

func TestMatchKnownIncidentExpires(t *testing.T) {
	cfg := Defaults()
	cfg.Prefixes = []Prefix{{CIDR: "203.0.113.0/24", ExpectedOrigins: []uint32{1}}}
	cfg.KnownIncidents = []KnownIncident{{
		PeerASN: 129500, Expires: time.Date(2026, 3, 3, 12, 0, 0, 0, time.UTC),
	}}
	before := time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC)
	after := time.Date(2026, 3, 3, 18, 0, 0, 0, time.UTC)
	if _, ok := cfg.MatchKnownIncident(129500, netip.MustParsePrefix("203.0.113.0/24"), before); !ok {
		t.Error("known incident not matched before expiry")
	}
	if _, ok := cfg.MatchKnownIncident(129500, netip.MustParsePrefix("203.0.113.0/24"), after); ok {
		t.Error("known incident matched after expiry")
	}
}

func TestIsApprovedCleaning(t *testing.T) {
	cfg := Defaults()
	cfg.Prefixes = []Prefix{{CIDR: "203.0.113.0/24", ExpectedOrigins: []uint32{1}, ApprovedCleanings: []uint32{129900}}}
	regs := cfg.Registered()
	if !cfg.IsApprovedCleaning(regs[0], 129900) {
		t.Error("129900 should be an approved cleaner")
	}
	if cfg.IsApprovedCleaning(regs[0], 204500) {
		t.Error("204500 should not be an approved cleaner")
	}
}
