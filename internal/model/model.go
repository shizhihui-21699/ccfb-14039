// Package model holds the wire types shared by the simulator, the detection
// engine, the HTTP service and the offline evaluator.
package model

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

// UpdateType is the BGP message type as reported by a collector.
type UpdateType string

const (
	Announce UpdateType = "announce"
	Withdraw UpdateType = "withdraw"
)

// Update is one BGP update as delivered by one observation point (VP).
//
// EventTime is when the collector says the BGP event happened; ReceivedAt is
// when our platform received it.  The difference is the observation lag and is
// central to the noise handling in the detector.
type Update struct {
	Seq         int        `json:"seq,omitempty"`
	Collector   string     `json:"collector"`
	PeerASN     uint32     `json:"peer_asn,omitempty"`
	PeerIP      string     `json:"peer_ip,omitempty"`
	Type        UpdateType `json:"type"`
	Prefix      string     `json:"prefix"`
	ASPath      []uint32   `json:"as_path,omitempty"`
	NextHop     string     `json:"next_hop,omitempty"`
	Communities []string   `json:"communities,omitempty"`
	EventTime   time.Time  `json:"event_time"`
	ReceivedAt  time.Time  `json:"received_at"`
}

// ParsedPrefix returns the update prefix as a netip.Prefix.
func (u Update) ParsedPrefix() (netip.Prefix, error) {
	return ParsePrefixOK(u.Prefix)
}

// ParsePrefixOK parses and masks a prefix string.
func ParsePrefixOK(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("bad prefix %q: %w", s, err)
	}
	return p.Masked(), nil
}

// Origin returns the origin AS of an announcement (the right-most non-zero ASN
// of the AS_PATH).
func (u Update) Origin() (uint32, bool) {
	for i := len(u.ASPath) - 1; i >= 0; i-- {
		if u.ASPath[i] != 0 {
			return u.ASPath[i], true
		}
	}
	return 0, false
}

// Validate performs the checks the ingestion API applies before accepting an
// update.  It is deliberately strict about timestamps because the whole
// detector reasons about time.
func (u Update) Validate(now time.Time) error {
	if strings.TrimSpace(u.Collector) == "" {
		return fmt.Errorf("collector is required")
	}
	if u.Type != Announce && u.Type != Withdraw {
		return fmt.Errorf("invalid update type %q", u.Type)
	}
	if _, err := u.ParsedPrefix(); err != nil {
		return err
	}
	if u.Type == Announce {
		if len(u.ASPath) == 0 {
			return fmt.Errorf("announce without as_path")
		}
		if _, ok := u.Origin(); !ok {
			return fmt.Errorf("announce with no usable origin AS")
		}
	}
	if u.EventTime.IsZero() || u.ReceivedAt.IsZero() {
		return fmt.Errorf("event_time and received_at are required")
	}
	if u.ReceivedAt.Before(u.EventTime) {
		return fmt.Errorf("received_at %s precedes event_time %s", u.ReceivedAt, u.EventTime)
	}
	if u.EventTime.After(now.Add(24 * time.Hour)) {
		return fmt.Errorf("event_time %s is implausibly far in the future", u.EventTime)
	}
	return nil
}

// Relation describes how an observed announced prefix relates to one of our
// registered prefixes.
type Relation int

const (
	Unrelated Relation = iota
	Exact
	MoreSpecific
	LessSpecific
)

func (r Relation) String() string {
	switch r {
	case Exact:
		return "exact"
	case MoreSpecific:
		return "more-specific"
	case LessSpecific:
		return "less-specific"
	default:
		return "unrelated"
	}
}

// Relate relates observed p to registered reg.
func Relate(reg, p netip.Prefix) Relation {
	if reg.Addr().BitLen() != p.Addr().BitLen() {
		return Unrelated
	}
	if reg.Contains(p.Addr()) && p.Bits() >= reg.Bits() {
		if p.Bits() == reg.Bits() {
			return Exact
		}
		return MoreSpecific
	}
	if p.Contains(reg.Addr()) && p.Bits() < reg.Bits() {
		return LessSpecific
	}
	return Unrelated
}

// Severity is an ordered alert severity.
type Severity int

const (
	SevInfo Severity = iota // informational, never pages
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "critical"
	case SevHigh:
		return "high"
	case SevMedium:
		return "medium"
	case SevLow:
		return "low"
	default:
		return "info"
	}
}

// MarshalJSON renders a severity as its name rather than a bare integer, so
// API consumers do not have to know the ordering.
func (s Severity) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// UnmarshalJSON accepts either a severity name or its integer value.
func (s *Severity) UnmarshalJSON(b []byte) error {
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*s = Severity(n)
		return nil
	}
	var name string
	if err := json.Unmarshal(b, &name); err != nil {
		return err
	}
	v, err := ParseSeverity(name)
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// ParseSeverity parses a severity name (used by config and truth files).
func ParseSeverity(s string) (Severity, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":
		return SevInfo, nil
	case "low":
		return SevLow, nil
	case "medium":
		return SevMedium, nil
	case "high":
		return SevHigh, nil
	case "critical":
		return SevCritical, nil
	}
	return SevInfo, fmt.Errorf("unknown severity %q", s)
}

// Incident kinds.  They are deliberately coarse: the alert pipeline needs one
// primary explanation for an anomaly, while the evidence list keeps the detail.
const (
	KindBogusOrigin   = "bogus_origin"
	KindSubprefix     = "subprefix_hijack"
	KindPathInsertion = "path_insertion"
	KindForgedPath    = "forged_path"
	KindPathChange    = "path_change"
)

// Evidence is one explainable detector signal attached to an incident.
//
// Hard means the signal is structurally conclusive on its own (wrong origin,
// impossible path).  Strong means it is a high-quality indicator but still
// benefits from corroboration.  Mitigation means the signal argues *against*
// an attack (approved scrubbing, provider-wide change) and is there so the
// operator can see why severity was capped.
type Evidence struct {
	Code       string `json:"code"`
	Weight     int    `json:"weight"`
	Hard       bool   `json:"hard"`
	Strong     bool   `json:"strong,omitempty"`
	Mitigation bool   `json:"mitigation,omitempty"`
	Detail     string `json:"detail"`
}

// AlertStatus is the lifecycle state of an alert.
type AlertStatus string

const (
	StatusFiring   AlertStatus = "firing"
	StatusResolved AlertStatus = "resolved"
)

// Alert is what an on-call engineer sees.  One alert per (kind, prefix,
// origin) incident; severity is upgraded in place as evidence accumulates.
type Alert struct {
	ID         string          `json:"id"`
	IncidentID string          `json:"incident_id"`
	Kind       string          `json:"kind"`
	Prefix     string          `json:"prefix"`
	Parent     string          `json:"parent_prefix"`
	Origin     uint32          `json:"origin_asn"`
	Status     AlertStatus     `json:"status"`
	Severity   Severity        `json:"severity"`
	Score      int             `json:"score"`
	Confidence float64         `json:"confidence"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
	UpdatedAt  time.Time       `json:"updated_at"`
	ResolvedAt *time.Time      `json:"resolved_at,omitempty"`
	Collectors []string        `json:"collectors"`
	Evidence   []Evidence      `json:"evidence"`
	Summary    string          `json:"summary"`
	Timeline   []TimelineEntry `json:"timeline,omitempty"`

	// CandKey links the alert back to the detector's internal candidate so the
	// resolution loop can tell whether the route is still present.  Not part of
	// the public API.
	CandKey string `json:"-"`
}

// TimelineEntry records alert state transitions and evidence accumulation.
type TimelineEntry struct {
	At       time.Time `json:"at"`
	Event    string    `json:"event"`
	Severity Severity  `json:"severity"`
	Score    int       `json:"score"`
	Detail   string    `json:"detail,omitempty"`
}

// ASNClass classifies an AS number for path sanity checks.
type ASNClass string

const (
	ASNPublic   ASNClass = "public"
	ASNPrivate  ASNClass = "private"
	ASNReserved ASNClass = "reserved"
	ASNDoc      ASNClass = "documentation"
	ASNAsTrans  ASNClass = "as_trans"
	ASNUnalloc  ASNClass = "unallocated"
)

// ClassifyASN returns a coarse class for an ASN.  Only classes that BGP should
// never carry in a real path are flagged by the forge detector.
func ClassifyASN(asn uint32) ASNClass {
	switch {
	case asn == 0:
		return ASNReserved
	case asn == 23456:
		return ASNAsTrans
	case asn >= 64496 && asn <= 64511:
		return ASNDoc
	case asn >= 64512 && asn <= 65534:
		return ASNPrivate
	case asn == 65535:
		return ASNReserved
	case asn >= 65536 && asn <= 65551:
		return ASNDoc
	case asn >= 4200000000 && asn <= 4294967294:
		return ASNPrivate
	case asn == 4294967295:
		return ASNReserved
	}
	return ASNPublic
}

// IsSuspiciousASN reports ASNs whose presence in a path is always worth a
// signal (never a page on its own).
func IsSuspiciousASN(asn uint32) bool {
	switch ClassifyASN(asn) {
	case ASNReserved, ASNPrivate, ASNAsTrans:
		return true
	}
	return false
}
