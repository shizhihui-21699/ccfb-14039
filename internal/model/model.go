// Package model holds the wire-level types shared by the simulator, the
// detection engine and the evaluation harness. The shapes are deliberately
// close to a BGP UPDATE as seen by a collector (RouteViews / RIPE RIS style):
// a vantage point reports, per peer, the best route it currently has for a
// prefix.
package model

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ASN is a 32-bit autonomous system number.
type ASN uint32

func (a ASN) String() string { return "AS" + strconv.FormatUint(uint64(a), 10) }

// ParseASN parses "64500" or "AS64500".
func ParseASN(s string) (ASN, error) {
	s = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "AS")
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("bad ASN %q: %w", s, err)
	}
	return ASN(n), nil
}

func (a ASN) MarshalYAML() (any, error) { return a.String(), nil }

func (a ASN) MarshalText() ([]byte, error) { return []byte(a.String()), nil }

func (a *ASN) UnmarshalText(b []byte) error {
	v, err := ParseASN(string(b))
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// Prefix is an IP prefix. It wraps netip.Prefix so it marshals as "a.b.c.d/len".
type Prefix struct{ netip.Prefix }

func MustPrefix(s string) Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(err)
	}
	return Prefix{p.Masked()}
}

func ParsePrefix(s string) (Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return Prefix{}, err
	}
	return Prefix{p.Masked()}, nil
}

func (p Prefix) String() string { return p.Prefix.String() }

func (p Prefix) MarshalJSON() ([]byte, error) {
	return []byte(strconv.Quote(p.String())), nil
}

func (p *Prefix) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	pp, err := ParsePrefix(s)
	if err != nil {
		return err
	}
	*p = pp
	return nil
}

func (p Prefix) MarshalYAML() (any, error) { return p.String(), nil }

func (p *Prefix) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}
	pp, err := ParsePrefix(s)
	if err != nil {
		return err
	}
	*p = pp
	return nil
}

// Bits returns the prefix length.
func (p Prefix) Bits() int { return p.Prefix.Bits() }

// Contains reports whether q is equal to or more specific than p.
func (p Prefix) Contains(q Prefix) bool {
	return p.Prefix.Contains(q.Addr()) && q.Bits() >= p.Bits() && p.Addr().BitLen() == q.Addr().BitLen()
}

// Overlaps reports whether either prefix contains the other.
func (p Prefix) Overlaps(q Prefix) bool { return p.Contains(q) || q.Contains(p) }

// Observation is one route announcement or withdrawal as reported by one
// vantage point for one peer. Timestamps are split into the time the route
// changed at the VP (Timestamp) and the time our collector received it
// (ReceivedAt); the difference models propagation and export latency.
type Observation struct {
	ID          string    `json:"id"`
	VP          string    `json:"vp"`
	VPASN       ASN       `json:"vp_asn"`
	PeerASN     ASN       `json:"peer_asn"`
	Prefix      Prefix    `json:"prefix"`
	Origin      ASN       `json:"origin"`
	ASPath      []ASN     `json:"as_path"`
	Communities []string  `json:"communities,omitempty"`
	Withdraw    bool      `json:"withdraw,omitempty"`
	Timestamp   time.Time `json:"timestamp"`
	ReceivedAt  time.Time `json:"received_at"`
	// GroundTruth is only set by the simulator; the engine ignores it.
	GroundTruth string `json:"ground_truth,omitempty"`
}

// Adjacent returns the AS the origin is attached to: the last hop before the
// origin, skipping prepended repeats of the origin itself. Returns 0 when no
// such hop exists.
func (o Observation) Adjacent() ASN {
	for i := len(o.ASPath) - 1; i >= 0; i-- {
		if o.ASPath[i] != o.Origin {
			return o.ASPath[i]
		}
	}
	return 0
}

// PathSignature is a stable key for a path, used to group evidence.
func (o Observation) PathSignature() string {
	var b strings.Builder
	for i, a := range o.ASPath {
		if i > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(strconv.FormatUint(uint64(a), 10))
	}
	return b.String()
}

// Prepending returns how many extra times the origin AS appears at the tail of
// the path (0 means no prepending).
func (o Observation) Prepending() int {
	n := 0
	for i := len(o.ASPath) - 1; i >= 0 && o.ASPath[i] == o.Origin; i-- {
		n++
	}
	if n <= 1 {
		return 0
	}
	return n - 1
}

// HasCommunity reports whether the observation carries the exact community.
func (o Observation) HasCommunity(c string) bool {
	for _, got := range o.Communities {
		if got == c {
			return true
		}
	}
	return false
}

// SortObservations orders by ReceivedAt then ID, the order a collector would
// process them in.
func SortObservations(obs []Observation) {
	sort.SliceStable(obs, func(i, j int) bool {
		if obs[i].ReceivedAt.Equal(obs[j].ReceivedAt) {
			return obs[i].ID < obs[j].ID
		}
		return obs[i].ReceivedAt.Before(obs[j].ReceivedAt)
	})
}

// Kind classifies what an alert is about.
type Kind string

const (
	KindOriginHijack    Kind = "origin_hijack"     // a foreign origin announces exactly our prefix
	KindCoveringHijack  Kind = "covering_hijack"   // a foreign origin announces a shorter prefix covering ours
	KindSubPrefixHijack Kind = "subprefix_hijack"  // a more-specific inside our space from a foreign origin
	KindPathHijack      Kind = "path_hijack"       // our origin, but traffic is pulled through an unknown AS
	KindTransitChange   Kind = "transit_change"    // our AS switched upstream: informational
	KindScrubbing       Kind = "traffic_scrubbing" // pre-agreed diversion to a scrubbing center
	KindAuthorized      Kind = "authorized"        // matches a customer/anycast authorization
	KindFlap            Kind = "route_flap"        // withdraw/reannounce with identical attributes
	KindUnknown         Kind = "unknown"
)

func (k Kind) String() string { return string(k) }

// isHostile reports whether a kind describes an attack (as opposed to a
// recognized legitimate operation).
func (k Kind) IsHostile() bool {
	switch k {
	case KindOriginHijack, KindCoveringHijack, KindSubPrefixHijack, KindPathHijack:
		return true
	}
	return false
}

// Phase is the lifecycle stage of an alert.
type Phase string

const (
	PhaseRaised     Phase = "raised"
	PhaseEscalated  Phase = "escalated"
	PhaseDowngraded Phase = "downgraded" // new operational context (e.g. scrub session recorded) explains it
	PhaseResolved   Phase = "resolved"
)

// Severity orders alerts. Informational notifications are emitted for changes
// we recognize as legitimate but still want in the audit log.
type Severity int

const (
	SevNone Severity = iota
	SevInfo
	SevWarning
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevWarning:
		return "WARNING"
	case SevInfo:
		return "INFO"
	default:
		return "NONE"
	}
}

// ParseSeverity is the inverse of String.
func ParseSeverity(s string) Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return SevCritical
	case "WARNING":
		return SevWarning
	case "INFO":
		return SevInfo
	}
	return SevNone
}

// Signal is one piece of evidence behind an alert. Delta is the signed
// contribution to the score; contributions above zero raise severity, and
// negative ones discount (e.g. a matching ROA).
type Signal struct {
	Name  string `json:"name"`
	Delta int    `json:"delta"`
	Note  string `json:"note,omitempty"`
}

// Alert is what the service emits. One alert covers one incident (a prefix and
// a suspected origin/attacker) for its whole lifetime; later state changes
// come through as Phase transitions on the same ID.
type Alert struct {
	ID              string     `json:"id"`
	Kind            Kind       `json:"kind"`
	Phase           Phase      `json:"phase"`
	Severity        Severity   `json:"severity"`
	Prefix          Prefix     `json:"prefix"`
	OurPrefix       *Prefix    `json:"our_prefix,omitempty"`
	SuspectedOrigin ASN        `json:"suspected_origin,omitempty"`
	ObservedOrigins []ASN      `json:"observed_origins,omitempty"`
	VPs             []string   `json:"vps,omitempty"`
	VPRegions       []string   `json:"vp_regions,omitempty"`
	PathSamples     []string   `json:"path_samples,omitempty"`
	Score           int        `json:"score"`
	Signals         []Signal   `json:"signals,omitempty"`
	FirstSeen       time.Time  `json:"first_seen"`
	AlertedAt       time.Time  `json:"alerted_at"`
	LastSeen        time.Time  `json:"last_seen"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	// Visibility is the fraction of configured VPs currently reporting this
	// prefix at all; low values mean a blind spot rather than calm.
	Visibility float64 `json:"visibility"`
	// Coverage is the fraction of VPs that see the *anomalous* route, i.e. how
	// broadly the change is observed. One VP alone is weak evidence.
	Coverage float64 `json:"coverage"`
	Summary  string  `json:"summary"`
	// Reason names why a non-hostile alert was recognized as legitimate.
	Reason string `json:"reason,omitempty"`
	// DataQualityFlags note missing/late vantage points at alert time.
	DataQualityFlags []string `json:"data_quality_flags,omitempty"`
}

// Decision is the detector's verdict for one observation batch. It is what the
// engine returns to the caller so both the streaming service and the offline
// evaluator share one code path.
type Decision struct {
	// NewAlerts are alerts raised by this batch.
	NewAlerts []Alert
	// Updated are existing alerts whose phase/score changed.
	Updated []Alert
	// Suppressed counts suspicious observations folded into an existing alert
	// or explained away by an authorization/scrub agreement. Kept for the
	// metrics endpoint and the evaluator's noise accounting.
	Suppressed int
	// Ignored counts observations about prefixes we do not protect.
	Ignored int
}

// Label is the simulator's ground truth for one injected event. The detection
// engine never sees labels; the evaluator does.
type Label struct {
	ID          string    `json:"id"`
	Kind        Kind      `json:"kind"`
	Prefix      Prefix    `json:"prefix"`
	AttackerASN ASN       `json:"attacker_asn,omitempty"`
	Start       time.Time `json:"start"`
	End         time.Time `json:"end"`
	VPs         []string  `json:"vps,omitempty"`
	Description string    `json:"description"`
	// Benign labels describe legitimate operations that look suspicious but
	// must not raise a WARNING or worse. Used to measure false positives.
	Benign bool `json:"benign,omitempty"`
	// MustAlert means the evaluator counts a miss as an incident failure even
	// if the anomaly is subtle.
	MustAlert bool `json:"must_alert,omitempty"`
	// UndetectableFromBGP marks a scenario that is structurally indistinguishable
	// from a legitimate route given BGP data alone. These are reported as known
	// blind spots, not as misses: scoring them as failures would reward a
	// detector for guessing, which is worse than being honest about the limit.
	UndetectableFromBGP bool `json:"undetectable_from_bgp,omitempty"`
}

// Scenario is the on-disk bundle the simulator writes: an ordered feed plus
// the labels needed to score it.
type Scenario struct {
	Name         string        `json:"name"`
	Seed         int64         `json:"seed"`
	Start        time.Time     `json:"start"`
	End          time.Time     `json:"end"`
	Observations []Observation `json:"observations"`
	Labels       []Label       `json:"labels"`
}
