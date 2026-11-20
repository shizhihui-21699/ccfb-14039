// Package registry holds the static facts the detector reasons against:
// which prefixes belong to us, which ASNs are legitimate origins or upstreams,
// which origins the RPKI/IRR actually authorize, and which announcement
// patterns are pre-approved (scrubbing centers, maintenance windows).
//
// Everything in here is "out of band" knowledge: it comes from the IRR/RPKI,
// from our own network inventory, and from the DDoS mitigation orchestration
// API. Keeping it separate from observed BGP data is what lets the detector
// tell "unexpected" apart from "unauthorized".
package registry

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"routewatch/internal/model"
)

// ASRole classifies an ASN in our topology.
type ASRole string

const (
	RoleSelf       ASRole = "self"       // our own ASN
	RoleUpstream   ASRole = "upstream"   // our own transits
	RoleScrubber   ASRole = "scrubber"   // DDoS scrubbing centers we divert into
	RoleDownstream ASRole = "downstream" // customers / CDN we legitimately announce for
	RoleHosting    ASRole = "hosting"    // hosting providers that may announce for us
	RolePeer       ASRole = "peer"       // settlement-free peers
	RoleAnycast    ASRole = "anycast"    // sibling PoP ASNs that originate the same prefix
	RoleUnknown    ASRole = "unknown"
)

// ASInfo describes one ASN.
type ASInfo struct {
	ASN  model.ASN `yaml:"asn" json:"asn"`
	Name string    `yaml:"name" json:"name"`
	Role ASRole    `yaml:"role" json:"role"`
	// Upstreams lists ASNs this ASN transits through, used to score whether a
	// path is plausible for our traffic.
	Upstreams []model.ASN `yaml:"upstreams" json:"upstreams,omitempty"`
	// Downstreams lists ASNs this ASN provides transit to, where known.
	Downstreams []model.ASN `yaml:"downstreams" json:"downstreams,omitempty"`
	// NoTransit marks a stub: a network with no customers. Real stub networks
	// never appear mid-path, so seeing one there means the path was forged.
	NoTransit bool `yaml:"no_transit" json:"no_transit,omitempty"`
	// PeerWith lists settlement-free peers where known, used only to score
	// adjacency plausibility.
	PeerWith []model.ASN `yaml:"peer_with" json:"peer_with,omitempty"`
	// AuthorizedFor lists prefixes this ASN may originate on our behalf. It
	// scopes a downstream/hosting role to specific space; a hosting provider
	// being allowed to originate one /24 does not license it everywhere.
	AuthorizedFor []model.Prefix `yaml:"authorized_for" json:"authorized_for,omitempty"`
}

// VPInfo is static metadata about a collector vantage point. Region is used to
// tell a locally-scoped anomaly from a globally coordinated one.
type VPInfo struct {
	Name   string    `yaml:"name" json:"name"`
	Region string    `yaml:"region" json:"region"`
	ASN    model.ASN `yaml:"asn" json:"asn"`
}

// ROA is a Route Origin Authorization.
type ROA struct {
	Prefix model.Prefix `yaml:"prefix" json:"prefix"`
	MaxLen int          `yaml:"max_length" json:"max_length"`
	Origin model.ASN    `yaml:"origin" json:"origin"`
}

// ROAStatus is the tri-state result of validating an announcement against RPKI.
// The "no covering ROA" case is deliberately not "invalid": unregistered space
// is common and treating it as invalid would drown us in noise.
type ROAStatus int

const (
	ROANone    ROAStatus = iota // no covering ROA: nothing to say
	ROAValid                    // a covering ROA authorizes this origin and length
	ROAInvalid                  // a covering ROA exists but origin or length is wrong
)

func (s ROAStatus) String() string {
	switch s {
	case ROAValid:
		return "valid"
	case ROAInvalid:
		return "invalid"
	default:
		return "none"
	}
}

// Authorization is a pre-approved announcement pattern: a customer prefix we
// aggregate, a maintenance window, a CDN that is allowed to originate our /24
// from its own ASNs.
type Authorization struct {
	Prefix model.Prefix `yaml:"prefix"`
	Origin model.ASN    `yaml:"origin"`
	// MaxLen is the most specific announcement allowed (e.g. 24 to permit
	// /24s inside an authorized /22). Zero means exactly Prefix.
	MaxLen int    `yaml:"max_length"`
	Start  string `yaml:"start,omitempty"` // RFC3339, empty = always
	End    string `yaml:"end,omitempty"`
	Reason string `yaml:"reason"`

	start, end time.Time
}

// ScrubAgreement is a contract with a scrubbing center: when we divert
// traffic, it will originate `Prefix` (or a more-specific) from its ASN.
// A real deployment would tighten this with a live session record from the
// mitigation API; see EngineConfig.ScrubState.
type ScrubAgreement struct {
	Prefix   model.Prefix `yaml:"prefix"`
	Scrubber model.ASN    `yaml:"scrubber"`
	Reasons  []string     `yaml:"communities,omitempty"` // communities that mark cleaning
	Start    string       `yaml:"start,omitempty"`
	End      string       `yaml:"end,omitempty"`

	start, end time.Time
}

func (s ScrubAgreement) active(t time.Time) bool {
	if s.start.IsZero() && s.end.IsZero() {
		return true
	}
	return !t.Before(s.start) && !t.After(s.end)
}

func (a Authorization) active(t time.Time) bool {
	if a.start.IsZero() && a.end.IsZero() {
		return true
	}
	return !t.Before(a.start) && !t.After(a.end)
}

// covers reports whether the agreement can explain an announcement of p by
// this scrubber.
func (s ScrubAgreement) covers(p model.Prefix) bool {
	return p.Bits() >= s.Prefix.Bits() && s.Prefix.Contains(model.MustPrefix(p.String()))
}

// Registry is the immutable set of facts the service is configured with.
type Registry struct {
	SelfASN     model.ASN        `yaml:"self_asn"`
	OrgName     string           `yaml:"org_name"`
	OurPrefixes []model.Prefix   `yaml:"monitored_prefixes"`
	ASNs        []ASInfo         `yaml:"asns"`
	VPs         []VPInfo         `yaml:"vantage_points"`
	ROAs        []ROA            `yaml:"roas"`
	Auths       []Authorization  `yaml:"authorizations"`
	Scrubs      []ScrubAgreement `yaml:"scrub_agreements"`
	// Anycast records prefixes where multiple origins are by design. The
	// engine must not read a second origin on these as a hijack, and must not
	// let the registration license unrelated origins.
	Anycast []AnycastOrigin `yaml:"anycast"`
	// MaxPlausiblePathLen bounds what we treat as a normal path length to us.
	MaxPlausiblePathLen int `yaml:"max_plausible_path_len"`

	asnByID  map[model.ASN]ASInfo
	vpByName map[string]VPInfo
	adjacent map[[2]model.ASN]bool
}

// Load resolves all derived tables. Call once after unmarshalling YAML.
func (r *Registry) Load() error {
	r.asnByID = make(map[model.ASN]ASInfo, len(r.ASNs))
	for _, a := range r.ASNs {
		if a.Role == "" {
			a.Role = RoleUnknown
		}
		r.asnByID[a.ASN] = a
	}
	r.vpByName = make(map[string]VPInfo, len(r.VPs))
	for _, v := range r.VPs {
		r.vpByName[v.Name] = v
	}
	for i := range r.Auths {
		var err error
		if r.Auths[i].start, err = parseWindow(r.Auths[i].Start); err != nil {
			return fmt.Errorf("authorization %s: %w", r.Auths[i].Prefix, err)
		}
		if r.Auths[i].end, err = parseWindow(r.Auths[i].End); err != nil {
			return fmt.Errorf("authorization %s: %w", r.Auths[i].Prefix, err)
		}
	}
	r.buildAdjacency()
	for i := range r.Scrubs {
		var err error
		if r.Scrubs[i].start, err = parseWindow(r.Scrubs[i].Start); err != nil {
			return fmt.Errorf("scrub agreement %s: %w", r.Scrubs[i].Prefix, err)
		}
		if r.Scrubs[i].end, err = parseWindow(r.Scrubs[i].End); err != nil {
			return fmt.Errorf("scrub agreement %s: %w", r.Scrubs[i].Prefix, err)
		}
	}
	return r.Validate()
}

func parseWindow(s string) (time.Time, error) {
	if strings.TrimSpace(s) == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, s)
}

// Validate checks internal consistency. Errors here are config bugs, so the
// service refuses to start rather than silently mis-scoring.
func (r *Registry) Validate() error {
	if r.SelfASN == 0 {
		return fmt.Errorf("registry: self ASN not set")
	}
	if len(r.OurPrefixes) == 0 {
		return fmt.Errorf("registry: no monitored prefixes")
	}
	if _, ok := r.asnByID[r.SelfASN]; !ok {
		return fmt.Errorf("registry: self ASN %s missing from AS table", r.SelfASN)
	}
	if r.MaxPlausiblePathLen == 0 {
		r.MaxPlausiblePathLen = 8
	}
	for _, p := range r.OurPrefixes {
		_ = p // prefixes already masked by the parser
	}
	return nil
}

// Lookup returns info for asn, with RoleUnknown when absent.
func (r *Registry) Lookup(asn model.ASN) ASInfo {
	if info, ok := r.asnByID[asn]; ok {
		return info
	}
	return ASInfo{ASN: asn, Role: RoleUnknown, Name: asn.String()}
}

// Known reports whether asn is in our tables at all.
func (r *Registry) Known(asn model.ASN) bool { _, ok := r.asnByID[asn]; return ok }

// Role returns the role of asn.
func (r *Registry) Role(asn model.ASN) ASRole { return r.Lookup(asn).Role }

// VPRegion returns the configured region for a VP, or "".
func (r *Registry) VPRegion(name string) string { return r.vpByName[name].Region }

// VPsConfigured returns the configured vantage point names.
func (r *Registry) VPsConfigured() []string {
	out := make([]string, 0, len(r.VPs))
	for _, v := range r.VPs {
		out = append(out, v.Name)
	}
	sort.Strings(out)
	return out
}

// AnycastOrigin registers the full set of origins allowed to announce a prefix
// for anycast reasons.
type AnycastOrigin struct {
	Prefix  model.Prefix `yaml:"prefix" json:"prefix"`
	Origins []model.ASN  `yaml:"origins" json:"origins"`
}

// IsAnycastOrigin reports whether asn may originate prefix as an anycast
// sibling.
func (r *Registry) IsAnycastOrigin(asn model.ASN, prefix model.Prefix) bool {
	for _, a := range r.Anycast {
		if !a.Prefix.Overlaps(prefix) {
			continue
		}
		for _, o := range a.Origins {
			if o == asn {
				return true
			}
		}
	}
	return false
}

// AuthorizedFor reports whether asn is registered to originate prefix.
func (r *Registry) AuthorizedFor(asn model.ASN, prefix model.Prefix) bool {
	info, ok := r.asnByID[asn]
	if !ok {
		return false
	}
	for _, p := range info.AuthorizedFor {
		if p.Overlaps(prefix) && prefix.Bits() >= p.Bits() {
			return true
		}
	}
	return false
}

// OurPrefix returns the most specific monitored prefix containing p, or nil.
func (r *Registry) OurPrefix(p model.Prefix) *model.Prefix {
	var best *model.Prefix
	for i := range r.OurPrefixes {
		ours := r.OurPrefixes[i]
		if ours.Contains(p) {
			if best == nil || ours.Bits() > best.Bits() {
				best = &r.OurPrefixes[i]
			}
		}
	}
	return best
}

// CoversOurs returns the monitored prefixes that p is *shorter than or equal
// to* and covers. Used to recognise a covering announcement.
func (r *Registry) CoversOurs(p model.Prefix) []model.Prefix {
	var out []model.Prefix
	for _, ours := range r.OurPrefixes {
		if p.Contains(ours) {
			out = append(out, ours)
		}
	}
	return out
}

// LegitOrigin reports whether asn may legitimately originate prefix, ignoring
// time windows (used for baseline learning, where we want the set of origins
// that are structurally ours).
func (r *Registry) LegitOrigin(asn model.ASN, prefix model.Prefix) bool {
	if asn == r.SelfASN {
		return true
	}
	if r.IsAnycastOrigin(asn, prefix) || r.AuthorizedFor(asn, prefix) {
		return true
	}
	for _, a := range r.Auths {
		if a.Origin == asn && a.Prefix.Overlaps(prefix) {
			return true
		}
	}
	// Scrubbing centers are deliberately absent: a scrubber is legitimate only
	// while a session is actually active and signalling, which the detector
	// checks against the agreement and communities. Being our scrubber does not
	// license a blanket announcement.
	return false
}

// LegitAdjacent returns the set of ASNs that may plausibly appear immediately
// before the origin in a path to us: our own upstreams and peers, and the
// upstreams of whoever is originating.
func (r *Registry) LegitAdjacent(origin model.ASN) map[model.ASN]bool {
	out := map[model.ASN]bool{}
	for _, u := range r.Lookup(r.SelfASN).Upstreams {
		out[u] = true
	}
	for asn, info := range r.asnByID {
		if info.Role == RolePeer || info.Role == RoleAnycast {
			out[asn] = true
		}
	}
	if info, ok := r.asnByID[origin]; ok && origin != r.SelfASN {
		out[origin] = true
		for _, u := range info.Upstreams {
			out[u] = true
		}
	}
	return out
}

// Authorized reports whether (origin, prefix) matches a live authorization.
func (r *Registry) Authorized(origin model.ASN, prefix model.Prefix, at time.Time) (Authorization, bool) {
	for _, a := range r.Auths {
		if a.Origin != origin || !a.active(at) {
			continue
		}
		if !a.Prefix.Overlaps(prefix) {
			continue
		}
		maxLen := a.MaxLen
		if maxLen == 0 {
			maxLen = a.Prefix.Bits()
		}
		if prefix.Bits() < a.Prefix.Bits() || prefix.Bits() > maxLen {
			continue
		}
		return a, true
	}
	return Authorization{}, false
}

// ScrubAgreementFor returns the agreement that would explain scrubber
// announcing prefix right now.
func (r *Registry) ScrubAgreementFor(scrubber model.ASN, prefix model.Prefix, at time.Time) (ScrubAgreement, bool) {
	for _, s := range r.Scrubs {
		if s.Scrubber != scrubber || !s.active(at) || !s.covers(prefix) {
			continue
		}
		return s, true
	}
	return ScrubAgreement{}, false
}

// ROA validates an announcement against RPKI ROAs.
func (r *Registry) ROA(prefix model.Prefix, origin model.ASN) ROAStatus {
	if len(r.ROAs) == 0 {
		return ROANone
	}
	covered := false
	for _, roa := range r.ROAs {
		if !roa.Prefix.Contains(prefix) {
			continue
		}
		covered = true
		maxLen := roa.MaxLen
		if maxLen == 0 {
			maxLen = roa.Prefix.Bits()
		}
		if roa.Origin == origin && prefix.Bits() <= maxLen {
			return ROAValid
		}
	}
	if covered {
		return ROAInvalid
	}
	return ROANone
}

// ExplainPath renders a path with each ASN's role, for alert text.
func (r *Registry) ExplainPath(path []model.ASN) string {
	parts := make([]string, 0, len(path))
	for _, a := range path {
		parts = append(parts, fmt.Sprintf("%s(%s)", a, r.Role(a)))
	}
	return strings.Join(parts, " > ")
}

// PathIssue is one reason a path is implausible. Codes are stable strings so
// the detector can attach weights to them.
type PathIssue struct {
	Code   string
	Detail string
	// Hard issues make the path structurally impossible. Soft issues are only
	// suspicious given incomplete public data, so they must never be the sole
	// reason for a page.
	Hard bool
}

const (
	// IssuePathLoop: the same ASN appears twice. BGP paths do not loop, so the
	// path was fabricated or corrupted.
	IssuePathLoop = "path_loop"
	// IssueStubInTransit: an AS registered as a stub (no customers) appears with
	// traffic passing through it. Stub networks do not transit; their presence
	// mid-path is proof of fabrication.
	IssueStubInTransit = "stub_in_transit"
	// IssueOriginNotTerminal: the origin ASN is not the last element.
	IssueOriginNotTerminal = "origin_not_terminal"
	// IssueUnknownAdjacency: two known ASNs have no registered relationship.
	// Weak: public AS graphs are always incomplete.
	IssueUnknownAdjacency = "unknown_adjacency"
	// IssueUnknownASNInTransit: an ASN we have never heard of sits mid-path.
	IssueUnknownASNInTransit = "unknown_asn_in_transit"
	// IssueTooLong: path longer than MaxPlausiblePathLen.
	IssueTooLong = "path_too_long"
)

// PlausibilityIssues examines a path and returns every structural problem,
// flagging each as hard (impossible) or soft (unusual).
//
// Prepending is removed before analysis: a path that ends "X X X" is a single
// hop X plus traffic engineering, not a loop. Treating prepending as a loop is
// the classic false positive against real BGP data.
func (r *Registry) PlausibilityIssues(path []model.ASN, origin model.ASN) []PathIssue {
	var issues []PathIssue
	clean := NormalizePath(path)
	seen := map[model.ASN]bool{}
	for _, a := range clean {
		if seen[a] {
			issues = append(issues, PathIssue{IssuePathLoop, fmt.Sprintf("%s repeats", a), true})
			break
		}
		seen[a] = true
	}
	if len(clean) > 0 && clean[len(clean)-1] != origin {
		issues = append(issues, PathIssue{IssueOriginNotTerminal,
			fmt.Sprintf("path ends at %s, origin is %s", clean[len(clean)-1], origin), true})
	}
	if r.MaxPlausiblePathLen > 0 && len(clean) > r.MaxPlausiblePathLen {
		issues = append(issues, PathIssue{IssueTooLong,
			fmt.Sprintf("%d ASes, expected <= %d", len(clean), r.MaxPlausiblePathLen), false})
	}
	// Only internal hops can be "in transit". The origin and the AS attached to
	// it are end-points, and the leftmost hop is a collector-side start.
	for i := 1; i < len(clean)-1; i++ {
		mid := r.Lookup(clean[i])
		if mid.NoTransit {
			issues = append(issues, PathIssue{IssueStubInTransit,
				fmt.Sprintf("%s (%s) is a stub but has traffic passing through", clean[i], mid.Name), true})
		} else if !r.Known(clean[i]) {
			issues = append(issues, PathIssue{IssueUnknownASNInTransit,
				fmt.Sprintf("%s is not in any public AS table", clean[i]), false})
		}
	}
	for i := 0; i+1 < len(clean); i++ {
		up, down := clean[i], clean[i+1]
		if r.knownAdjacent(up, down) {
			continue
		}
		if !r.Known(up) || !r.Known(down) {
			// We have no data on one side; absence of evidence is not evidence.
			continue
		}
		issues = append(issues, PathIssue{IssueUnknownAdjacency,
			fmt.Sprintf("%s and %s are not known to be connected", up, down), false})
	}
	return issues
}

// NormalizePath collapses consecutive repeats of the same ASN, which is what
// prepending produces. The result is the logical path.
func NormalizePath(path []model.ASN) []model.ASN {
	out := make([]model.ASN, 0, len(path))
	for _, a := range path {
		if n := len(out); n > 0 && out[n-1] == a {
			continue
		}
		out = append(out, a)
	}
	return out
}

// knownAdjacent reports whether up and down are known to exchange routes.
func (r *Registry) knownAdjacent(up, down model.ASN) bool {
	if up == down {
		return true
	}
	_, ok := r.adjacent[[2]model.ASN{up, down}]
	return ok
}

// buildAdjacency turns the directed fields into a symmetric adjacency set.
func (r *Registry) buildAdjacency() {
	r.adjacent = map[[2]model.ASN]bool{}
	add := func(a, b model.ASN) {
		r.adjacent[[2]model.ASN{a, b}] = true
		r.adjacent[[2]model.ASN{b, a}] = true
	}
	for _, info := range r.ASNs {
		for _, u := range info.Upstreams {
			add(info.ASN, u)
		}
		for _, d := range info.Downstreams {
			add(info.ASN, d)
		}
		for _, p := range info.PeerWith {
			add(info.ASN, p)
		}
	}
}

// HardIssues filters to structurally impossible problems.
func HardIssues(in []PathIssue) []PathIssue {
	var out []PathIssue
	for _, i := range in {
		if i.Hard {
			out = append(out, i)
		}
	}
	return out
}

// IsTransitCapable reports whether asn plausibly sells transit: it has
// downstreams or upstreams in our tables, or is explicitly a transit role. An
// eyeball/stub network cannot legitimately appear as the upstream of our
// origin.
func (r *Registry) IsTransitCapable(asn model.ASN) bool {
	info, ok := r.asnByID[asn]
	if !ok {
		return false
	}
	switch info.Role {
	case RoleUpstream, RolePeer, RoleAnycast, RoleScrubber, RoleHosting:
		return true
	}
	return len(info.Downstreams) > 0 || len(info.Upstreams) > 1
}

// PlausibleAdjacent reports whether adjacent is an acceptable AS to attach
// directly to origin.
func (r *Registry) PlausibleAdjacent(origin, adjacent model.ASN) bool {
	if adjacent == 0 {
		return false
	}
	return r.LegitAdjacent(origin)[adjacent]
}

// AdjacentRole describes the AS immediately before origin.
func (r *Registry) AdjacentRole(origin model.ASN, adjacent model.ASN) ASRole {
	if adjacent == 0 {
		return RoleUnknown
	}
	if r.LegitAdjacent(origin)[adjacent] {
		if role := r.Role(adjacent); role != RoleUnknown {
			return role
		}
		return RoleUpstream
	}
	return RoleUnknown
}

// IsScrubber reports whether asn is one of the scrubbing centers.
func (r *Registry) IsScrubber(asn model.ASN) bool { return r.Role(asn) == RoleScrubber }

// VPLatencyHint gives the collection latency characteristic of a collector,
// derived deterministically from its name so the simulator and the evaluator
// agree without extra config. Collectors in far regions tend to batch and
// export less often.
func (r *Registry) VPLatencyHint(vp string) time.Duration {
	h := uint32(2166136261)
	for i := 0; i < len(vp); i++ {
		h ^= uint32(vp[i])
		h *= 16777619
	}
	// 8s..68s, in 4s steps, skewed by region.
	base := time.Duration(8+(h%16)*4) * time.Second
	switch r.VPRegion(vp) {
	case "apac-sg", "apac-jp", "apac-hk", "apac-in", "apac-kr":
		base += 20 * time.Second
	case "latam", "africa":
		base += 30 * time.Second
	}
	return base
}

// VPNames returns vantage point names in stable order.
func (r *Registry) VPNames() []string { return r.VPsConfigured() }
