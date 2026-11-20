package registry

import (
	"testing"
	"time"

	"routewatch/internal/model"
)

func asns(t *testing.T, raw ...string) []model.ASN {
	t.Helper()
	out := make([]model.ASN, len(raw))
	for i, s := range raw {
		a, err := model.ParseASN(s)
		if err != nil {
			t.Fatalf("ParseASN(%q): %v", s, err)
		}
		out[i] = a
	}
	return out
}

func testRegistry(t *testing.T) *Registry {
	t.Helper()
	r := &Registry{
		SelfASN: 400001,
		OurPrefixes: []model.Prefix{
			model.MustPrefix("198.51.100.0/23"),
			model.MustPrefix("203.0.113.0/24"),
		},
		ASNs: []ASInfo{
			{ASN: 400001, Role: RoleSelf, Upstreams: asns(t, "AS3356", "AS1299")},
			{ASN: 400002, Role: RoleAnycast, AuthorizedFor: []model.Prefix{model.MustPrefix("203.0.113.0/24")}},
			{ASN: 400010, Role: RoleDownstream, Upstreams: asns(t, "AS400001"), NoTransit: true,
				AuthorizedFor: []model.Prefix{model.MustPrefix("198.51.101.0/24")}},
			{ASN: 400666, Role: RoleHosting, Upstreams: asns(t, "AS1299")},
			{ASN: 400777, Role: RoleUnknown, Upstreams: asns(t, "AS174"), NoTransit: true},
			{ASN: 400999, Role: RoleScrubber, Upstreams: asns(t, "AS1299", "AS3356")},
			{ASN: 3356, Role: RoleUpstream, Upstreams: asns(t, "AS174"), Downstreams: asns(t, "AS400001")},
			{ASN: 1299, Role: RoleUpstream, Upstreams: asns(t, "AS174"), Downstreams: asns(t, "AS400001", "AS400666")},
			{ASN: 174, Role: RoleUpstream, Downstreams: asns(t, "AS3356", "AS1299", "AS400777")},
			{ASN: 209, Role: RoleUpstream, Upstreams: asns(t, "AS174")},
		},
		ROAs: []ROA{
			{Prefix: model.MustPrefix("198.51.100.0/23"), MaxLen: 24, Origin: 400001},
		},
		Auths: []Authorization{
			{Prefix: model.MustPrefix("198.51.101.0/24"), Origin: 400010, Reason: "customer CDN"},
		},
		Scrubs: []ScrubAgreement{
			{Prefix: model.MustPrefix("198.51.100.0/23"), Scrubber: 400999, Reasons: []string{"64500:666"}},
		},
		Anycast: []AnycastOrigin{
			{Prefix: model.MustPrefix("203.0.113.0/24"), Origins: asns(t, "AS400001", "AS400002")},
		},
	}
	if err := r.Load(); err != nil {
		t.Fatalf("Load: %v", err)
	}
	return r
}

func TestPlausibilityPrependingIsNotLoop(t *testing.T) {
	r := testRegistry(t)
	// Prepend is traffic engineering, not a loop.
	issues := r.PlausibilityIssues(asns(t, "AS3356", "AS3356", "AS400001", "AS400001", "AS400001"), 400001)
	if len(issues) != 0 {
		t.Fatalf("prepending produced issues: %+v", issues)
	}
}

func TestPlausibilityStubInTransitIsHard(t *testing.T) {
	r := testRegistry(t)
	issues := r.PlausibilityIssues(asns(t, "AS3356", "AS400777", "AS400001"), 400001)
	if len(registryHard(issues)) != 1 {
		t.Fatalf("expected one hard issue for stub in transit, got %+v", issues)
	}
}

func TestPlausibilityRealLoopIsHard(t *testing.T) {
	r := testRegistry(t)
	issues := r.PlausibilityIssues(asns(t, "AS3356", "AS1299", "AS3356", "AS400001"), 400001)
	if len(registryHard(issues)) == 0 {
		t.Fatalf("expected a hard issue for a repeated ASN, got %+v", issues)
	}
}

func TestROA(t *testing.T) {
	r := testRegistry(t)
	cases := []struct {
		prefix string
		origin model.ASN
		want   ROAStatus
	}{
		{"198.51.100.0/23", 400001, ROAValid},
		{"198.51.100.0/24", 400001, ROAValid},   // within maxLength
		{"198.51.100.0/24", 400666, ROAInvalid}, // wrong origin
		{"198.51.100.0/25", 400001, ROAInvalid}, // too specific
		{"203.0.113.0/24", 400001, ROANone},     // no ROA
	}
	for _, c := range cases {
		got := r.ROA(model.MustPrefix(c.prefix), c.origin)
		if got != c.want {
			t.Errorf("ROA(%s, %s) = %v, want %v", c.prefix, c.origin, got, c.want)
		}
	}
}

func TestLegitOriginIsPrefixScoped(t *testing.T) {
	r := testRegistry(t)
	// The anycast sibling may originate the service /24...
	if !r.LegitOrigin(400002, model.MustPrefix("203.0.113.0/24")) {
		t.Error("anycast sibling should be legit for 203.0.113.0/24")
	}
	// ...but its authorization must not leak to other space.
	if r.LegitOrigin(400002, model.MustPrefix("198.51.100.0/24")) {
		t.Error("anycast sibling must not be legit for unrelated space")
	}
	// Our scrubber is only legitimate via an active session, never on
	// registration alone.
	if r.LegitOrigin(400999, model.MustPrefix("198.51.100.0/23")) {
		t.Error("scrubber must not be a blanket-legal origin")
	}
}

func TestAuthorizedWindow(t *testing.T) {
	r := testRegistry(t)
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	if _, ok := r.Authorized(400010, model.MustPrefix("198.51.101.0/24"), now); !ok {
		t.Fatal("customer /24 should be authorized")
	}
	if _, ok := r.Authorized(400010, model.MustPrefix("198.51.101.128/26"), now); ok {
		t.Fatal("more-specific than MaxLen must not be authorized")
	}
	if _, ok := r.Authorized(400666, model.MustPrefix("198.51.101.0/24"), now); ok {
		t.Fatal("wrong origin must not be authorized")
	}
}

func TestScrubAgreementNeedsWindowAndPrefix(t *testing.T) {
	r := testRegistry(t)
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	if _, ok := r.ScrubAgreementFor(400999, model.MustPrefix("198.51.100.0/23"), now); !ok {
		t.Fatal("scrub agreement should cover our /23")
	}
	if _, ok := r.ScrubAgreementFor(400999, model.MustPrefix("203.0.113.0/24"), now); ok {
		t.Fatal("scrub agreement must not cover prefixes outside its range")
	}
}

func registryHard(in []PathIssue) []PathIssue { return HardIssues(in) }
