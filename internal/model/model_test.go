package model

import (
	"net/netip"
	"testing"
	"time"
)

func TestRelate(t *testing.T) {
	web := netip.MustParsePrefix("203.0.113.0/24")
	cases := []struct {
		p    string
		want Relation
	}{
		{"203.0.113.0/24", Exact},
		{"203.0.113.0/25", MoreSpecific},
		{"203.0.113.128/25", MoreSpecific},
		{"203.0.0.0/16", LessSpecific},
		{"203.1.113.0/24", Unrelated},
		{"198.51.100.0/24", Unrelated},
		{"2001:db8::/32", Unrelated},
	}
	for _, c := range cases {
		got := Relate(web, netip.MustParsePrefix(c.p))
		if got != c.want {
			t.Errorf("Relate(web, %s) = %s, want %s", c.p, got, c.want)
		}
	}
}

func TestOrigin(t *testing.T) {
	u := Update{ASPath: []uint32{65001, 129000, 0, 133900}}
	if o, ok := u.Origin(); !ok || o != 133900 {
		t.Errorf("Origin = %d,%v want 133900,true", o, ok)
	}
	u = Update{ASPath: []uint32{0, 0}}
	if _, ok := u.Origin(); ok {
		t.Error("Origin of all-zero path should not be ok")
	}
}

func TestClassifyASN(t *testing.T) {
	cases := map[uint32]ASNClass{
		133900: ASNPublic,
		64512:  ASNPrivate,
		23456:  ASNAsTrans,
		0:      ASNReserved,
		65535:  ASNReserved,
		64496:  ASNDoc,
	}
	for asn, want := range cases {
		if got := ClassifyASN(asn); got != want {
			t.Errorf("ClassifyASN(%d) = %s, want %s", asn, got, want)
		}
	}
	if !IsSuspiciousASN(64512) || IsSuspiciousASN(133900) {
		t.Error("IsSuspiciousASN misclassified")
	}
}

func TestValidate(t *testing.T) {
	now := time.Now().UTC()
	good := Update{
		Collector: "c1", Type: Announce, Prefix: "203.0.113.0/24",
		ASPath: []uint32{65001, 133900}, EventTime: now, ReceivedAt: now,
	}
	if err := good.Validate(now); err != nil {
		t.Errorf("good update rejected: %v", err)
	}

	bad := []Update{
		{Type: Announce, Prefix: "203.0.113.0/24", ASPath: []uint32{1}, EventTime: now, ReceivedAt: now},                                   // no collector
		{Collector: "c", Type: "bogus", Prefix: "203.0.113.0/24", EventTime: now, ReceivedAt: now},                                         // bad type
		{Collector: "c", Type: Announce, Prefix: "x", ASPath: []uint32{1}, EventTime: now, ReceivedAt: now},                                // bad prefix
		{Collector: "c", Type: Announce, Prefix: "203.0.113.0/24", EventTime: now, ReceivedAt: now},                                        // no path
		{Collector: "c", Type: Announce, Prefix: "203.0.113.0/24", ASPath: []uint32{1}},                                                    // no times
		{Collector: "c", Type: Announce, Prefix: "203.0.113.0/24", ASPath: []uint32{1}, EventTime: now, ReceivedAt: now.Add(-time.Minute)}, // recv before event
	}
	for i, u := range bad {
		if err := u.Validate(now); err == nil {
			t.Errorf("bad update %d accepted", i)
		}
	}
}

func TestParseSeverity(t *testing.T) {
	for _, s := range []string{"info", "low", "medium", "high", "critical", "CRITICAL"} {
		if _, err := ParseSeverity(s); err != nil {
			t.Errorf("ParseSeverity(%q) error: %v", s, err)
		}
	}
	if _, err := ParseSeverity("nonsense"); err == nil {
		t.Error("ParseSeverity accepted nonsense")
	}
}
