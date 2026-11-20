// Package sim synthesises a believable multi-vantage-point BGP world: a stable
// baseline of announcements and withdrawals, ordinary operational churn, and
// injected events whose labels are recorded separately from the feed. The
// detector never sees a label; the evaluator matches alerts to labels after the
// fact.
//
// The interesting part of this package is the normal traffic. A detector tuned
// only against injected attacks is easy; the hard part is that real routing
// looks like attacks all day long:
//
//   - anycast/CDN: the same prefix originated from several ASNs at once
//   - prepending: the same route, longer, from some vantage points
//   - AS path changes when a carrier re-routes around a maintenance
//   - transit switches: our own upstream changes for days
//   - withdrawals and reannouncements (flaps) during maintenance
//   - collection gaps: a collector goes silent, then floods us with a backlog
//   - latency: every collector reports the same change minutes apart
//
// The simulator produces all of these from a seed, with the injected attacks
// hidden among them.
package sim

import (
	"math/rand"
	"time"

	"routewatch/internal/model"
	"routewatch/internal/registry"
)

// EventKind describes a scripted injected event.
type EventKind string

const (
	EvOriginHijack  EventKind = "origin_hijack" // foreign origin on our exact prefix
	EvSubPrefix     EventKind = "subprefix_hijack"
	EvCovering      EventKind = "covering_hijack"
	EvPathHijack    EventKind = "path_hijack"    // forged path pulling traffic elsewhere
	EvTransitSwitch EventKind = "transit_switch" // benign, our upstream changes globally
	EvReRoute       EventKind = "re_route"       // benign, one carrier re-routes a region
	EvScrub         EventKind = "scrub_session"  // benign, diverts to a scrubbing center
	EvMaintenance   EventKind = "maintenance"    // benign, flaps during an announced window
	EvAnycastJoin   EventKind = "anycast_join"   // benign, a CDN sibling originates too
)

// World holds the simulated topology the generator draws from.
type World struct {
	Reg *registry.Registry
	Rng *rand.Rand
	// our anycast siblings and downstreams by prefix.
	siblings map[model.Prefix][]model.ASN
	// carrier pools per VP region, used for baseline paths.
	pathPool map[string][][]model.ASN
}

// rate models how fast a change reaches each collector: some VPs see it almost
// at once, others are minutes behind. It is the collection latency of a real
// RouteViews-style collector, not network convergence.
func (w *World) latency(vp string) time.Duration {
	h := w.Reg.VPLatencyHint(vp)
	return h
}

// BuildWorld constructs a World from the registry, precomputing the paths each
// region's collectors will use.
func BuildWorld(reg *registry.Registry, seed int64) *World {
	w := &World{Reg: reg, Rng: rand.New(rand.NewSource(seed))}
	w.siblings = map[model.Prefix][]model.ASN{}
	w.pathPool = map[string][][]model.ASN{}
	self := reg.Lookup(reg.SelfASN)
	for _, vp := range reg.VPs {
		if _, ok := w.pathPool[vp.Region]; ok {
			continue
		}
		var pool [][]model.ASN
		for _, up := range self.Upstreams {
			info := reg.Lookup(up)
			if len(info.Upstreams) == 0 {
				pool = append(pool, []model.ASN{up, reg.SelfASN})
				continue
			}
			for _, top := range info.Upstreams {
				pool = append(pool, []model.ASN{top, up, reg.SelfASN})
			}
		}
		if len(pool) == 0 {
			pool = [][]model.ASN{{reg.SelfASN}}
		}
		w.pathPool[vp.Region] = pool
	}
	return w
}
