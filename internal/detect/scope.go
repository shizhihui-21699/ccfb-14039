package detect

import (
	"sync"
	"time"
)

// scopeTracker remembers, for each ASN that shows up as the penultimate hop of
// an announcement for one of *our* prefixes, which prefixes it fronts.
//
// The discriminator it provides is the single most useful one for the hard
// case of a path insertion by an expected origin: a legitimate transit change
// is a property of a provider, so the new upstream appears in front of many of
// our prefixes at once.  A hijacker who inserts a hop (or a forged path) only
// needs to steer one victim block, so the new upstream fronts exactly one.
type scopeTracker struct {
	mu    sync.Mutex
	byASN map[uint32]map[string]time.Time
}

func newScopeTracker() *scopeTracker {
	return &scopeTracker{byASN: map[uint32]map[string]time.Time{}}
}

func (s *scopeTracker) note(asn uint32, prefix string, now time.Time) {
	if asn == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.byASN[asn]
	if m == nil {
		m = map[string]time.Time{}
		s.byASN[asn] = m
	}
	if _, ok := m[prefix]; !ok {
		m[prefix] = now
	}
}

// scopeLive counts how many of our registered prefixes the ASN currently
// fronts, by inspecting the live per-collector RIB rather than remembered
// sightings.  This is the number that matters at finalisation time: if a new
// upstream appears in front of several prefixes, it is a provider re-homing;
// if exactly one, it is the shape of an insertion.
//
// It requires the ASN to be penultimate on the route so that an ASN seen
// mid-path for unrelated reasons is not counted.
func (s *scopeTracker) scopeLive(asn uint32, rib map[string]map[string]announcement, now time.Time, window time.Duration) int {
	prefixes := map[string]bool{}
	for _, cols := range rib {
		for pfx, a := range cols {
			if len(a.path) < 2 {
				continue
			}
			if a.path[len(a.path)-2] != asn {
				continue
			}
			if now.Sub(a.recvTime) > window {
				continue
			}
			prefixes[pfx] = true
		}
	}
	return len(prefixes)
}
