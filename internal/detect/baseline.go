package detect

import (
	"strconv"
	"strings"
	"sync"

	"hijackwatch/internal/model"
)

// edge is one adjacent AS pair of an observed AS_PATH.
type edge struct{ a, b uint32 }

// baseline learns what "normal" looks like for our address space.
//
// The most important property is that "normal" is per observation point and
// per prefix.  Different collectors legitimately reach us through different
// upstreams, so a global "have I seen this upstream for this prefix" test
// produces false positives during warm-up and after every collector restart.
// Instead we remember the penultimate ASN each collector has used for each
// prefix; a *change* for that (collector,prefix) pair is meaningful, a
// different value from a collector we have never heard from is not.
//
// It only learns from observations the detector judged benign, so an ongoing
// anomaly cannot poison the model.
type baseline struct {
	mu sync.RWMutex

	globalASN map[uint32]bool
	edgeCount map[edge]int
	pathCount map[string]int

	// upstream history keyed by collector|prefix.
	upstream map[string]map[uint32]int
	// last upstream per collector|prefix, so the detector can see a change.
	lastUpstream map[string]uint32
	// how many samples collected for each collector|prefix.
	pairSamples map[string]int

	peers   map[string]map[uint32]bool // collector -> peer ASNs seen
	samples int
}

func newBaseline() *baseline {
	return &baseline{
		globalASN:    map[uint32]bool{},
		edgeCount:    map[edge]int{},
		pathCount:    map[string]int{},
		upstream:     map[string]map[uint32]int{},
		lastUpstream: map[string]uint32{},
		pairSamples:  map[string]int{},
		peers:        map[string]map[uint32]bool{},
	}
}

func pathKey(path []uint32) string {
	var sb strings.Builder
	sb.Grow(len(path) * 6)
	for i, a := range path {
		if i > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(strconv.FormatUint(uint64(a), 10))
	}
	return sb.String()
}

func pairKey(collector, prefix string) string { return collector + "|" + prefix }

// observe records a path as normal for a given collector, prefix and origin.
func (b *baseline) observe(collector string, path []uint32, origin uint32, prefix string) {
	if len(path) == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.samples++
	b.pathCount[pathKey(path)]++
	for _, a := range path {
		b.globalASN[a] = true
	}
	for i := 0; i+1 < len(path); i++ {
		b.edgeCount[edge{path[i], path[i+1]}]++
	}
	if len(path) >= 2 {
		pen := path[len(path)-2]
		k := pairKey(collector, prefix)
		m := b.upstream[k]
		if m == nil {
			m = map[uint32]int{}
			b.upstream[k] = m
		}
		m[pen]++
		b.lastUpstream[k] = pen
		b.pairSamples[k]++
	}
}

func (b *baseline) edgeKnown(a, c uint32) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.edgeCount[edge{a, c}] > 0
}

func (b *baseline) pathKnown(path []uint32) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.pathCount[pathKey(path)] > 0
}

// isKnownASN reports whether the ASN has appeared anywhere in learned paths.
func (b *baseline) isKnownASN(asn uint32) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.globalASN[asn]
}

func (b *baseline) sampleCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.samples
}

// learnPeer records a collector/peer pairing as expected.
func (b *baseline) learnPeer(collector string, peer uint32) {
	if collector == "" || peer == 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	m := b.peers[collector]
	if m == nil {
		m = map[uint32]bool{}
		b.peers[collector] = m
	}
	m[peer] = true
}

func (b *baseline) peerKnown(collector string, peer uint32) bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.peers[collector][peer]
}

// minPairSamples is how many observations a (collector,prefix) pair needs
// before its upstream is considered stable enough to detect a *change*.
const minPairSamples = 3

// upstreamChange reports whether this path's penultimate ASN differs from what
// this collector has previously used for this prefix.  It returns the previous
// upstream (or 0) when there was one.
//
// A pair with no history, or too little history, is not a change: the first
// time we hear from a collector is not evidence of anything.
func (b *baseline) upstreamChange(collector, prefix string, path []uint32) (changed bool, prev uint32, known bool) {
	if len(path) < 2 {
		return false, 0, false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	k := pairKey(collector, prefix)
	if b.pairSamples[k] < minPairSamples {
		return false, 0, false
	}
	pen := path[len(path)-2]
	prev = b.lastUpstream[k]
	if prev == 0 || prev == pen {
		return false, prev, prev != 0
	}
	// Only a repeated, stable new upstream counts as a change, so a single
	// outlier path does not trip the check.
	if b.upstream[k][pen] == 0 {
		return true, prev, true
	}
	return false, prev, true
}

// minBaselineSamples is how much history we require before novelty verdicts
// are trustworthy.
const minBaselineSamples = 20

// noveltyCapped measures how structurally new a path is relative to the
// baseline.  The contribution is capped so that novelty alone — which every
// legitimate topology change produces — never reaches a paging severity.
func (b *baseline) noveltyCapped(path []uint32, origin uint32) (int, []model.Evidence) {
	if len(path) == 0 || b.sampleCount() < minBaselineSamples {
		return 0, nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()

	var (
		score int
		ev    []model.Evidence
	)
	novelEdges := 0
	for i := 0; i+1 < len(path); i++ {
		if b.edgeCount[edge{path[i], path[i+1]}] == 0 {
			novelEdges++
			if novelEdges <= 2 {
				score += weightNovelEdge
				ev = append(ev, model.Evidence{
					Code:   "path.novel_edge",
					Weight: weightNovelEdge,
					Detail: "AS" + strconv.FormatUint(uint64(path[i]), 10) + "->AS" +
						strconv.FormatUint(uint64(path[i+1]), 10) + " never observed before",
				})
			}
		}
	}
	if b.pathCount[pathKey(path)] == 0 {
		score += weightNovelPath
		ev = append(ev, model.Evidence{
			Code:   "path.novel_path",
			Weight: weightNovelPath,
			Detail: "full AS path never observed before",
		})
	}
	if score > noveltyCap {
		score = noveltyCap
	}
	return score, ev
}

// Tunable novelty weights.  Deliberately small: novelty alone is a weak
// signal because legitimate carrier switches and TE changes also create new
// paths.
const (
	weightNovelEdge = 6
	weightNovelPath = 4
	noveltyCap      = 16
)
