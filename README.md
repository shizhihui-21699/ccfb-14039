# hijackwatch

A BGP route-hijack monitor for a small set of organisation-owned prefixes,
driven by a multi-vantage update stream. It answers one question — *has someone
started steering traffic for one of our blocks?* — while staying quiet through
the legitimate operations that look almost the same:

- a carrier switching upstream (a new path for **all** our prefixes at once),
- the same block announced from many sites simultaneously (anycast),
- temporary more-specifics injected by a scrubbing centre during a DDoS,
- our own traffic engineering,
- route flaps, collector restarts and late/duplicate/lost updates.

Everything here runs offline: the BGP data is simulated (fictional AS numbers,
documentation prefixes). `hijackwatch eval` replays that data through the
detector and scores the result against built-in ground truth.

## Quick start

```sh
go run ./cmd/hijackwatch sim  -out testdata/dataset.json   # generate 36h of data
go run ./cmd/hijackwatch eval -data testdata/dataset.json  # replay + score
go run ./cmd/hijackwatch eval -data testdata/dataset.json -v  # list every alert
go run ./cmd/hijackwatch serve -data testdata/dataset.json -addr :8080
#   -> open http://localhost:8080
go test ./...
```

Expected `eval` output on the default dataset:

```
TP=6 FP=0 FN=0 TN=7 median=7s p95=10s
```

That is: all six attack scenarios detected (median ~7s to alert), and none of
the seven benign scenarios paged. The one deliberately ambiguous benign event
(a genuine new peering for a single prefix) may reach Medium for review but is
reported separately and does not count as a false positive.

## How it decides

The hard part is that the attack shapes and the legitimate operations are
identical in a *single* update. A more-specific announced by an unknown AS is a
hijack — unless it is an approved scrubber. A path whose upstream changed is a
hijack — unless a carrier switched upstream for every prefix. So the detector
never decides on one update. It accumulates **evidence** for a
`(prefix, origin)` incident across collectors and a corroboration window, then
applies scope and policy.

### Evidence

| code | meaning | kind |
|------|---------|------|
| `origin.unexpected` | exact/more-specific announced by an unexpected origin | **hard** |
| `path.absurd` | impossible path (too long, origin mid-path, tight cycle) | **hard** |
| `prefix.more_specific` | unexpected more-specific of our block | strong |
| `path.new_peer` | a peer this collector has never reported; strong if it fronts a more-specific with our own origin (forged path) | weak/strong |
| `path.upstream_replaced_narrow` | a **never-seen** upstream replaced this collector's upstream for a prefix that no other of our prefixes uses | strong |
| `path.upstream_replaced_wide` | the new upstream fronts several of our prefixes → carrier re-homing | **mitigation** |
| `path.prepended_loop` | an unknown AS prepended ≥4× | strong |
| `path.suspicious_asn` | private/reserved/known-bad ASN in path | weak |
| `path.novel_edge` / `novel_path` | structural novelty vs. the learned baseline (capped at 16) | weak |
| `corroboration.*` | multiple observation points agree | bonus |
| `prefix.approved_cleanup` | more-specific from an approved scrubber | **mitigation** |
| `policy.known_incident` | matches an operator-registered change window | **mitigation** |

### The two discriminators that do the heavy lifting

1. **Origin correctness** is the only thing conclusive from one update. A wrong
   origin on our exact prefix is hard evidence; a correct origin is not
   exculpatory (attackers forge paths).

2. **Scope.** For a path anomaly where the origin is legitimately ours (the
   classic stealth insertion), the discriminator is *how many of our prefixes
   the new upstream fronts*. A provider serves several blocks; a hijacker needs
   to steer one victim. This is measured against the live multi-collector RIB at
   finalisation time, so it sees every collector's view, not just the first one
   to report.

### The baseline is per observation point, per prefix

"Normal" is learned as: which upstream each collector uses for each prefix, and
which path edges exist. A *change* for a `(collector, prefix)` pair is
meaningful; a different upstream from a collector we have never heard from is
not. A global "have I seen this upstream for this prefix" test produces false
positives during warm-up and after every collector restart — that bug is why the
baseline is keyed this way.

### Timing

Updates are judged with an explicit clock driven by `ReceivedAt`, so late and
out-of-order updates are handled the same way live and offline:

- **corroboration window** (`neighbor_rtt`, default 90s): a candidate is not
  finalised until the window closes or enough collectors agree, so a single
  collector's flap or a dropped duplicate cannot page.
- **auto-resolve** (`resolution_window`): an alert resolves once no observation
  point still holds the anomalous route for that long.

### Severity caps (the false-positive guard rails)

- a single observation point never pages above **High**, and soft signals from a
  single point cap at **Low**;
- an approved scrubbing more-specific caps at **Low** unless hard evidence also
  fires;
- `min_severity` (default `medium`) discards anything below the paging bar
  entirely, so the alert queue only holds what an operator would act on.

## Data model

The simulator (`internal/sim`) keeps a per-`(collector, prefix)` timeline of
stable path *segments* and re-emits the current one periodically. That models a
collector's table honestly: a stable route does not flicker back to a stale path
while a scenario is in progress. Collectors have different upstreams, observation
lag, jitter and drop rates; one is a deliberately laggy, lossy feeder.

Scenarios (all in one 36h dataset):

| id | kind | expected |
|----|------|----------|
| `atk-bogus-origin` | exact /24 by rogue AS | critical |
| `atk-subprefix` | /25 hijack spreading over 11 min, one lagging collector | critical |
| `atk-path-insertion` | rogue AS inserted as penultimate hop, one prefix, 4 collectors | high |
| `atk-forged-path` | /26 with our origin forged, unseen peer | high |
| `atk-single-collector` | bogus origin visible from one vantage only | high (capped) |
| `atk-covering-aggregate` | rogue /16 covering our /24 | critical |
| `benign-carrier-switch` | upstream change for all prefixes | no page |
| `benign-multisite` | same block from 8 sites at once | no page |
| `benign-scrubbing` | approved scrubber more-specific | no page |
| `benign-te-morespecific` | our own TE more-specific | no page |
| `benign-flap` | announce/withdraw every 30s | no page |
| `benign-new-peering` | genuinely new upstream, one prefix | ambiguous (may be Medium) |
| `benign-collector-outage` | collector offline, full-table recovery | no page |
| `benign-known-migration` | operator-registered change window | no page |

## HTTP API

| method | path | purpose |
|--------|------|---------|
| POST | `/v1/updates` | ingest one update (JSON `model.Update`), validated |
| POST | `/v1/updates/batch` | ingest an array; returns accepted/rejected counts |
| GET | `/v1/alerts?status=&min_severity=&limit=` | list alerts |
| GET | `/v1/alerts/{id}` | one alert with evidence and timeline |
| GET | `/v1/incidents` | ground truth (in replay mode) |
| GET | `/v1/stats` | counters + detector clock |
| GET | `/metrics` | Prometheus text metrics |
| GET | `/` | server-rendered dashboard |

## Configuration

See `config.example.yaml`. The only thing the detector truly needs is your
prefix list and expected origins. Tune `approved_cleanings`, `known_incidents`,
`min_severity` and the score thresholds against your own `eval` runs.

## Layout

```
cmd/hijackwatch        CLI: sim / eval / serve
internal/model         wire types, prefix relations, ASN classes, severity
internal/policy        config, prefix registry, scoring weights
internal/detect        the detector: scoring, baseline, scope, alert lifecycle
internal/sim           synthetic multi-vantage data + ground truth
internal/replay        replay a dataset and score it against truth
internal/api           HTTP API, metrics, dashboard
```

## Known limitations

- The baseline is in-memory and unbounded by time. In production it would be
  persisted and windowed; the detector treats it as a "have I seen this"
  oracle so that swap is local to `internal/detect/baseline.go`.
- RPKI/ROA and IRR cross-checks would make `origin.unexpected` far more precise.
  They are deliberately out of scope here (no external data), but the evidence
  model already has the slot: a ROA-invalid origin would be a second hard signal.
- The simulated topology is small (8 collectors, 3 prefixes). The logic does not
  depend on that size, but thresholds would want re-tuning on real volume.
