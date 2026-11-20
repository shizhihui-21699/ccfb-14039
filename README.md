# RouteWatch — multi-vantage-point BGP hijack detection

RouteWatch watches our public address space from a fleet of BGP collectors and
raises an alert when it looks like someone else is attracting our traffic. It is
built around one uncomfortable fact: **almost every hijack signature is also a
legitimate operation.** A scrubbing center announces our prefix from its own
ASN. A carrier maintenance moves our whole path to a new upstream in ten
minutes. A CDN sibling originates our service /24 from another ASN. A customer
flaps their /24 eight times during a maintenance window. A hijack looks like all
of these.

The service is therefore not a pattern matcher. It is a scoring engine that
weighs positive evidence, structural impossibility, scope and persistence, and
it is explicit about what it cannot know.

```
go run ./cmd/routewatch validate -config config/topology.yaml
go run ./cmd/routewatch generate -config config/topology.yaml -out scenario.json
go run ./cmd/routewatch replay   -config config/topology.yaml -scenario scenario.json
go run ./cmd/routewatch serve    -config config/topology.yaml -scenario scenario.json
```

The default configuration and simulated scenario produce:

```
detection    7/7 hostile events (100%), median TTD 1m10s, p90 TTD 45m2s
precision    0 false positive(s); precision on WARNING+ 1.00
benign       5 legitimate operations, 0 raised WARNING+ (specificity 1.00)
```

with one event deliberately reported as a **blind spot** rather than a miss
(see *What this cannot do*, below).

---

## How a decision is made

Observations arrive per collector, with their own latency and their own gaps.
The engine keeps each collector's newest route per prefix plus a liveness
timestamp, and every 30 seconds evaluates every prefix that is ours, covers
ours, or sits inside ours. Each candidate announcement is asked four questions,
in order:

### 1. Is it legitimate? (checked before anything else)

Some announcements are *expected*, and the only way to know is out-of-band
configuration: IRR/RPKI objects, customer authorizations, anycast registrations,
and the live DDoS-mitigation API. A match produces an **INFO audit entry**, never
a page. The distinction that matters: an authorization is scoped to a *prefix
and an ASN*. Our anycast sibling may originate `203.0.113.0/24`; the same ASN
announcing `198.51.100.0/24` is a hijack. A scrubber is legitimate only while a
session is actually active **and** the announcement carries the agreed cleaning
community — a scrubber ASN appearing without it is exactly the "looks
legitimate" case we must not wave through.

### 2. Is the route possible? (structural reasoning)

This is the defence against a forged path that uses real ASNs. A forgery still
has to respect which ASNs actually connect to which. The engine checks:

- **Prepending is removed first.** `X X X` at the tail is one hop plus traffic
  engineering, not a loop. Treating it as a loop is the classic false positive.
- **Loops** (a real repeat after normalization) — impossible in BGP.
- **Stub in transit** — a network registered with no customers appearing
  mid-path. Stubs never transit; their presence is proof of fabrication.
- **Unknown adjacency** — two *known* ASNs with no registered relationship.
  This is a *soft* signal, because public AS graphs are always incomplete;
  absence of evidence is not evidence.
- **Path attached through a non-upstream.** Our own announcement reaching a
  collector through a carrier we do not buy transit from is not a re-route.
- **Novelty** — a path never observed for this prefix. Weak on its own (carriers
  re-route constantly) but decisive in combination.

Structurally impossible paths are **hard** evidence and page immediately.
Soft path signals require the corroboration below.

### 3. What is its scope? (and why it must wait)

A fleet-wide change is a transit switch; a change confined to a minority is the
shape of selective interception. But scope is **unobservable in the first
minutes**: a global re-route races across collectors and initially looks like it
is hitting two of them. So the engine refuses to judge scope until a
`propagation_grace` (20 minutes) has passed, and it will not escalate a path
anomaly whose only evidence is an unexpected adjacent ASN until scope has
settled. This one rule eliminated the largest class of false positives in
development.

### 4. How sure can we be? (corroboration, persistence, blindness)

- **Corroboration.** Independent collectors agreeing is the main defence
  against one collector's bad data.
- **Persistence.** One odd evaluation window is a glitch; two in a row is news.
- **Single-collector evidence** must persist for `single_vp_min_age` (45
  minutes) before it may page at all. A collector can be wrong — a stale
  session, a misconfiguration — in ways two cannot. This is expressed as a
  *duration*, not a window count, so lowering the evaluation interval cannot
  silently weaken it.
- **Visibility** is measured against the **configured** fleet, not the live one.
  A fleet that has gone silent is 0 of 16, not "perfectly visible". Without
  this, an outage reads as "the hijack went away" and resolves every open
  incident.

Points combine additively into a score. The score sets severity, but a score
never pages on its own: the anomaly must also survive the persistence and
corroboration gates.

### Severity

| | CRITICAL | WARNING | INFO |
|---|---|---|---|
| Origin hijack / covering prefix | foreign origin, ≥2 collectors | — | if authorized |
| Sub-prefix hijack | score ≥ threshold, ≥2 collectors | else | — |
| Path hijack | structurally impossible, or settled-regional with high score | plausible path, ambiguous scope | — |
| Transit switch / scrub / flap | — | — | always |

Origin-class hijacks rest on **positive evidence**: independent collectors
reporting an impossible fact. Broad visibility does not make them more damning,
so a blind fleet does not downgrade them. Path anomalies rest on **absence**
("nobody else sees this path"), which a blind fleet also produces, so those *are*
downgraded when visibility is poor.

---

## Alerts are a story, not a stream

Each incident has a stable ID for its lifetime and moves through
`raised → escalated → downgraded → resolved`. Two genuinely separate attacks of
the same kind on the same prefix get different IDs, so a downstream deduplicator
cannot swallow the second. Every alert carries its evidence (`signals` with
signed contributions that sum to the score), the collector set, the regions, the
path samples, visibility, coverage, and data-quality flags such as
`reduced_visibility`, `scope_unsettled`, or `2_vps_with_high_collection_delay`.
An operator can see *why* it fired.

---

## The simulator

`internal/sim` synthesises a believable 36-hour multi-collector feed from a
seed. The interesting part is the **normal traffic**, because that is what makes
the detector hard:

- baseline announcements per collector with per-region upstreams;
- ordinary path churn (configurable rate) that never stops;
- prepending at ~30% of views;
- per-collector delivery latency (8s–98s) and phase offsets, so no two
  collectors see a change at the same instant;
- **data gaps**: views go silent for 5–40 minutes and replay a backlog on
  recovery, so a detector that reads silence as "no change" breaks;
- withdrawals when routes disappear, so recovery is observable.

Injected events, each labelled with ground truth the detector never sees:

| ID | What it is | Why it is hard |
|---|---|---|
| `hijack-origin-legacy` | foreign origin on a /24 with **no ROA** | only the authorization check can catch it |
| `hijack-brief-origin` | 25-minute origin hijack | must page fast; waiting for long persistence misses it |
| `hijack-subprefix-apac` | /24 carved from our /23, **4 APAC collectors only** | a global-scope heuristic misses it entirely |
| `hijack-covering` | /22 that swallows our /23 | shorter-than-ours is worse than exact match |
| `hijack-forged-path` | our origin, path through a **stub network** | origin and ROA are perfect; only connectivity reasoning exposes it |
| `hijack-subtle-path` | real carrier we do not buy from, 3 collectors | plausible except for attachment point |
| `hijack-single-vp` | one collector only | a collector can be wrong; must hold and check persistence |
| `hijack-plausible-path` | `AS3356 → us`, a **registered adjacency** | see below |
| `benign-scrub` | scrubber announces our /23 with cleaning community | indistinguishable from a foreign-origin hijack without the community |
| `benign-transit-switch` | **every** collector changes upstream for a day | looks exactly like a path hijack |
| `benign-anycast` | registered sibling originates the service /24 | second origin by design |
| `benign-maintenance` | 8 withdraw/reannounce cycles in 11 minutes | bursty churn |
| `benign-reroute-eu` | fibre cut changes the path at EU collectors only | regional scope + plausible path |

The evaluator scores detection rate, time-to-detect, false positives, and
whether any benign operation raised WARNING+, and it is careful about its own
semantics: hostile labels are matched **before** benign ones (so a real attack
during a maintenance window is a detection, not a "violation"), detection latency
is credited, and repeat alerts for an already-detected attack are counted as
noise rather than false positives.

---

## What this cannot do

`hijack-plausible-path` announces from our *own* ASN through a *registered*
upstream. The route is byte-for-byte what our legitimate traffic can look like.
No BGP-only detector can separate it from the real thing; guessing would be
worse than being honest. The evaluator reports it as a **blind spot**, excluded
from every rate, and the report says so. The real defences against it are
RPKI ASPA / full path validation, and out-of-band signals such as traffic-volume
anomalies — which is what the `Feed`/`Publisher` interface in `internal/feed`
exists to grow into.

Two further honest limits:

- **Data gaps create unavoidable blind spots.** The engine refuses to resolve an
  incident while a majority of collectors cannot see the prefix, and flags
  `blind_at_resolution` rather than reporting a false recovery — but a hijack
  that begins and ends entirely inside a fleet-wide outage is invisible.
- **The scoring weights are a starting point, not truth.** They are in
  `detector.weights` in `config/topology.yaml` precisely so an operator can
  re-tune against their own history. The defaults encode the reasoning above,
  but whether `min_vps: 2` is right for your fleet is a question only your data
  answers.

---

## Layout

```
cmd/routewatch      CLI: generate, replay, serve, validate
internal/model      wire types (Observation, Alert, Label, Scenario)
internal/registry   out-of-band facts: prefixes, AS roles, ROAs, auths, scrubs
internal/detect     the engine: classification, scoring, incidents
internal/sim        scenario generator and injected events
internal/eval       replay and scoring harness
internal/feed       streaming HTTP service over a scenario
internal/report     human-readable evaluation output
config/topology.yaml  everything above, in one file
```
