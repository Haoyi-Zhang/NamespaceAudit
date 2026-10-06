# Input and result formats

## Single-model command

```sh
python3 src/continuity_audit.py MODEL.json RESULT.json
```

`MODEL.json` must be at most 1 MiB and contain one JSON object. `RESULT.json` must not exist. The command enforces a 3 GiB address-space limit and a 120 CPU-second limit. It emits deterministic, pretty-printed JSON.

## Namespace model

The top-level object contains exactly:

```json
{
  "id": "model-name",
  "key_count": 2,
  "exposure": {"windows": [[0], [0]], "capacity": [1]},
  "policies": [],
  "loci": [],
  "events": []
}
```

### Identifier and key bounds

- `id`: nonempty string, at most 100 characters.
- `key_count`: ordinary JSON integer in `1..12`; booleans are rejected as integers.
- Keys are represented by indices `0..key_count-1`.

### Exposure object

`exposure` contains exactly `windows` and `capacity`.

- `capacity` is a list of 1--12 ordinary integers, each in `0..12`.
- `windows` contains exactly one nonempty list per key.
- Each window is a strictly increasing list of valid slot indices.
- Windows may be noncontiguous in the recovery-ordered checker.

A key set is exposable when every key can be assigned to one listed slot without exceeding that slot's capacity. The input asserts this model; the result does not authenticate clocks, erasure, or compromise evidence.

### Policies

There are 1--32 policy objects. Each has exactly:

```json
{"id": "policy-name", "nodes": [...], "root": 0}
```

A policy identifier is nonempty, unique, and at most 80 characters. There are at most 64 topologically ordered nodes. Two node forms are admitted:

```json
{"op": "key", "key": 0}
{"op": "threshold", "k": 2, "children": [0, 1, 3]}
```

A key index must be valid. Threshold `k` is an ordinary positive integer not exceeding the number of child indices. Children must be distinct valid indices referring only to preceding nodes; their list order is not semantically constrained and need not be sorted. The root is a valid node index. Repeated key leaves are permitted and denote the same key. Negation, mutable state, cycles, and false/unsatisfiable policies are not part of the language.

### Loci

There are 1--8 loci. Each has exactly:

```json
{"id": "locus-name", "parents": ["earlier-locus"]}
```

The identifier is nonempty, unique, and at most 80 characters. Parents are a sorted distinct list and must precede the child in the loci array. The order therefore defines an acyclic dependency graph.

### Events

There are 1--32 events and 1--8 events at each locus. Each event has exactly:

```json
{
  "id": "event-name",
  "locus": "locus-name",
  "policy": "policy-name",
  "dominates": ["older-event-at-same-locus"],
  "requires": {"parent-locus": "required-parent-event"}
}
```

Event identifiers are nonempty, unique, and at most 80 characters. The locus and policy must exist. Dominance targets must be sorted, distinct, already declared, and at the same locus; the analyzer takes the reflexive transitive closure. A dominance edge means the current event is a protocol-validated resolution that dominates the named older event.

A requirement may name only a declared parent locus and an already declared event at that parent. In a view, the selected parent event satisfies the requirement when it equals or dominates the required event. Omitted parent entries impose no requirement.

The product of event counts over loci must not exceed 100,000 candidate views. At least one valid view must remain after requirements are applied.

## Result object

The main fields are:

```json
{
  "id": "model-name",
  "result": "prevented",
  "valid_views": 2,
  "incompatible_view_pairs": 1,
  "pair_counts": {
    "prevented": 1,
    "accountable-fork": 0,
    "silent-fork": 0
  },
  "globally_prevented": true,
  "globally_accountable": true,
  "minimum_exposure_margin": 1,
  "pairs": []
}
```

`result` is `no-conflict` when there is no incompatible valid-view pair. Otherwise it is the worst pair class: any silent pair yields `silent-fork`; otherwise any feasible accountable pair yields `accountable-fork`; otherwise the model is `prevented`. `globally_prevented` is true for a prevented model and vacuously true for `no-conflict`. `globally_accountable` means that no incompatible pair is silent. `minimum_exposure_margin` is null for `no-conflict`; otherwise it is the smallest exact margin over incompatible pairs.

Each incompatible-pair row contains:

- `left_view`, `right_view`: event arrays in locus order;
- `conflict_loci`: loci whose selected events are incomparable;
- `option_counts`: number of retained minimal intersection choices at each conflict locus;
- `minimal_forced_sets`: inclusion-minimal unions of keys forced to sign incomparable events;
- `forced_set_analysis`: one row per forced set, containing its keys, maximum matching size, exact `exposure_deficit`, and either null or a deterministic positive `hall_obstruction`; these rows do not contain schedules;
- `exposure_margin`: the minimum deficit over the minimal forced sets;
- `classification`: `silent-fork`, `accountable-fork`, or `prevented`;
- `accountable`: true when the empty forced set is impossible; and
- `fork_witness`: null for a prevented pair, otherwise one deterministic minimal witness.

A Hall obstruction has exactly:

```json
{
  "keys": [0, 1, 2],
  "slots": [0, 2],
  "demand": 3,
  "capacity": 2,
  "deficit": 1
}
```

The key subset has more demand than total capacity in its neighbor slots. For arbitrary noncontiguous windows this general certificate replaces interval-only reasoning. The deficit is also the exact minimum number of unit-capacity positions that must be added at slots already listed in the affected key windows to make that forced set exposable.

Exactly one deterministic `fork_witness` is retained for each feasible pair. It contains `forced_keys`, a key-to-slot `exposures` assignment, and one left/right policy-support pair for every conflict locus. Other feasible forced sets are represented only by their `forced_set_analysis` rows. The witness is symbolic under the supplied model, not a cryptographic proof or evidence that a real exposure occurred.

## Batch replay

`src/continuity_replay.py MODELS.jsonl RESULTS.jsonl` separately recomputes and verifies paired JSON lines. It admits at most 8 keys, 256 KiB per line, 10,000 paired lines, and 1,000,000 raw support-choice combinations per incompatible pair. It performs its own bounded model/reference admission and rejects an empty valid-view set. For each pair it enumerates every raw support-pair choice across all conflict loci, forms the full Cartesian product, and applies subset minimalization once at the end; it does not import or reuse the analyzer's parser, policy compiler, matching routine, local-intersection pruning, or layerwise union-antichain dynamic program. It validates the exact result schema, valid views, minimal supports, exposure schedules for the retained witness, matching sizes, Hall obstructions, pair and model margins, classifications, and deterministic witnesses. Both implementations still share Python, JSON, this schema, and the mathematical specification. The reference campaign invokes replay automatically.

Result comparison preserves JSON types recursively. Counts, key/slot indices, matching sizes, and deficits must be integers, not booleans or floats with the same numeric value. Accountability and prevention flags must be booleans, not integer `0` or `1`. This also applies to nested forced-set analysis and the duplicated model-level fork witness.

The older fixed-pair JSON-lines certificate interface remains exercised by `src/reproduce.py`; it is retained as a one-locus regression rather than the principal model.
