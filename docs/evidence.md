# Evidence interpretation

## Evidence classes

The general mathematical claims are supported by written proofs in `proofs/model.md`. The executable evidence tests the bounded implementation against separately written direct oracles, exact small enumerations, prespecified aggregate counts, mutation tests, and named semantic controls. These evidence classes are complementary: finite agreement is not a proof of the general theorem, while a written proof does not establish that an implementation matches it.

There is no learned component, sampled deployment population, performance target, or statistical estimator. Counts below describe complete finite grids or exact retained inputs only. Timing and memory measurements establish resource closure; they are not throughput benchmarks.

## Recovery-ordered campaign

### Relation-aware threshold grid

For three keys and two exposure slots, each key receives one of the nonempty contiguous windows `[0]`, `[1]`, or `[0,1]`; each slot capacity is zero or one. Each side uses one of 12 legal nonempty committee/threshold combinations. The retained CSV has 46,656 rows, but they are not one evidence type.

Exactly 15,552 incomparable-event rows compare the threshold formula with explicit quorum-pair intersections and enumerated exposure states. They yield 2,953 prevented, 3,527 accountable-fork, and 9,072 silent-fork, with zero formula/oracle disagreements. The remaining 31,104 rows are the two ordered relations for each such parameter tuple. They record the direct semantic consequence `no-conflict`; they do not construct a namespace model and do not call the main checker or replay. The summary and paper therefore report them as derived ordered-relation bookkeeping, not independent checker validation.

### Two-locus graph grid

The graph grid contains root and child loci. It varies the relation at each locus, four parent-dependency patterns, four policies per locus, and six exposure schedules, including noncontiguous and staggered windows. The 3,456 models are parsed and audited by the main checker and independently recomputed by direct enumeration.

Results are 1,920 no-conflict, 72 prevented, 348 accountable-fork, and 1,116 silent-fork, with zero model-level disagreements. The models contain 2,496 incompatible valid-view pairs, 192 of them multi-locus. Two pairs are feasible at every conflict locus in isolation but globally prevented because the union of forced keys exceeds shared exposure capacity. The checker emits 112 positive Hall-obstruction certificates. Pair exposure margins are 0 for 2,384 pairs, 1 for 110 pairs, and 2 for two pairs.

This broad grid has an important coverage limit: every incompatible pair has exactly one retained local intersection option at each conflict locus and exactly one final minimal forced set. It therefore validates view construction, dependency composition, exposure, and replay on many models, but it does not test multi-branch union-antichain pruning. That obligation is addressed by the targeted regressions below. These counts establish finite implementation behavior and a strictness example, not prevalence in deployed namespaces.


### Targeted branching and pruning regressions

A micro-oracle accepts local forced-set families, enumerates their complete Cartesian product, takes every union, and performs subset minimalization only once at the end. It does not call the main checker's local-intersection or layerwise union-antichain routines. Five deterministic family cases cover multi-locus branching, duplicate unions, strict-superset deletion, a shared key across three loci, and locus-order invariance.

The principal family input is `{{0},{1}}` and `{{1},{2}}`; the exact final antichain is `{{1},{0,2}}`. Two corresponding namespace models reverse the locus-family order. Their key windows are `[0]`, `[1]`, `[2]` and capacities are `[1,0,1]`. The forced set `{1}` is infeasible, whereas `{0,2}` is feasible, so both the main checker and full-product replay return `accountable-fork`, `exposure_margin=0`, and a witness using `{0,2}`. The complete inputs, both outputs, and an empty difference list are retained in `branching-oracle-inputs.json`, `branching-oracle-outputs.json`, and `branching-oracle-diff.json`.

### HITTING SET reduction grid

For a three-key universe, every nonempty family of nonempty subsets is paired with each budget from zero through three, giving 508 instances. The generated policy is an AND of OR clauses; the opposing policy requires every universe key. Direct enumeration of hitting sets is compared with fork feasibility. Results contain 275 feasible and 233 blocked cases, with zero reduction disagreements.

This grid checks the implemented reduction on all such three-key instances. NP-completeness is established by the general written reduction, not by the number of checked instances.

### Monotone-policy pairs

The exact 128 policy DAGs selected with seed 20260914 are retained in `inputs/policies.jsonl` without embedded oracle answers. Each is evaluated at four exposure budgets against an all-keys policy, yielding 512 pairs. A direct truth-table evaluator and support enumerator is separate from the analyzer's compiler. Results contain 276 feasible and 236 blocked pairs, with zero disagreements.

The retained policy set is deterministic and replayable but not exhaustive over all monotone circuits.

### Named semantic controls

| Control | Isolated distinction | Expected model result / margin |
|---|---|---|
| `control-resolved-recovery` | A later event validly dominates an earlier event although committees are disjoint | `no-conflict` / none |
| `control-omitted-resolution` | The same alternatives lack a dominance edge | `silent-fork` / 0 |
| `control-bridge-blocked` | One key must sign incomparable events and no exposure capacity exists | `prevented` / 1 |
| `control-bridge-exposed` | The same pair has one exposure position | `accountable-fork` / 0 |
| `control-joint-amplification` | Root and child divergence are forced together under capacity one | `prevented` / 1 |
| `control-joint-feasible` | The same graph has capacity two | `accountable-fork` / 0 |
| `control-holey-hall` | Three keys use only slots 0 and 2 with total capacity two | `prevented` / 1, general Hall obstruction |
| `control-transitive-dominance` | A child requirement is satisfied through the transitive dominance closure | `no-conflict` / none |

All eight controls match the prespecified result and are accepted by the separate replay. The runner automatically aggregates and asserts the category distribution: 2 `no-conflict`, 3 `prevented`, 2 `accountable-fork`, and 1 `silent-fork`. The silent row is `control-omitted-resolution`; it is retained rather than absorbed into an accountable count.

### Exact capacity-margin oracle

The margin oracle enumerates every nonempty subset of three slots as each of three key windows, every binary three-slot capacity vector, and every nonempty forced-key set. For each of 19,208 instances it directly tries all allocations after each possible number of unit-capacity additions, then compares the first feasible value with both maximum-matching deficit and maximum Hall deficiency. All three values agree. The margin histogram is 8,416 at zero, 7,581 at one, 2,784 at two, and 427 at three.

This oracle changes capacity only at slots already allowed by affected keys. It does not interpret the number as compromise probability, elapsed time, or signer availability.

## Retained one-locus regression

| Check | Cases / assignments | Observation |
|---|---:|---|
| Fixed signer pairs | 5,292 | 3,186 feasible, 2,106 blocked, 0 direct-oracle disagreements |
| Mixed thresholds | 15,552 | 2,953 prevented, 12,599 feasible, 0 disagreements |
| Policy DAGs | 128 / 8,192 | 0 support disagreements |

Contiguous opportunity windows admit short interval-overload certificates. A holey-window control demonstrates that interval overload is not complete for arbitrary windows, whereas the general Hall certificate remains exact.

## Independent replay boundary

`src/continuity_replay.py` imports neither `continuity.py` nor the analyzer's parser, matching routine, policy compiler, local-intersection pruning, or layerwise union-antichain dynamic program. It independently checks bounded model structure and references, rejects an empty valid-view set, recursively evaluates policies, enumerates valid views and temporal exposure states, enumerates the full Cartesian product of raw support-pair choices across all conflict loci, and minimalizes forced unions only once at the end. It validates the one retained feasible witness schedule, recomputes matching size and Hall deficiency for every forced set, verifies margins and schema fields, and rejects extra or malformed evidence.

The full-product route is materially different from the main checker's pruning route, but it is not an independently developed formalization or human replication. Both programs share Python, JSON semantics, the published schema, the mathematical specification, and the same project authorship process. Replay does not authenticate signatures, recovery order, clocks, or exposure facts. Its direct support-product bound is 1,000,000 choices per incompatible pair.

### Replay admission risk controls

Before repair, executing the inherited reader reproduced two concrete risks: an empty event list paired with a forged `valid_views=0` no-conflict result was accepted, and a feasible pair with `fork_witness=null` raised an uncaught `AttributeError`. The repaired reader now performs its own finite structure/reference admission, rejects zero valid views, and checks nested result types before field access.

Four retained cases distinguish current exclusions from the historical observations: a legal resolved-recovery no-conflict model remains accepted; an empty-event model is rejected; a nonempty, structurally valid model whose requirements leave no global view is rejected; and a null feasible witness is rejected without an uncaught exception. Exact current inputs, outputs, and zero-difference checks are in `replay-admission-inputs.json`, `replay-admission-outputs.json`, and `replay-admission-diff.json`. The package contains only the repaired reader, so the pre-repair behavior is recorded as an executed repair observation rather than claimed reproducible from the final code.

## Unit and mutation tests

The earlier reference appendix was text-extracted and its documented commands were executed with fresh output destinations. That historical check found the literal ASCII `--out`, retained shell continuation backslashes, and successful full-reproducer and single-model commands. Its machine-readable record is `results/pdf-command-verification.json`; it does not establish a build or command extraction of the currently edited TeX sources.

The current suite has 27 test methods; the historical POSIX reference ran 25. In addition to the earlier certificate, parser, recovery, graph, reduction, Hall, and margin checks, it covers full-product multi-branch combination, duplicate unions, strict-superset deletion, shared-key combination, locus-order invariance, the target accountable/margin-zero branching model, unsorted-but-preceding policy children, automatic semantic-control aggregation, replay rejection of empty/no-view models, and null feasible witnesses. Two added methods reject 446 individual numeric-type substitutions across nine model results and retain nine valid JSON round trips. Type-sensitive replay is a result-schema property, not an additional cryptographic guarantee.

Passing these tests shows that the named regressions are enforced. It does not exhaust all parser inputs or establish absence of implementation defects.

## Resource observations

`src/reproduce.py` runs one child at a time on POSIX, refuses an existing output directory, applies 120 CPU-second and 3 GiB address-space limits to scientific children, and reconciles outputs against both expected-count files. Historical host measurements remain in `results/reference/reproduction.json` and `results/reference/run-ledger.json`; timing may vary by environment. The bounded current Windows library-level rerun reproduces the continuity campaign's deterministic semantic fields and executes the current tests, but does not run the POSIX command-line resource-limit path. `results/intake.json` and `results/campaign-budget.json` retain the earlier intake and campaign accounting.

## Result interpretation checklist

Before reusing a result, confirm that:

1. the model passed the strict parser;
2. every dominance edge and parent requirement has a protocol-specific justification outside this checker;
3. key identifiers denote the intended independently attributable signing epochs;
4. the exposure family represents the claimed compromise mechanism, including any correlation that matters;
5. the complete reproduction record, rather than one child command, reports success;
6. `no-conflict`, prevention, accountability, and freshness are not conflated;
7. a Hall margin is interpreted only as added allowed-slot capacity in the declared model; and
8. no finite count is presented as a general proof, deployment-frequency estimate, or independent review.
