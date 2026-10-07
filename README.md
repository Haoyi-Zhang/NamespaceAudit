# Self-certifying namespace continuity

This standalone repository implements a bounded exact audit for **recovery-ordered continuity** in a finite self-certifying namespace. It is a symbolic analyzer, not a signature library, consensus protocol, key-management service, or deployed file system.

The audit reports `no-conflict` when the model has no incompatible valid-view pair. Otherwise it distinguishes three outcomes:

- `silent-fork`: both views can be certified without any key signing incomparable events;
- `accountable-fork`: a fork is feasible within the declared exposure model, but every feasible fork forces at least one attributable equivocation;
- `prevented`: no incompatible view pair can be certified within the declared exposure model while unexposed keys obey chain signing.

A protocol may mark a later event as dominating an earlier event. Such comparable events are a single recoverable history, not a fork. The checker does **not** infer recovery semantics from labels: an integration must validate every dominance edge, event, policy snapshot, parent requirement, signature, and exposure assumption.

## Quick audit

Python 3.10 or later and only the standard library are required.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 src/continuity_audit.py \
  inputs/example-namespace.json results/example-result.json
```

The output path must not exist. The example has two valid views whose root and child choices are linked by parent requirements. Each local conflict needs one exposed key, but their joint fork needs two distinct exposed keys while the only slot has capacity one. The expected global result is `prevented`.

## Full reproduction

Run from the repository root with a fresh output directory:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 src/reproduce.py --out results/local
```

The runner executes one child at a time and refuses to overwrite evidence. It performs:

1. 27 unit-test methods (the historical reference run contains the earlier 25);
2. the retained fixed-pair and policy-DAG regression campaign;
3. the recovery-ordered continuity campaign;
4. fixed-pair certificate generation and independent replay;
5. recovery-ordered direct-oracle replay; and
6. expected-count reconciliation.

Completion is recorded only when `results/local/reproduction.json` reports success. A directory name, partial output, or successful PDF build is not proof of scientific correctness.

Each scientific child is limited to 120 CPU seconds and 3 GiB of address space, with a 120-second wall timeout. The code uses POSIX resource limits; a non-POSIX port has not been validated. No network, solver, package installation, private data, model API, secret key, live service, or paper directory is required.

The two added tests enforce type-sensitive result replay: integer evidence cannot be replaced by a numerically equal Boolean or float, and Boolean flags cannot be replaced by integers. They cover 446 single-field substitutions across the eight semantic controls and one branching model, plus nine valid JSON round trips. A current Windows library-level check uses a wall-bounded private harness; it is not a run of the POSIX reproducer. `results/reference/` retains the historical POSIX outputs and resource measurements, rather than replacing them with Windows telemetry.

## Model in one paragraph

The analyzer reuses immutable exposure analyses within one `Audit` instance,
keyed by forced-key set and cleared if its exposure parameters change. Hall
subset enumeration and its separate matching consistency check are retained on
first use; the feasible witness uses that same deterministic assignment. Returned
evidence lists/dictionaries are fresh. Policy, view, antichain, margin and witness
selection semantics are unchanged; the independent replay does not share this
cache. This removes repeated analysis work, not scientific cases or obligations,
and makes no measured speedup claim.

`python -B tests/regression_exposure_reuse.py` runs three additional finite checks
over twelve owned models, including literal partial-assignment/Hall enumeration,
full replay, repeated pairs, nested result mutation, capacity isolation and
refusals. Scientific CI runs this explicit step before the unchanged full
reproducer; it is separate from the retained 27-method suite and does not rewrite
archived measurements or certify the POSIX campaign on Windows.

A finite acyclic graph of namespace loci contains events. Each event snapshots a satisfiable monotone authorization policy, may require events at parent loci, and belongs to a protocol-supplied dominance order at its locus. A valid view selects one event per locus and satisfies parent requirements up to dominance. Two views conflict where their events are incomparable. An honest unexposed key may sign comparable events at one locus, but not incomparable events there; it may sign independently at different loci. Exposed keys belong to a downward-closed temporal family defined by per-key exposure slots and per-slot capacities.

For a pair of incompatible views, select a minimal policy support for each selected event at each conflict locus. The keys forced to equivocate are the union of the support intersections across all conflict loci. The pair is feasible exactly when some such union is exposable. For every forced set the checker also reports maximum matching size, exact Hall deficiency, and (when positive) a deterministic Hall obstruction. The minimum deficiency over all minimal forced sets is the exact number of unit-capacity additions at already allowed slots needed to make that view pair feasible. `proofs/model.md` gives the complete written proof, computational lifting under attributable EUF-CMA signatures, threshold specialization, graph-composition result, complexity boundary, and currentness limitation. These are mathematical arguments in the declared model, not proof-assistant output.

## Retained validation

The continuity summary contains 70,348 **heterogeneous recorded rows**, not 70,348 executions of one common checker/oracle path:

| Evidence unit | Rows / models | Main observations | Mismatches |
|---|---:|---|---:|
| Incomparable threshold formula/oracle | 15,552 | 2,953 prevented; 3,527 accountable; 9,072 silent | 0 |
| Derived ordered-relation rows | 31,104 | `no-conflict` follows from supplied comparability; no namespace checker/replay call | not applicable |
| Two-locus graph models | 3,456 | 1,920 no-conflict; 72 prevented; 348 accountable; 1,116 silent | 0 |
| HITTING SET reduction models | 508 | 275 fork-feasible; 233 blocked | 0 |
| Monotone-policy models | 512 | 276 fork-feasible; 236 blocked | 0 |
| Named semantic controls | 8 | 2 no-conflict; 3 prevented; 2 accountable; 1 silent | 0 |
| Capacity-margin oracle | 19,208 | exact added capacity equals matching deficit and maximum Hall deficiency | 0 |

The main checker and full-product replay are jointly exercised on the 4,484 namespace models in the graph, reduction, policy, and control rows. The graph grid contains 2,496 incompatible pairs, including 192 multi-locus pairs, but every pair has one local option per conflict locus and one final forced set. It therefore does **not** validate branching antichain pruning. Separate retained regressions cover five direct set-family cases and two namespace models. In the target model, local families `{{0},{1}}` and `{{1},{2}}` produce `{{1},{0,2}}`; windows `[0]`, `[1]`, `[2]` with capacity `[1,0,1]` preserve feasible `{0,2}`, yielding `accountable-fork` with margin 0. Exact inputs, outputs, and a zero-difference record are stored under `results/reference/continuity/branching-oracle-*.json`.

Replay-admission controls retain one legal `no-conflict` case and reject an empty event list, a nonempty structurally valid model with zero valid views, and a feasible pair whose witness is null. The current reader performs its own bounded structure/reference checks and full Cartesian support-choice combination, then minimalizes once at the end. It does not reuse the main checker's local-intersection or layerwise union-antichain pruning. Both paths still share Python, JSON, the schema, and the mathematical specification.

The retained one-locus regression contains 5,292 signer-pair cases, 15,552 mixed-threshold configurations, and 128 policy DAGs evaluated over 8,192 assignments. The one-locus prevention formula is explicitly identified as a specialization of Byzantine-quorum intersection, not a new quorum principle.

Finite agreement checks an implementation over the stated inputs. It does not establish empirical prevalence, deployed cryptographic security, liveness, secure erasure, or the correctness of a real protocol's recovery order.

## Repository map

| Location | Purpose |
|---|---|
| `src/continuity.py` | Strict parser, dominance closure, valid-view enumeration, minimal-support dynamic program, temporal exposure test, Hall/margin analysis, classifications and witnesses |
| `src/continuity_audit.py` | Single-model fresh-file CLI |
| `src/continuity_replay.py` | Separately written bounded reader/oracle; performs its own admission, enumerates full support-choice products with final-only minimalization, and rechecks witnesses, Hall deficits, margins, and schema fields |
| `src/run_continuity.py` | Deterministic threshold, graph, reduction, policy-pair, semantic-control, and exact capacity-margin campaigns |
| `src/finite_model.py`, `src/replay.py`, `src/run_pilot.py` | Retained one-locus specialization, certificates, and exact regression campaign |
| `src/reproduce.py` | Sequential full reproduction and count reconciliation |
| `tests/test_model.py` | Parser, theorem-boundary, witness-mutation, recovery, graph, and reduction tests |
| `inputs/example-namespace.json` | Two-locus nonlocal-composition example |
| `inputs/expected-*.json` | Prespecified aggregate regression targets |
| `proofs/model.md` | Definitions, theorems, proofs, complexity, and scope |
| `docs/formats.md` | Input and result schema |
| `docs/evidence.md` | Case selection, observations, and evidence interpretation |
| `docs/source-boundaries.md` | Closest-work and attribution boundary |
| `claim_evidence_ledger.csv` | Claim-to-proof/check/result map |
| `external_resources.csv` | External source identity, access, rights, and integration record |
| `results/reference/` | Complete reference run generated by `src/reproduce.py` |
| `results/pdf-command-verification.json` | Rebuilt-appendix text/command check using fresh output destinations |

## Implemented bounds

The main checker admits 1--12 keys, 1--8 loci, 1--32 events, at most 8 events per locus, at most 32 policies, at most 64 nodes per policy, a 1--12-slot exposure horizon, and at most 100,000 candidate view tuples. The direct replay oracle admits at most 8 keys and 1,000,000 raw support-choice combinations per incompatible pair. Policy truth tables and exact support families are exponential in distinct keys; the general decision problem is NP-complete even for one locus and two events.

The checker enumerates the candidate-view product and pairs of valid views. Its key-parameter tractability statement is relative to that explicit view count, not to the compact graph alone. Hall evidence requires subset enumeration for every retained forced set, and Python truth-vector operations have exponential bit length; `proofs/model.md` includes these costs in its conservative bound.

## Security and interpretation boundaries

The input is a claimed model, not authenticated evidence. In particular:

- a dominance edge must be justified by the integrated protocol;
- exposure windows and capacities are assumptions, not observed compromise facts;
- a device exposure that releases several keys is a correlated family outside the main model;
- a key identifier is assumed to name one independently attributable signing secret/epoch;
- the analyzer compares supplied histories but cannot prove that no later event exists;
- denial of service, liveness, policy availability, probabilistic leakage, side channels, mutable interpretation, and live network behavior are outside scope.

No result asserts a vulnerability in SFS, KERI, a PKI, or any third-party implementation.

## Licensing and research status

Original code, tests, symbolic inputs, generated results, and repository documentation are licensed under `LICENSE`. Scholarly papers and publisher assets are cited but not redistributed here. The theorem has not received independent external or proof-assistant verification.
