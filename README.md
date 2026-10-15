# Recovery-ordered namespace continuity

A bounded symbolic analyzer for recovery-ordered continuity in a finite self-certifying namespace. It reports `no-conflict` when there is no incompatible valid-view pair; otherwise it distinguishes `silent-fork`, `accountable-fork`, and `prevented` under the supplied exposure model.

The input is a claimed model, not authenticated evidence. Integrations must validate every event, dominance edge, policy snapshot, parent requirement, signature, and exposure assumption. Comparable recovery events belong to one history; a label alone does not establish recovery order.

## Environment

Use **Python 3.10+ on Linux or Linux under WSL2**, with the standard library only; no package installation is needed. CI uses Python 3.12 on Ubuntu 24.04. The command-line tools import POSIX `resource` and enforce Unix CPU/address-space limits. Native Windows is not a supported CLI/full-reproduction path; a non-POSIX resource-limit port has not been validated.

No network, solver, private data, external model, secret key, live service, or paper directory is required. Commands below run from this directory, or the root of either flat public repository.

## Audit one model

```sh
python3 -B src/continuity_audit.py inputs/example-namespace.json results/example-result.json
```

The output file must not exist. The CLI accepts a JSON object of at most 1 MiB and writes deterministic result JSON, including incompatible-pair details; `--summary-only` omits those details. It enforces 120 CPU seconds and 3 GiB address space.

The example has two valid views linked by parent requirements. Their joint fork needs two distinct exposed keys, but the only slot has capacity one; the expected result is `prevented`. See [docs/formats.md](docs/formats.md) for the complete input, output, and replay schemas.

## Tests and full reproduction

```sh
python3 -B -m unittest discover -s tests -v
python3 -B tests/regression_exposure_reuse.py
python3 -B src/reproduce.py --out results/local
```

`results/local` must **not exist**. The runner executes one child at a time: 27 unit-test methods, fixed-pair/policy-DAG and continuity campaigns, certificate generation/replay, direct-oracle replay, and expected-count reconciliation. Each scientific child has 120 CPU seconds, 3 GiB address space, and a 120-second wall timeout.

Success requires `results/local/reproduction.json` to report all commands succeeded, deterministic certificate bytes equal, and both expected-count sets equal. Partial output or a successful paper build is not completion.

The separate exposure-reuse regression has three methods over twelve named models: literal partial-assignment/Hall checks, full replay, repeated pairs, fresh returned evidence, capacity isolation, and refusal cases. It can run on native Windows using its existing deny-all resource-import shim; it never invokes POSIX resource operations or the campaign CLIs. A Windows library-level check is not validation of the POSIX reproduction path.

CI runs the exposure-reuse regression followed by the bounded full reproducer and retains raw outputs even on failure. Historical POSIX outputs and measurements stay in `results/reference/`; its older unit transcript contains 25 methods, not the current 27. Do not replace the reference results or measurements with local output.

## Model, results, and evidence

A finite acyclic graph contains namespace loci and events with immutable monotone policies, parent requirements, and a protocol-supplied dominance order. A valid view chooses one event per locus and satisfies requirements up to dominance. Honest unexposed keys may sign comparable events at a locus, but not incomparable events there. Exposure slots and capacities define a downward-closed family.

For an incompatible view pair, the analyzer combines minimal policy supports and asks whether the union of forced equivocation keys is exposable. It records deterministic witnesses, matching sizes, Hall obstructions, and exact added-capacity margins. Exposure analyses are reused only within an `Audit` instance, with parameter-change invalidation and fresh returned evidence; independent replay does not share that cache. No measured speedup is claimed.

[docs/evidence.md](docs/evidence.md) partitions the retained 70,348 heterogeneous rows by validation path. They are not one common checker/oracle agreement count: 31,104 are derived ordered-relation rows with no checker/replay call. Checker and full-product replay cover 4,484 namespace models; targeted branching regressions supplement the single-option graph grid. The retained one-locus specialization is a regression, not a new quorum-intersection principle.

- `src/continuity.py`, `continuity_audit.py`: parser, model, analyzer, and single-model CLI.
- `src/continuity_replay.py`: separate bounded admission and full support-product oracle, final-only minimalization, type-sensitive result and witness checking.
- `src/run_continuity.py`: deterministic continuity campaigns.
- `src/finite_model.py`, `audit.py`, `replay.py`, `run_pilot.py`: one-locus specialization and certificate workflow.
- `src/reproduce.py`: sequential reproduction and aggregate reconciliation.
- `inputs/`: example, frozen policy DAGs, pilot protocol, and prespecified expected counts.
- `proofs/model.md`: written definitions, proofs, lifting assumptions, complexity, and currentness boundary.
- `docs/source-boundaries.md`, `docs/literature-audit.md`, `external_resources.csv`: closest-work attribution, recorded reading depth, identities, rights, and access.
- `claim_evidence_ledger.csv`: claim-to-proof/check/result map.
- `results/reference/`: historical reference outputs and resource records; the other retained receipts document intake, accounting, extraction, and historical command checks, not fresh verification of edited sources.

## Bounds and conditions

The analyzer admits 1–12 keys, 1–8 loci, 1–32 events (at most 8 per locus), at most 32 policies with 64 nodes each, a 1–12-slot exposure horizon, and at most 100,000 candidate view tuples. The direct replay admits at most 8 keys and 1,000,000 raw support combinations per incompatible pair. Exact support/Hall enumeration is exponential; tractability is relative to explicit view count, not just compact graph size.

Dominance and exposure assumptions must come from the integrated protocol. One key identifier denotes one independently attributable signing secret/epoch; correlated multi-key device compromise is outside the main exposure model. Historical evidence cannot establish that no later recovery/revocation exists. Liveness, erasure, availability, probabilistic leakage, side channels, mutable interpretation, and live network behavior are outside scope.

This is not a signature library, consensus protocol, key-management service, deployed file system, or vulnerability claim about SFS, KERI, a PKI, or any third-party implementation. Finite agreement does not prove general theorems, deployment security/prevalence, or a real recovery order. The written proof is not proof-assistant output or independent external verification.

Original code, tests, symbolic inputs, results, and documentation are covered by `LICENSE`. Scholarly papers and publisher assets are cited, not redistributed.
