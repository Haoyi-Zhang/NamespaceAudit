# Source and closest-work boundaries

This file records what is reused from external work and what requires this project's own proof. External publications are cited, not redistributed. The detailed 12-paper TDSC calibration and adjacent/full-paper reading record is in `docs/literature-audit.md`; source identities and access notes are in `external_resources.csv`.

## Self-certifying namespaces

Mazières, Kaminsky, Kaashoek, and Witchel's SFS paper establishes self-certifying pathnames and separates file-system security from external key management; it also discusses signed forwarding and revocation. This project reuses that setting and historical motivation with citation. It does not claim to introduce self-certifying identifiers, forwarding, revocation, or the SFS architecture.

The changed question is static and combinatorial: given supplied recovery order, immutable policy snapshots, parent dependencies, and an exposure family, can two incompatible finite namespace views both obtain certificates? SFS implementation and performance claims are neither reproduced nor transferred.

## Quorum intersection and Byzantine replication

Malkhi and Reiter's Byzantine quorum systems require every two quorums to intersect outside every admissible fail-prone set. The one-locus threshold prevention inequality here is a specialization of that condition after exposable key sets are treated as admissible failures. Dynamic Byzantine quorum systems and BFT reconfiguration protocols already address membership evolution in live replicated services. PBFT, Prime, Fast Byzantine Consensus, Steward, oracle-based consensus, AWARE, and DBFT supply relevant protocol, proof, and evaluation patterns; none is reimplemented or used as an empirical baseline.

The project-specific proof obligation is composition across a finite namespace graph with a protocol-supplied recovery partial order, heterogeneous monotone policies, parent requirements, and one shared exposure family. The strictness construction relies on dependencies forcing several local divergences into the same valid-view pair.

## Recovery, key evolution, and key exposure

Proactive recovery supplies the established bounded-vulnerability-window idea. Bellare and Miner supply forward-secure signatures, where later compromise need not enable forgery of past signatures. Asynchronous Byzantine reconfiguration uses comparable histories and forward-secure key updates to make superseded configurations harmless in a live protocol. Key-exposure-resistant auditing and rotatable authenticated dictionaries show other application-specific ways to structure epochs and post-compromise updates.

This project does not implement those mechanisms, prove erasure, or infer that a physical compromise releases keys independently. A signing epoch may be represented as a distinct attributable key with a window only when a concrete integration justifies that abstraction.

## KERI and recovery order

KERI supplies self-certifying identifiers, append-only key-event histories, key pre-rotation, witnesses, delegation, and superseding recovery semantics. It distinguishes an authoritative recovered history from events that may remain relevant to accountability. The checker uses KERI only as a motivating example for protocol-validated dominance; it neither implements KERI events/receipts nor certifies a KERI deployment.

A label such as `recovery` has no semantic effect in the input. Every dominance edge is an asserted protocol fact that must be validated outside the artifact.

## Fork detection, accountability, and transparency

SUNDR supplies fork consistency for an untrusted storage server. PeerReview supplies distributed-system accountability. CONIKS, secure logging, and rotatable zero-knowledge sets use commitments, logs, clients, or monitors to expose inconsistent bindings. Polygraph, BFT Protocol Forensics, Self-Healing Lattice Agreement, and Tenderbake study evidence or recovery for broader protocol forks.

This project uses a narrower definition: an incompatible pair is accountable when every feasible support choice forces at least one attributable key to sign incomparable events. That is not full execution accountability, legal blame, detection latency, evidence dissemination, consensus, or a guarantee that isolated clients compare views.

## Cryptographic lifting

The exact criterion is first proved in a symbolic certificate model. Its computational corollary additionally assumes a canonical event encoding, sound association between key identifiers and verification keys/epochs, per-key EUF-CMA signatures, the stated honest chain-signing rule for unexposed keys, and an actual exposure set belonging to the supplied family. Under those assumptions, successful certificates for a symbolically prevented pair imply either a signature forgery or failure of an integration assumption. The artifact performs no cryptographic operations and does not experimentally validate EUF-CMA security.

## Matching, margin, and complexity

Hall's theorem underlies the temporal exposure test. The project proves that maximum Hall deficiency equals matching deficit and is the exact number of unit-capacity positions that must be added at already allowed slots to expose a forced set. The contribution is the use of that exact margin inside the namespace criterion and its checkable obstruction record, not Hall's theorem or bipartite matching itself. Interval overload remains only a special complete certificate for contiguous windows.

HITTING SET is the source problem for the NP-hardness proof. The reduction technique, antichain pruning, and truth-table evaluation are standard; novelty is not claimed for them.

## Offline currentness

Self-certifying historical authentication does not prove that no later revocation or recovery exists. The two-world indistinguishability argument in `proofs/model.md` is a boundary statement. Freshness may instead come from a current witness receipt, transparency checkpoint, trusted clock plus expiry policy, online authority, or another trusted current input.

## Evidence status

The theorem, computational corollary, margin result, and reductions have complete written arguments in the declared model, but are not proof-assistant mechanized. Finite grids, mutation tests, exact small oracles, and independent code replay validate bounded implementation paths only. No independent human referee, protocol maintainer, faculty contact, or external solver has certified the result. The manuscript and repository must preserve these distinctions.
