# Recovery-ordered namespace continuity: model and proofs

This document gives the complete written argument used by the manuscript.  It is a mathematical proof in a declared symbolic model, not a proof-assistant development and not a proof of a deployed protocol.  Signatures are represented only by their signer identities.  Protocol-specific validation of event syntax, dominance edges, policy snapshots, and parent requirements is assumed and must be supplied by an integration.

## 1. Objects and assumptions

### 1.1 Keys, policies, and supports

Let `K` be a finite set of distinct signing-key identities.  An authorization policy `P` is an upward-closed family of subsets of `K`: if `Q` satisfies `P`, every superset of `Q` also satisfies `P`. Every event policy is satisfiable, equivalently `K` belongs to `P_e`. A **support** is a satisfying set.  A support is **minimal** if no proper subset satisfies the policy.  Every policy admitted by the checker is a finite monotone threshold circuit over key leaves; repeated leaves name the same physical key.

A certificate for event `e` contains signatures from a support of the event's immutable policy snapshot `P_e`.  Extra signatures may be discarded, so every certificate contains a minimal support as a subset.

We assume existential unforgeability for unexposed keys and public attribution of each accepted signature to one key identity.  The executable artifact does not instantiate or benchmark a signature scheme.

### 1.2 Namespace loci, events, and recovery order

A namespace has a finite, acyclic graph of **loci**.  A locus is an independently resolved namespace decision point, such as the authority for one path component or one delegation edge.  Every event belongs to one locus.

Each locus `l` has a protocol-supplied partial order `<=_l` over its events.  We write `e <_l f` when `f` is a publicly verifiable resolution that dominates `e`.  Comparable events can coexist in one authoritative evolution; incomparable events represent alternative terminal authorities.  A KERI-style superseding recovery is the motivating example, but the checker does not infer KERI semantics.  An integration must validate every dominance edge using its own event rules.

An event may require named events at parent loci.  A namespace **view** `v` selects exactly one event `v(l)` at every locus and is valid when every requirement `(p,r)` of `v(l)` is satisfied by `r <=_p v(p)`.  Explicit bottom events may represent an absent or not-yet-created locus, so total selection does not require every real-world object to exist.

Two views are **compatible** when their selected events are comparable at every locus.  Their conflict set is

```
D(v,w) = { l : v(l) and w(l) are incomparable under <=_l }.
```

### 1.3 Chain signing and exposure

For one locus, an honest, unexposed key may sign only a chain of events under that locus's partial order.  It may sign comparable rotation/recovery events and may sign independently at different loci.  Signing two incomparable events at one locus is publicly attributable equivocation.

The adversary may expose a set of keys from a downward-closed family `F`: if `B` is exposable, every subset of `B` is exposable.  The empty set is exposable.  Exposed keys may sign any event.

The implemented exposure family is temporal.  Key `k` has a nonempty set `W_k` of slots in which the corresponding signing epoch can be exposed.  Slot `t` has capacity `c_t`.  A set `B` is exposable exactly when there is an injective key-to-capacity-position assignment that sends every `k in B` to a slot in `W_k`.  A post-erasure compromise of a forward-secure epoch is represented by omitting that later slot from the epoch key's window.  The checker does not infer windows from clocks, logs, or operational claims.

The main model treats key exposures as independent units.  A device compromise that releases several keys at once is a different, correlated exposure family and is retained as an explicit countermodel.

## 2. Forced equivocators for two views

For an incompatible pair of valid views `v,w`, select certificate supports `Q_l` for `v(l)` and `R_l` for `w(l)` at every conflict locus.  Define

```
X(v,w,Q,R) = union over l in D(v,w) of (Q_l intersect R_l).
```

`X` is the set of keys forced to sign incomparable events somewhere in the pair of views.

### Lemma 1 (minimal supports suffice)

If two certificates can be produced with arbitrary supports while exposing a set in `F`, then they can be produced with minimal supports while exposing a set in `F`.

**Proof.**  Replace every support by an included minimal support.  The forced-equivocator set can only shrink.  Since `F` is downward closed, the smaller set remains exposable.  The reverse direction is immediate because minimal supports are supports.  QED.

### Theorem 1 (exact view-pair criterion)

Under the satisfiable-policy premise, two valid views `v,w` can both be certified while every unexposed key obeys chain signing if and only if there is a choice of minimal supports at their conflict loci for which `X(v,w,Q,R)` belongs to `F`.

**Necessity.**  Suppose both views have certificates and the adversary exposes `B in F`.  At any conflict locus, every key in both certificate supports signed two incomparable events.  Chain signing therefore implies that the key is in `B`.  Hence the union of all such intersections is a subset of `B`.  Apply Lemma 1 and downward closure.

**Sufficiency.**  Choose minimal supports whose forced set `X` is exposable and expose exactly `X`.  Exposed keys can produce all signatures requested of them.  Consider an unexposed key at one locus.  If the two selected events are incomparable, the key is not in both supports by construction.  If they are comparable, signing both is permitted.  Across different loci there is no shared lock.  Thus every unexposed key obeys chain signing.  Policies at nonconflict loci have at least one support and can be satisfied without creating an incomparable double-signature.  QED.

This theorem is conditional on policy authenticity, dominance validation, and key attribution.  It does not claim liveness or freshness.

### Corollary 1 (three exact risk classes)

For a fixed incompatible view pair:

1. **Silent fork:** some minimal-support choice has `X = empty`.  No signer need double-sign.  The fork is feasible because the empty set is exposable.
2. **Accountable fork:** every choice has nonempty `X`, and some choice has `X in F`.  The fork is feasible under the exposure model, but every such fork contains at least one publicly attributable double-signature.
3. **Prevented:** no choice has `X in F`.  The pair cannot be certified within the exposure bound while unexposed keys follow chain signing.

The classes are disjoint and exhaustive for an **incompatible pair**.  If a complete model has no incompatible valid pair, the implementation reports `no-conflict`; it does not relabel the absence of a fork as a prevented pair.

### Corollary 2 (computational lifting)

Assume:

1. events have canonical encodings and the policy/dominance inputs are soundly bound to those encodings;
2. accepted signatures are publicly attributable to a listed key;
3. each unexposed key uses an EUF-CMA signature scheme;
4. an honest unexposed signer signs only a comparable chain at a locus; and
5. the actual exposed-key set `B` belongs to `F`.

If the symbolic audit classifies an incompatible pair `v,w` as prevented, a polynomial adversary that nevertheless produces accepted certificates for both views either forges an unexposed-key signature or violates one of assumptions 1, 2, 4, or 5.  In an independent multi-user signature experiment, the forgery contribution is bounded by the sum of the per-key EUF-CMA advantages.

**Proof.**  Condition on no signature forgery and on sound validation.  Every signer occurring in both supports at a conflict locus produced signatures for incomparable canonical messages.  Honest chain signing therefore implies that signer is actually exposed.  Thus the forced set `X` is a subset of `B`.  Since `B in F` and `F` is downward closed, `X in F`, contradicting the symbolic prevented classification.  A standard reduction either guesses the forged key or uses a union bound over key identities.  QED.

This corollary does not validate the dominance graph, secure erasure, or exposure declaration.  Those are explicit premises.

### Corollary 3 (global continuity and accountability)

A finite namespace model prevents incompatible certified views exactly when every incompatible valid view pair is in the prevented class.  It guarantees modeled accountability for every incompatible pair exactly when no pair is in the silent class.

This follows by applying Theorem 1 to every incompatible valid view pair.  Parent requirements determine which combinations of local events are valid views.

## 3. Why graph composition is stronger than isolated pair tests

A local audit checks one incomparable event pair at one locus.  If every local pair is prevented, global continuity follows: an exposable global forced set would have every local intersection as an exposable subset, contradicting local prevention.

The converse is false.  Parent requirements can force several loci to diverge together.  Suppose the only valid views are `(r0,c0)` and `(r1,c1)`.  At the root, both policies require key `a`; at the child, both require key `b`.  The two events at each locus are incomparable.  Each isolated conflict is feasible if one key can be exposed, but the only global fork forces `{a,b}`.  With one exposure slot of capacity one, the namespace is globally prevented.  The retained control `control-joint-amplification` computes this case; increasing the capacity to two yields an accountable fork.

Thus local pair conditions are useful sufficient rules, while the exact graph criterion is the union condition in Theorem 1.

## 4. Recovery order removes false conflicts

A one-successor lock marks any two different events as equivocation.  That rule rejects a legitimate recovery event authorized by a disjoint recovery committee after an operational event.  In the recovery-ordered model, an authenticated dominance edge makes the two events comparable, removes the locus from `D(v,w)`, and imposes no unnecessary committee overlap.

Conversely, merely labeling an event `recovery` does not make it comparable.  If the dominance edge is omitted or invalid, disjoint operational and recovery supports produce a silent fork.  The controls `control-resolved-recovery` and `control-omitted-resolution` differ only in this edge and produce the two expected outcomes.

This separation is the model's main semantic purpose: policy overlap is required for unresolved alternatives, not for a recovery that the protocol already proves to be authoritative.

## 5. Threshold specialization

Consider one conflict locus.  Event 0 uses a `q0`-of-`C0` threshold policy and event 1 uses a `q1`-of-`C1` policy.  Let

```
U = C0 union C1,
O = C0 intersect C1,
r_F(O) = max {|B| : B subseteq O and B in F}.
```

### Lemma 2 (minimum quorum intersection)

There are quorums of sizes `q0,q1` with intersection contained in a given `B subseteq O` if and only if

```
q0 + q1 <= |U| + |B|.
```

**Proof.**  Necessity follows from
`|Q0|+|Q1| = |Q0 union Q1| + |Q0 intersect Q1| <= |U|+|B|`.
For sufficiency, allow the elements of `B` to be used twice and every element of `U` once.  The inequality states that this multiset has enough positions for the two quorum demands.  Allocate committee-exclusive elements first and fill any remaining demand from the overlap, using a member twice only when it is in `B`.  Equivalently, this is a two-bin capacitated matching with the displayed Hall inequality as its only nontrivial cut.  QED.

### Theorem 2 (threshold trichotomy)

The exact class is

```
silent fork          iff q0+q1 <= |U|,
accountable fork      iff |U| < q0+q1 <= |U|+r_F(O),
prevented             iff q0+q1 > |U|+r_F(O).
```

**Proof.**  A silent fork exists exactly when the two quorums can be disjoint; apply Lemma 2 with `B=empty`.  A fork within the exposure family exists exactly when Lemma 2 holds for some exposable `B subseteq O`, which is equivalent to the inequality with maximum size `r_F(O)`.  Subtract the silent region to obtain the accountable middle region.  QED.

The prevention inequality is the earlier fixed-parent condition.  Mapping maximal exposable sets to fail-prone sets makes it an instance of Byzantine quorum-system intersection condition D1.  The new graph theorem does not relabel that known one-locus fact as a new quorum theorem.

### Corollary 4 (minimum threshold-only repair)

Let `s=q0+q1`.  The minimum total threshold increase needed for accountability is

```
delta_A = max(0, |U| + 1 - s),
```

and for prevention is

```
delta_P = max(0, |U| + r_F(O) + 1 - s).
```

The repair is feasible by threshold changes alone exactly when the available headroom
`(|C0|-q0)+(|C1|-q1)` is at least the requested delta.  This is immediate because both guarantees depend only on the threshold sum, and each unit increase raises that sum by one.

## 6. Temporal exposure rank, Hall certificates, and exact margin

For a key set `B`, construct a bipartite graph from keys to unit-capacity slot positions `(t,j)`, with an edge from `k` to `(t,j)` exactly when `t in W_k`.  Let `nu(B)` be its maximum matching size.  For `S subseteq B`, let `N(S)` be the adjacent unit positions and define

```
d(B) = max over S subseteq B of max(0, |S|-|N(S)|).
```

### Lemma 3 (temporal exposure)

`B` is exposable if and only if the graph has a matching saturating `B`.

This is exactly the definition of assigning every key to one distinct unit position at an allowed slot.

### Theorem 4 (exact exposure-capacity margin)

Assume every key window is nonempty.  Then

```
d(B) = |B| - nu(B),
```

and this value is the exact minimum number of unit-capacity positions that must be added at slots already allowed by the affected keys to make `B` exposable.

**Proof.**  Hall's deficiency form of the matching theorem states that the number of unmatched left vertices in a maximum matching is the maximum deficiency `max_S (|S|-|N(S)|)`, proving the equality.  One added position can increase maximum matching size by at most one, so at least `d(B)` additions are necessary.  Retain a maximum matching.  For each of its `d(B)` unmatched keys, choose any slot in that key's nonempty window, add one fresh unit position there, and match the key to it.  The previous matching plus these edges saturates `B`, so `d(B)` additions suffice.  QED.

For a view pair whose minimal forced-set antichain is `A`, define

```
Delta(v,w) = min { d(X) : X in A }.
```

The pair is feasible exactly when `Delta=0`; it is prevented exactly when `Delta>0`.  Any subset attaining positive Hall deficiency is an independently checkable obstruction.  The checker chooses a deterministic maximum-deficiency subset, then breaks ties by smaller cardinality and lexical key order.

For contiguous windows, a failed matching also admits an interval overload: some interval `[a,b]` contains more keys whose complete windows lie within it than total interval capacity.  This certificate remains sound but is not complete for noncontiguous windows.  The retained holey-window control forces a general Hall obstruction without an interval overload.

The margin changes only capacity at already permitted slots.  It is not a compromise probability, does not model adding new attack times, and does not measure signer availability.

## 7. Exact checker

For each monotone policy over `k` keys, the checker evaluates its truth table and records all minimal supports.  It enumerates valid namespace views from the locus product and filters them by parent requirements.  For each incompatible view pair and each conflict locus, it forms the family of intersections between minimal supports.

A dynamic program combines conflict loci.  Its state is a bit mask for the union of forced equivocators.  After each locus it discards any mask having a retained subset, because the exposure family is downward closed.  At most `2^k` union states remain.  The exact invariant is: after processing the first `j` conflict loci, the retained masks are precisely the inclusion-minimal unions obtainable by choosing one local support intersection at each processed locus.  The proof is inductive.  The base family is `{empty}`.  At the next locus every retained state is unioned with every minimal local intersection; replacing a discarded previous state or local intersection by its retained subset can only shrink the union, so subset pruning leaves exactly the minimal obtainable unions.  Hall deficiency is monotone under adding keys, hence discarded supersets cannot improve feasibility, silence, or the minimum margin.

A temporal matching tests exposability.  For every final forced set the checker records the forced keys, matching size, exact deficit, and either a deterministic Hall obstruction or null.  These per-set analysis rows do not carry schedules.  The pair output includes the minimum margin `Delta`.  If any forced set is feasible, the result additionally carries one lexicographically deterministic fork witness: two views, one support pair per conflict locus, the selected forced set, and its key-to-slot exposure assignment.  A blocked result carries the complete final antichain and blocking evidence for every member; one Hall subset alone would not prove the universal claim.  A model with no incompatible view pair is reported as `no-conflict`.

Let `S` be total circuit encoding size, `N` the number of candidate view tuples, and `m` the number of loci. Charging truth-vector operations by their bit length gives the conservative bound

```
2^{O(k)} * poly(S,N,m,|E|,|T|).
```

Support cross-products and subset comparisons have at most `4^k` combinations. Hall-certificate extraction enumerates up to `2^|X|` subsets for every retained forced set, and compilation uses `2^k`-bit Python integers rather than unit-cost truth vectors. These costs are included in the exponential factor. This is fixed-parameter tractability in `k` relative to explicit candidate-view count `N`, not relative to a compact graph description whose view product can be exponential. The delivered checker admits at most 12 keys, 8 loci, 32 events, and 100,000 candidate view tuples.

The separate replay implementation does not import the analyzer, matching code, parser, truth-table compiler, local-intersection pruning, or layerwise union-antichain dynamic program.  It performs its own bounded structure/reference admission and rejects models with no valid view.  For at most eight keys it directly evaluates policies, enumerates valid views and exposure states, enumerates the full Cartesian product of raw support-pair choices across all conflict loci, and minimalizes forced unions only once at the end.  It checks the one retained feasible witness schedule, recomputes Hall deficiencies for every forced set, validates every result field, and rejects extra or malformed evidence.  The graph grid alone does not exercise this algorithmic difference: its 2,496 incompatible pairs include 192 multi-locus pairs but no pair with more than one local option or final set.  Five direct set-family cases and two branching namespace models therefore target duplicate unions, strict-superset deletion, a shared key, locus-order invariance, and the antichain `{{1},{0,2}}`.  A further 19,208-case oracle directly searches the minimum number of capacity additions and compares it with both matching deficit and Hall deficiency.

## 8. Complexity boundary

Define **FORK**: given two incomparable events with monotone policy circuits and a cardinality exposure budget `b`, decide whether both can be certified while exposing at most `b` keys.

### Theorem 5 (NP-completeness)

FORK is NP-complete even for one locus, two events, and one exposure slot.

**Membership.**  A certificate consists of two satisfying key sets and an exposed set of size at most `b` containing their intersection.  Circuit evaluation and set checks are polynomial.

**Hardness.** Reduce HITTING SET restricted to a nonempty universe and a nonempty family of nonempty subsets. This restriction remains NP-hard: vertex cover is its two-element-subset special case. For universe `K={k1,...,kn}`, family `S1,...,Sm`, and budget `b`, create policy

```
P = AND over j of (OR over ki in Sj of ki)
```

and policy `Q = AND over all ki in K of ki`.  Give their events no dominance relation and allow at most `b` exposures in one slot.  Every support of `P` is a hitting set; the only minimal support of `Q` is `K`.  The intersection of a support of `P` with the support of `Q` is therefore the support of `P` itself.  A fork exists exactly when the HITTING SET instance has a solution of size at most `b`.  The construction is polynomial.  QED.

The universal prevention decision is consequently coNP-complete.  This result explains why the checker has an exponential distinct-key parameter and why threshold policies merit the closed form in Theorem 2.

## 9. Offline currentness impossibility

The results authenticate and compare the events supplied to a verifier.  They do not tell an offline verifier that no later event exists.

Consider two worlds with identical historical transcript `H` at disconnect time.  In world 0 no later event occurs; in world 1 an authenticated revocation or recovery occurs after disconnection.  A verifier receiving only `H` has the same input in both worlds and must return the same answer.  It therefore cannot be both complete for world 0 and reject stale authority in world 1.  Freshness requires an additional trusted input, such as a current witness receipt, a transparency checkpoint, a trusted clock plus expiry policy, or an online authority.  No self-certifying historical name alone removes this indistinguishability.

## 10. Scope that remains outside the theorem

The theorem does not prove that a protocol's dominance relation is correct, that its clocks or exposure windows are truthful, that key erasure occurred, or that authorized signers are available.  It excludes correlated device/domain compromise, probabilistic leakage, side channels, denial of service, policy cycles, mutable policy interpretation, hidden keys sharing one secret, and live network behavior.  It proves neither KERI nor any file system secure.  It is a conditional audit of finite event/policy graphs.
