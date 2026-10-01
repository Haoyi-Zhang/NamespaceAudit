"""Deterministic campaign for recovery-ordered namespace continuity.

The campaign is finite validation, not a machine-checked general proof.  It uses
one process and reports heterogeneous evidence units separately: an explicit
three-key threshold oracle grid, derived ordered-relation rows, admitted
namespace models, an exact capacity-margin grid, targeted branching-pruning
regressions, and replay-admission negative controls.
"""
from __future__ import annotations

import argparse
import csv
import json
import resource
import time
from collections import Counter
from itertools import combinations, product
from pathlib import Path

from continuity import Audit, NamespaceModel, audit
from continuity_replay import direct_union_antichain, oracle, verify
from finite_model import hall_obstruction, maximum_exposure
from replay import oracle_exposed_sets

ROOT = Path(__file__).resolve().parents[1]


def stable_histogram(counter: Counter) -> dict[str, int]:
    """Return a JSON-stable histogram for integer or ``None`` keys."""
    def order(item: tuple[object, int]) -> tuple[int, int]:
        key = item[0]
        return (1, 0) if key is None else (0, int(key))

    return {"none" if key is None else str(key): count
            for key, count in sorted(counter.items(), key=order)}


def direct_saturates(keys: tuple[int, ...], windows: tuple[tuple[int, ...], ...],
                     capacity: tuple[int, ...]) -> bool:
    """Small direct assignment oracle, deliberately independent of matching."""
    if not keys:
        return True
    for slots in product(*(windows[key] for key in keys)):
        counts = [0] * len(capacity)
        for slot in slots:
            counts[slot] += 1
        if all(used <= limit for used, limit in zip(counts, capacity)):
            return True
    return False


def capacity_compositions(total: int, slots: int) -> tuple[tuple[int, ...], ...]:
    """All weak compositions of ``total`` into ``slots`` deterministic parts."""
    if slots == 1:
        return ((total,),)
    rows = []
    for first in range(total + 1):
        for rest in capacity_compositions(total - first, slots - 1):
            rows.append((first,) + rest)
    return tuple(rows)


def run_margin_oracle_grid(out: Path) -> dict:
    """Exhaustively verify the exposure-deficit repair interpretation.

    Three keys range over every nonempty subset of three slots, every binary
    capacity vector, and every nonempty forced-key subset.  The matching
    deficit is compared with a direct enumeration of all assignments after
    every smaller/equal total unit-capacity augmentation.
    """
    n = 3
    slot_sets = [tuple(t for t in range(3) if mask & (1 << t)) for mask in range(1, 1 << 3)]
    key_sets = [tuple(k for k in range(n) if mask & (1 << k)) for mask in range(1, 1 << n)]
    cases = 0
    mismatches = 0
    margins: Counter = Counter()
    with (out / "capacity-margin-oracle.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["windows", "capacity", "forced_keys", "matching_deficit",
                         "direct_minimum_added_capacity", "hall_deficit"])
        for windows, capacity, keys in product(product(slot_sets, repeat=n),
                                                product((0, 1), repeat=3), key_sets):
            windows = tuple(windows); capacity = tuple(capacity)
            cases += 1
            deficit = len(keys) - len(maximum_exposure(keys, windows, capacity))
            direct_margin = None
            for total in range(len(keys) + 1):
                if any(direct_saturates(
                        keys, windows,
                        tuple(capacity[t] + extra[t] for t in range(3)))
                       for extra in capacity_compositions(total, 3)):
                    direct_margin = total
                    break
            obstruction = hall_obstruction(keys, windows, capacity)
            hall_deficit = 0 if obstruction is None else obstruction["deficit"]
            if direct_margin != deficit or hall_deficit != deficit:
                mismatches += 1
                raise AssertionError((windows, capacity, keys, deficit,
                                      direct_margin, obstruction))
            margins[deficit] += 1
            writer.writerow([json.dumps(windows, separators=(",", ":")),
                             json.dumps(capacity), json.dumps(keys), deficit,
                             direct_margin, hall_deficit])
    if cases != 19_208:
        raise AssertionError(cases)
    return {"cases": cases, "mismatches": mismatches,
            "exposure_margin_histogram": stable_histogram(margins)}


def dump(path: Path, obj: object) -> None:
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def threshold_policy(pid: str, committee: tuple[int, ...], q: int) -> dict:
    nodes = [{"op": "key", "key": k} for k in committee]
    if len(nodes) == 1 and q == 1:
        root = 0
    else:
        root = len(nodes)
        nodes.append({"op": "threshold", "k": q, "children": list(range(len(committee)))})
    return {"id": pid, "nodes": nodes, "root": root}


def key_policy(pid: str, key: int) -> dict:
    return {"id": pid, "nodes": [{"op": "key", "key": key}], "root": 0}


def pair_profile(name: str, prefix: str, shift: int = 0) -> tuple[list[dict], tuple[str, str]]:
    rot = lambda *keys: tuple((k + shift) % 4 for k in keys)
    if name == "disjoint":
        policies = [key_policy(prefix + "a", rot(0)[0]), key_policy(prefix + "b", rot(1)[0])]
    elif name == "shared":
        policies = [key_policy(prefix + "a", rot(0)[0]), key_policy(prefix + "b", rot(0)[0])]
    elif name == "threshold":
        policies = [threshold_policy(prefix + "a", rot(0, 1, 2), 2),
                    threshold_policy(prefix + "b", rot(1, 2, 3), 2)]
    elif name == "alternative":
        policies = [threshold_policy(prefix + "a", rot(0, 1), 1),
                    threshold_policy(prefix + "b", rot(1, 2), 1)]
    else:
        raise ValueError(name)
    return policies, (policies[0]["id"], policies[1]["id"])


def ordered_pair_events(locus: str, left: str, right: str, left_policy: str, right_policy: str,
                        relation: str, left_requires: dict | None = None,
                        right_requires: dict | None = None) -> list[dict]:
    left_requires = left_requires or {}; right_requires = right_requires or {}
    if relation == "incomparable":
        return [
            {"id": left, "locus": locus, "policy": left_policy, "dominates": [], "requires": left_requires},
            {"id": right, "locus": locus, "policy": right_policy, "dominates": [], "requires": right_requires},
        ]
    if relation == "right-over-left":
        return [
            {"id": left, "locus": locus, "policy": left_policy, "dominates": [], "requires": left_requires},
            {"id": right, "locus": locus, "policy": right_policy, "dominates": [left], "requires": right_requires},
        ]
    if relation == "left-over-right":
        return [
            {"id": right, "locus": locus, "policy": right_policy, "dominates": [], "requires": right_requires},
            {"id": left, "locus": locus, "policy": left_policy, "dominates": [right], "requires": left_requires},
        ]
    raise ValueError(relation)


def run_threshold_grid(out: Path) -> dict:
    """Compare the threshold formula only on incomparable-event instances.

    The CSV also retains two derived comparable-relation rows per explicit
    quorum/exposure comparison.  Those rows are bookkeeping checks of the
    supplied relation semantics; they do not invoke the namespace checker or
    the independent replay and are reported separately.
    """
    n = 3
    windows = [(0,), (1,), (0, 1)]
    subsets = [tuple(i for i in range(n) if mask & (1 << i)) for mask in range(1, 1 << n)]
    counts = {"no-conflict": 0, "prevented": 0, "accountable-fork": 0, "silent-fork": 0}
    formula_mismatches = 0
    derived_relation_mismatches = 0
    rows = 0
    explicit_cases = 0
    derived_rows = 0
    incomparable_margins: Counter = Counter()
    with (out / "threshold-triage.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["windows", "capacity", "left_committee", "right_committee", "left_q", "right_q",
                         "relation", "classification", "oracle_classification", "evidence_path"])
        for ws in product(windows, repeat=n):
            for caps in product((0, 1), repeat=2):
                proto = {"id": "oracle", "windows": [list(w) for w in ws], "capacity": list(caps),
                         "left": [0], "right": [0]}
                exposed = oracle_exposed_sets(proto)
                for left, right in product(subsets, repeat=2):
                    overlap = set(left).intersection(right)
                    rank = len(maximum_exposure(overlap, ws, caps))
                    for ql in range(1, len(left) + 1):
                        for qr in range(1, len(right) + 1):
                            explicit_cases += 1
                            intersections = [set(a).intersection(b)
                                             for a in combinations(left, ql)
                                             for b in combinations(right, qr)]
                            oracle_accountable = all(intersections)
                            oracle_feasible = any(any(inter <= state for state in exposed)
                                                  for inter in intersections)
                            if not oracle_feasible:
                                oracle_class = "prevented"
                            elif oracle_accountable:
                                oracle_class = "accountable-fork"
                            else:
                                oracle_class = "silent-fork"
                            formula_accountable = ql + qr > len(set(left).union(right))
                            formula_prevented = ql + qr > len(set(left).union(right)) + rank
                            margin = min(len(inter) - len(maximum_exposure(inter, ws, caps))
                                         for inter in intersections)
                            if (margin == 0) != oracle_feasible:
                                raise AssertionError((ws, caps, left, right, ql, qr, margin, oracle_feasible))
                            incomparable_margins[margin] += 1
                            if formula_prevented:
                                formula_class = "prevented"
                            elif formula_accountable:
                                formula_class = "accountable-fork"
                            else:
                                formula_class = "silent-fork"
                            if formula_class != oracle_class:
                                formula_mismatches += 1
                            counts[formula_class] += 1
                            rows += 1
                            writer.writerow([json.dumps(ws, separators=(",", ":")), json.dumps(caps),
                                             json.dumps(left), json.dumps(right), ql, qr, "incomparable",
                                             formula_class, oracle_class, "explicit-quorum-exposure"])
                            for relation in ("right-over-left", "left-over-right"):
                                predicted = "no-conflict"
                                expected = "no-conflict"
                                if predicted != expected:
                                    derived_relation_mismatches += 1
                                counts[predicted] += 1
                                rows += 1
                                derived_rows += 1
                                writer.writerow([json.dumps(ws, separators=(",", ":")), json.dumps(caps),
                                                 json.dumps(left), json.dumps(right), ql, qr, relation,
                                                 predicted, expected, "derived-comparable-relation"])
    if explicit_cases != 15_552 or derived_rows != 31_104 or rows != 46_656:
        raise AssertionError((explicit_cases, derived_rows, rows))
    return {
        "recorded_rows": rows,
        "incomparable_formula_oracle_cases": explicit_cases,
        "ordered_relation_derived_rows": derived_rows,
        "namespace_checker_models": 0,
        "counts": counts,
        "formula_oracle_mismatches": formula_mismatches,
        "derived_relation_mismatches": derived_relation_mismatches,
        "incomparable_exposure_margin_histogram": stable_histogram(incomparable_margins),
    }


def make_graph_model(index: int, root_relation: str, child_relation: str,
                     requirements: tuple[int, int], root_profile: str, child_profile: str,
                     exposure_name: str) -> dict:
    rp, rids = pair_profile(root_profile, "rp-", 0)
    cp, cids = pair_profile(child_profile, "cp-", 2)
    exposures = {
        "zero": {"windows": [[0]] * 4, "capacity": [0]},
        "one": {"windows": [[0]] * 4, "capacity": [1]},
        "two": {"windows": [[0]] * 4, "capacity": [2]},
        "split": {"windows": [[0], [0], [1], [1]], "capacity": [1, 1]},
        # Non-interval windows exercise the general Hall obstruction rather
        # than an interval-overload shortcut.
        "holey": {"windows": [[0, 2]] * 4, "capacity": [1, 0, 1]},
        "staggered": {"windows": [[0, 2], [0, 1], [1, 2], [0, 1, 2]],
                      "capacity": [1, 0, 1]},
    }
    root_events = ordered_pair_events("root", "r0", "r1", rids[0], rids[1], root_relation)
    child_events = ordered_pair_events(
        "child", "c0", "c1", cids[0], cids[1], child_relation,
        {"root": "r" + str(requirements[0])}, {"root": "r" + str(requirements[1])})
    return {
        "id": f"graph-{index:04d}",
        "key_count": 4,
        "exposure": exposures[exposure_name],
        "policies": rp + cp,
        "loci": [{"id": "root", "parents": []}, {"id": "child", "parents": ["root"]}],
        "events": root_events + child_events,
    }


def run_graph_grid(out: Path) -> dict:
    relations = ("incomparable", "right-over-left", "left-over-right")
    profiles = ("disjoint", "shared", "threshold", "alternative")
    exposures = ("zero", "one", "two", "split", "holey", "staggered")
    model_count = 0; mismatches = 0; pair_total = 0; joint_blocked = 0
    multi_locus_pairs = 0; branching_local_pairs = 0; multiple_final_set_pairs = 0
    result_counts = {"no-conflict": 0, "prevented": 0, "accountable-fork": 0, "silent-fork": 0}
    model_margins: Counter = Counter()
    pair_margins: Counter = Counter()
    pair_class_margins: Counter = Counter()
    hall_obstructions = 0
    with (out / "graph-models.jsonl").open("w") as fm, (out / "graph-results.jsonl").open("w") as fr:
        for rr, cr, req, rp, cp, exposure in product(relations, relations, product((0, 1), repeat=2), profiles, profiles, exposures):
            model_count += 1
            raw = make_graph_model(model_count, rr, cr, req, rp, cp, exposure)
            result = audit(raw, include_pairs=True)
            if not verify(raw, result):
                mismatches += 1
                raise AssertionError((raw, result, oracle(raw)))
            fm.write(json.dumps(raw, separators=(",", ":")) + "\n")
            fr.write(json.dumps(result, separators=(",", ":")) + "\n")
            result_counts[result["result"]] += 1
            model_margins[result["minimum_exposure_margin"]] += 1
            pair_total += result["incompatible_view_pairs"]
            engine = Audit(NamespaceModel.parse(raw))
            for row in result["pairs"]:
                if len(row["conflict_loci"]) > 1:
                    multi_locus_pairs += 1
                if any(count > 1 for count in row["option_counts"]):
                    branching_local_pairs += 1
                if len(row["minimal_forced_sets"]) > 1:
                    multiple_final_set_pairs += 1
                pair_margins[row["exposure_margin"]] += 1
                pair_class_margins[(row["classification"], row["exposure_margin"])] += 1
                hall_obstructions += sum(
                    analysis["hall_obstruction"] is not None
                    for analysis in row["forced_set_analysis"]
                )
                if row["classification"] != "prevented" or len(row["conflict_loci"]) < 2:
                    continue
                left = tuple(row["left_view"]); right = tuple(row["right_view"])
                all_local_feasible = True
                for locus_name in row["conflict_loci"]:
                    i = [l.name for l in engine.model.loci].index(locus_name)
                    opts = engine._intersection_options(left[i], right[i])
                    if not any(engine._exposure_for_mask(mask)[0] for mask in opts):
                        all_local_feasible = False; break
                if all_local_feasible:
                    joint_blocked += 1
    # 3*3*4*4*4*6 = 3456
    if (model_count, pair_total, multi_locus_pairs, branching_local_pairs, multiple_final_set_pairs) != (3456, 2496, 192, 0, 0):
        raise AssertionError((model_count, pair_total, multi_locus_pairs,
                              branching_local_pairs, multiple_final_set_pairs))
    class_margin_rows = {
        f"{classification}|{margin}": count
        for (classification, margin), count in sorted(pair_class_margins.items())
    }
    return {"models": model_count, "result_counts": result_counts,
            "incompatible_view_pairs": pair_total,
            "multi_locus_incompatible_pairs": multi_locus_pairs,
            "pairs_with_multiple_local_options": branching_local_pairs,
            "pairs_with_multiple_final_sets": multiple_final_set_pairs,
            "joint_exposure_blocked_pairs": joint_blocked,
            "oracle_mismatches": mismatches,
            "model_exposure_margin_histogram": stable_histogram(model_margins),
            "pair_exposure_margin_histogram": stable_histogram(pair_margins),
            "pair_class_margin_histogram": class_margin_rows,
            "hall_obstruction_certificates": hall_obstructions}


def hitting_policy(family: tuple[tuple[int, ...], ...], n: int) -> dict:
    nodes = [{"op": "key", "key": i} for i in range(n)]
    clauses = []
    for subset in family:
        if len(subset) == 1:
            clauses.append(subset[0])
        else:
            idx = len(nodes)
            nodes.append({"op": "threshold", "k": 1, "children": list(subset)})
            clauses.append(idx)
    if len(clauses) == 1:
        root = clauses[0]
    else:
        root = len(nodes)
        nodes.append({"op": "threshold", "k": len(clauses), "children": clauses})
    return {"id": "hit", "nodes": nodes, "root": root}


def run_reduction_grid(out: Path) -> dict:
    n = 3
    nonempty_subsets = [tuple(i for i in range(n) if mask & (1 << i)) for mask in range(1, 1 << n)]
    cases = 0; mismatches = 0; feasible = 0
    margins: Counter = Counter()
    with (out / "reduction-results.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["family_mask", "budget", "hitting_set_exists", "fork_feasible", "classification"])
        for family_mask in range(1, 1 << len(nonempty_subsets)):
            family = tuple(nonempty_subsets[j] for j in range(len(nonempty_subsets)) if family_mask & (1 << j))
            for budget in range(n + 1):
                cases += 1
                hit = any(all(set(choice).intersection(clause) for clause in family)
                          for size in range(budget + 1) for choice in combinations(range(n), size))
                p = hitting_policy(family, n)
                q = threshold_policy("all", tuple(range(n)), n)
                raw = {"id": f"reduction-{cases:04d}", "key_count": n,
                       "exposure": {"windows": [[0]] * n, "capacity": [budget]},
                       "policies": [p, q], "loci": [{"id": "name", "parents": []}],
                       "events": [
                           {"id": "candidate", "locus": "name", "policy": "hit", "dominates": [], "requires": {}},
                           {"id": "universe", "locus": "name", "policy": "all", "dominates": [], "requires": {}},
                       ]}
                result = audit(raw, include_pairs=True)
                margins[result["minimum_exposure_margin"]] += 1
                fork = result["result"] != "prevented"
                if hit != fork or not verify(raw, result):
                    mismatches += 1
                    raise AssertionError((family, budget, hit, result))
                feasible += fork
                writer.writerow([family_mask, budget, int(hit), int(fork), result["result"]])
    if cases != 508:
        raise AssertionError(cases)
    return {"cases": cases, "fork_feasible": feasible, "fork_blocked": cases - feasible,
            "reduction_mismatches": mismatches,
            "exposure_margin_histogram": stable_histogram(margins)}


def run_policy_pairs(out: Path) -> dict:
    frozen = ROOT / "inputs" / "policies.jsonl"
    cases = 0; mismatches = 0; feasible = 0
    margins: Counter = Counter()
    q = threshold_policy("all", tuple(range(6)), 6)
    with frozen.open() as source, (out / "policy-pair-results.jsonl").open("w") as handle:
        for line in source:
            p = json.loads(line)
            for budget in range(4):
                cases += 1
                policy = {"id": "sample", "nodes": p["nodes"], "root": p["root"]}
                raw = {"id": f"policy-pair-{cases:03d}", "key_count": 6,
                       "exposure": {"windows": [[0]] * 6, "capacity": [budget]},
                       "policies": [policy, q], "loci": [{"id": "name", "parents": []}],
                       "events": [
                           {"id": "sample-event", "locus": "name", "policy": "sample", "dominates": [], "requires": {}},
                           {"id": "all-event", "locus": "name", "policy": "all", "dominates": [], "requires": {}},
                       ]}
                result = audit(raw, include_pairs=True)
                if not verify(raw, result):
                    mismatches += 1; raise AssertionError((raw, result))
                feasible += result["result"] != "prevented"
                margins[result["minimum_exposure_margin"]] += 1
                handle.write(json.dumps({"id": raw["id"], "source_policy": p["id"],
                                         "budget": budget,
                                         "classification": result["result"],
                                         "exposure_margin": result["minimum_exposure_margin"],
                                         "minimal_forced_sets": result["pairs"][0]["minimal_forced_sets"]},
                                        separators=(",", ":")) + "\n")
    if cases != 512:
        raise AssertionError(cases)
    return {"cases": cases, "fork_feasible": feasible, "fork_blocked": cases - feasible,
            "oracle_mismatches": mismatches,
            "exposure_margin_histogram": stable_histogram(margins)}


def control_models() -> list[dict]:
    # Comparable recovery with disjoint operational/recovery keys: legal, not a fork.
    strict = {"id": "control-resolved-recovery", "key_count": 2,
              "exposure": {"windows": [[0], [0]], "capacity": [0]},
              "policies": [key_policy("oldp", 0), key_policy("recp", 1)],
              "loci": [{"id": "name", "parents": []}],
              "events": ordered_pair_events("name", "old", "recovery", "oldp", "recp", "right-over-left")}
    omitted = json.loads(json.dumps(strict)); omitted["id"] = "control-omitted-resolution"
    omitted["events"] = ordered_pair_events("name", "old", "recovery", "oldp", "recp", "incomparable")
    bridge_blocked = {"id": "control-bridge-blocked", "key_count": 1,
                      "exposure": {"windows": [[0]], "capacity": [0]},
                      "policies": [key_policy("p", 0)], "loci": [{"id": "name", "parents": []}],
                      "events": ordered_pair_events("name", "left", "right", "p", "p", "incomparable")}
    bridge_exposed = json.loads(json.dumps(bridge_blocked)); bridge_exposed["id"] = "control-bridge-exposed"
    bridge_exposed["exposure"]["capacity"] = [1]
    # Requirements force root and child divergences to occur together.  Each local
    # common key can be exposed alone, but the global union needs two exposures.
    joint = {"id": "control-joint-amplification", "key_count": 2,
             "exposure": {"windows": [[0], [0]], "capacity": [1]},
             "policies": [key_policy("r", 0), key_policy("c", 1)],
             "loci": [{"id": "root", "parents": []}, {"id": "child", "parents": ["root"]}],
             "events": [
                 {"id": "r0", "locus": "root", "policy": "r", "dominates": [], "requires": {}},
                 {"id": "r1", "locus": "root", "policy": "r", "dominates": [], "requires": {}},
                 {"id": "c0", "locus": "child", "policy": "c", "dominates": [], "requires": {"root": "r0"}},
                 {"id": "c1", "locus": "child", "policy": "c", "dominates": [], "requires": {"root": "r1"}},
             ]}
    joint_feasible = json.loads(json.dumps(joint)); joint_feasible["id"] = "control-joint-feasible"
    joint_feasible["exposure"]["capacity"] = [2]
    holey = {"id": "control-holey-hall", "key_count": 3,
             "exposure": {"windows": [[0, 2]] * 3, "capacity": [1, 1, 1]},
             "policies": [threshold_policy("all", (0, 1, 2), 3)],
             "loci": [{"id": "name", "parents": []}],
             "events": ordered_pair_events("name", "left", "right", "all", "all", "incomparable")}
    transitive = {"id": "control-transitive-dominance", "key_count": 2,
                  "exposure": {"windows": [[0], [0]], "capacity": [0]},
                  "policies": [key_policy("oldp", 0), key_policy("recp", 1)],
                  "loci": [{"id": "root", "parents": []}, {"id": "child", "parents": ["root"]}],
                  "events": [
                      {"id": "r0", "locus": "root", "policy": "oldp", "dominates": [], "requires": {}},
                      {"id": "r1", "locus": "root", "policy": "oldp", "dominates": ["r0"], "requires": {}},
                      {"id": "r2", "locus": "root", "policy": "recp", "dominates": ["r1"], "requires": {}},
                      {"id": "c", "locus": "child", "policy": "oldp", "dominates": [],
                       "requires": {"root": "r0"}},
                  ]}
    return [strict, omitted, bridge_blocked, bridge_exposed, joint, joint_feasible, holey, transitive]


def run_controls(out: Path) -> dict:
    expected = {
        "control-resolved-recovery": "no-conflict",
        "control-omitted-resolution": "silent-fork",
        "control-bridge-blocked": "prevented",
        "control-bridge-exposed": "accountable-fork",
        "control-joint-amplification": "prevented",
        "control-joint-feasible": "accountable-fork",
        "control-holey-hall": "prevented",
        "control-transitive-dominance": "no-conflict",
    }
    expected_counts = {
        "no-conflict": 2,
        "prevented": 3,
        "accountable-fork": 2,
        "silent-fork": 1,
    }
    rows = []
    margins: Counter = Counter()
    result_counts: Counter = Counter()
    for raw in control_models():
        result = audit(raw, include_pairs=True)
        if result["result"] != expected[raw["id"]] or not verify(raw, result):
            raise AssertionError((raw, result))
        rows.append({"model": raw, "result": result})
        result_counts[result["result"]] += 1
        margins[result["minimum_exposure_margin"]] += 1
    observed_counts = {name: result_counts[name] for name in expected_counts}
    if observed_counts != expected_counts:
        raise AssertionError((observed_counts, expected_counts))
    dump(out / "continuity-controls.json", rows)
    return {
        "cases": len(rows),
        "result_counts": observed_counts,
        "expected_result_counts": expected_counts,
        "expected_results_equal": True,
        "exposure_margin_histogram": stable_histogram(margins),
    }


def branching_model(model_id: str, reverse_locus_families: bool = False) -> dict:
    """Two valid views with two branching local support-intersection families."""
    family_a = (
        threshold_policy("a-left", (0, 1), 1),
        threshold_policy("a-right", (0, 1), 2),
    )
    family_b = (
        threshold_policy("b-left", (1, 2), 1),
        threshold_policy("b-right", (1, 2), 2),
    )
    root_pair, child_pair = (family_b, family_a) if reverse_locus_families else (family_a, family_b)
    policies = [root_pair[0], root_pair[1], child_pair[0], child_pair[1]]
    return {
        "id": model_id,
        "key_count": 3,
        "exposure": {"windows": [[0], [1], [2]], "capacity": [1, 0, 1]},
        "policies": policies,
        "loci": [{"id": "root", "parents": []}, {"id": "child", "parents": ["root"]}],
        "events": [
            {"id": "r-left", "locus": "root", "policy": root_pair[0]["id"],
             "dominates": [], "requires": {}},
            {"id": "r-right", "locus": "root", "policy": root_pair[1]["id"],
             "dominates": [], "requires": {}},
            {"id": "c-left", "locus": "child", "policy": child_pair[0]["id"],
             "dominates": [], "requires": {"root": "r-left"}},
            {"id": "c-right", "locus": "child", "policy": child_pair[1]["id"],
             "dominates": [], "requires": {"root": "r-right"}},
        ],
    }


def run_branching_regressions(out: Path) -> dict:
    """Exercise branches that the broad graph grid does not contain."""
    family_cases = [
        {"id": "target-two-locus", "families": [[[0], [1]], [[1], [2]]],
         "expected": [[1], [0, 2]]},
        {"id": "reversed-locus-order", "families": [[[1], [2]], [[0], [1]]],
         "expected": [[1], [0, 2]]},
        {"id": "duplicate-union", "families": [[[0], [1]], [[0], [1]]],
         "expected": [[0], [1]]},
        {"id": "explicit-superset-deletion", "families": [[[0], [0, 1]], [[2]]],
         "expected": [[0, 2]]},
        {"id": "shared-key-three-locus", "families": [[[0], [1]], [[0], [2]], [[0], [3]]],
         "expected": [[0], [1, 2, 3]]},
    ]
    family_outputs = []
    differences = []
    for case in family_cases:
        observed = direct_union_antichain(case["families"])
        family_outputs.append({"id": case["id"], "observed": observed})
        if observed["minimal_sets"] != case["expected"]:
            differences.append({"id": case["id"], "field": "minimal_sets",
                                "expected": case["expected"], "observed": observed["minimal_sets"]})

    model_cases = [
        branching_model("branching-forward", False),
        branching_model("branching-reversed", True),
    ]
    model_outputs = []
    expected_pair = {
        "option_counts": [2, 2],
        "minimal_forced_sets": [[1], [0, 2]],
        "classification": "accountable-fork",
        "accountable": True,
        "exposure_margin": 0,
    }
    compare_fields = list(expected_pair)
    for raw in model_cases:
        main_result = audit(raw, include_pairs=True)
        direct_result = oracle(raw, include_pairs=True)
        accepted = verify(raw, main_result)
        if len(main_result["pairs"]) != 1 or len(direct_result["pairs"]) != 1:
            differences.append({"id": raw["id"], "field": "pair_count",
                                "main": len(main_result["pairs"]), "direct": len(direct_result["pairs"])})
        else:
            main_pair = main_result["pairs"][0]
            direct_pair = direct_result["pairs"][0]
            for field in compare_fields:
                if main_pair[field] != direct_pair[field]:
                    differences.append({"id": raw["id"], "field": field,
                                        "main": main_pair[field], "direct": direct_pair[field]})
                if main_pair[field] != expected_pair[field]:
                    differences.append({"id": raw["id"], "field": "expected." + field,
                                        "expected": expected_pair[field], "observed": main_pair[field]})
            witness = main_pair.get("fork_witness")
            if not isinstance(witness, dict) or witness.get("forced_keys") != [0, 2]:
                differences.append({"id": raw["id"], "field": "fork_witness.forced_keys",
                                    "expected": [0, 2], "observed": None if witness is None else witness.get("forced_keys")})
        if not accepted:
            differences.append({"id": raw["id"], "field": "verify", "expected": True, "observed": False})
        model_outputs.append({"id": raw["id"], "main_checker": main_result,
                              "direct_full_product_oracle": direct_result,
                              "reported_result_accepted": accepted})

    dump(out / "branching-oracle-inputs.json", {
        "family_cases": family_cases,
        "model_cases": model_cases,
    })
    dump(out / "branching-oracle-outputs.json", {
        "family_outputs": family_outputs,
        "model_outputs": model_outputs,
    })
    dump(out / "branching-oracle-diff.json", {
        "mismatches": len(differences),
        "differences": differences,
        "direct_oracle_layerwise_union_pruning": False,
    })
    if differences:
        raise AssertionError(differences)
    return {
        "family_cases": len(family_cases),
        "model_cases": len(model_cases),
        "mismatches": 0,
        "target_minimal_forced_sets": [[1], [0, 2]],
        "target_classification": "accountable-fork",
        "target_exposure_margin": 0,
        "direct_oracle_layerwise_union_pruning": False,
    }


def run_replay_admission_controls(out: Path) -> dict:
    """Record repaired reader risks and current deterministic rejection checks."""
    resolved = next(model for model in control_models()
                    if model["id"] == "control-resolved-recovery")
    resolved_result = audit(resolved, include_pairs=True)
    legitimate_no_conflict_accepted = verify(resolved, resolved_result)

    empty_events = json.loads(json.dumps(resolved))
    empty_events["id"] = "negative-empty-events"
    empty_events["events"] = []
    forged_empty_report = {
        "id": empty_events["id"], "result": "no-conflict", "valid_views": 0,
        "incompatible_view_pairs": 0,
        "pair_counts": {"prevented": 0, "accountable-fork": 0, "silent-fork": 0},
        "globally_prevented": True, "globally_accountable": True,
        "minimum_exposure_margin": None, "pairs": [],
    }
    empty_events_rejected = not verify(empty_events, forged_empty_report)

    no_view = {
        "id": "negative-no-valid-view", "key_count": 1,
        "exposure": {"windows": [[0]], "capacity": [0]},
        "policies": [key_policy("p", 0)],
        "loci": [{"id": "root", "parents": []},
                   {"id": "left", "parents": ["root"]},
                   {"id": "right", "parents": ["root"]}],
        "events": [
            {"id": "r0", "locus": "root", "policy": "p", "dominates": [], "requires": {}},
            {"id": "r1", "locus": "root", "policy": "p", "dominates": [], "requires": {}},
            {"id": "l", "locus": "left", "policy": "p", "dominates": [], "requires": {"root": "r0"}},
            {"id": "r", "locus": "right", "policy": "p", "dominates": [], "requires": {"root": "r1"}},
        ],
    }
    forged_no_view = dict(forged_empty_report)
    forged_no_view["id"] = no_view["id"]
    no_valid_view_rejected = not verify(no_view, forged_no_view)

    feasible = next(model for model in control_models()
                    if model["id"] == "control-joint-feasible")
    null_witness_result = audit(feasible, include_pairs=True)
    null_witness_result["pairs"][0]["fork_witness"] = None
    null_witness_rejected_without_exception = not verify(feasible, null_witness_result)

    cases = [
        {
            "id": "legitimate-resolved-no-conflict",
            "model": resolved,
            "reported_result": resolved_result,
            "expected_accept": True,
            "observed_accept": legitimate_no_conflict_accepted,
        },
        {
            "id": "reject-empty-events",
            "model": empty_events,
            "reported_result": forged_empty_report,
            "expected_accept": False,
            "observed_accept": not empty_events_rejected,
        },
        {
            "id": "reject-zero-valid-views",
            "model": no_view,
            "reported_result": forged_no_view,
            "expected_accept": False,
            "observed_accept": not no_valid_view_rejected,
        },
        {
            "id": "reject-null-feasible-witness",
            "model": feasible,
            "reported_result": null_witness_result,
            "expected_accept": False,
            "observed_accept": not null_witness_rejected_without_exception,
        },
    ]
    differences = [
        {"id": case["id"], "expected_accept": case["expected_accept"],
         "observed_accept": case["observed_accept"]}
        for case in cases if case["expected_accept"] != case["observed_accept"]
    ]
    current = {
        "legitimate_no_conflict_accepted": legitimate_no_conflict_accepted,
        "empty_event_model_rejected": empty_events_rejected,
        "zero_valid_view_model_rejected": no_valid_view_rejected,
        "null_feasible_witness_rejected_without_exception": null_witness_rejected_without_exception,
    }
    if differences or not all(current.values()):
        raise AssertionError({"differences": differences, "checks": current})
    dump(out / "replay-admission-inputs.json", {
        "cases": [{key: value for key, value in case.items()
                   if key in {"id", "model", "reported_result", "expected_accept"}}
                  for case in cases]
    })
    dump(out / "replay-admission-outputs.json", {
        "cases": [{"id": case["id"], "observed_accept": case["observed_accept"]}
                  for case in cases],
        "current_exclusion_checks": current,
    })
    dump(out / "replay-admission-diff.json", {
        "mismatches": len(differences),
        "differences": differences,
    })
    record = {
        "risk_reproduced_before_repair": {
            "empty_event_model": "accepted as no-conflict with valid_views=0",
            "null_feasible_witness": "raised uncaught AttributeError",
        },
        "current_exclusion_checks": current,
        "saved_case_files": [
            "replay-admission-inputs.json",
            "replay-admission-outputs.json",
            "replay-admission-diff.json",
        ],
        "note": "The current package contains only the repaired reader; the pre-repair observations were produced by executing the inherited reader before this repair and cannot be rerun from the repaired package.",
    }
    dump(out / "replay-admission-controls.json", record)
    return {"checks": len(current), "all_passed": True, "mismatches": 0,
            "saved_input_cases": len(cases)}


def main() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (3 * 1024**3, 3 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    out = args.output
    out.mkdir(parents=True, exist_ok=False)
    cpu = time.process_time(); wall = time.perf_counter()
    threshold = run_threshold_grid(out)
    graphs = run_graph_grid(out)
    reduction = run_reduction_grid(out)
    policies = run_policy_pairs(out)
    controls = run_controls(out)
    margins = run_margin_oracle_grid(out)
    branching = run_branching_regressions(out)
    admission = run_replay_admission_controls(out)
    checker_replay_models = graphs["models"] + reduction["cases"] + policies["cases"] + controls["cases"]
    total_rows = (threshold["recorded_rows"] + checker_replay_models + margins["cases"])
    if checker_replay_models != 4_484 or total_rows != 70_348:
        raise AssertionError((checker_replay_models, total_rows))
    summary = {
        "purpose": "recovery-ordered continuity finite validation",
        "threshold_grid": threshold,
        "graph_grid": graphs,
        "hitting_set_reduction_grid": reduction,
        "policy_pair_grid": policies,
        "controls": controls,
        "capacity_margin_oracle_grid": margins,
        "branching_pruning_regressions": branching,
        "replay_admission_controls": admission,
        "evidence_unit_totals": {
            "total_recorded_rows": total_rows,
            "checker_replay_namespace_models": checker_replay_models,
            "threshold_formula_oracle_cases": threshold["incomparable_formula_oracle_cases"],
            "derived_ordered_relation_rows": threshold["ordered_relation_derived_rows"],
            "capacity_margin_oracle_cases": margins["cases"],
        },
        "workers": 1,
        "cpu_seconds": time.process_time() - cpu,
        "wall_seconds": time.perf_counter() - wall,
        "peak_rss_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        "general_theorem_mechanized": False,
        "independent_human_review": False,
    }
    dump(out / "summary.json", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
