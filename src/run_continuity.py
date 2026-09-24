"""Deterministic campaign for recovery-ordered namespace continuity.

The campaign is finite validation, not a machine-checked general proof.  It uses
one process and four bounded families: an exhaustive three-key threshold grid,
a two-locus delegation/recovery graph grid, a Hitting-Set reduction grid, and
the retained monotone-policy sample.
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
from continuity_replay import oracle, verify
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
    n = 3
    windows = [(0,), (1,), (0, 1)]
    subsets = [tuple(i for i in range(n) if mask & (1 << i)) for mask in range(1, 1 << n)]
    counts = {"no-conflict": 0, "prevented": 0, "accountable-fork": 0, "silent-fork": 0}
    mismatches = 0
    rows = 0
    incomparable_margins: Counter = Counter()
    with (out / "threshold-triage.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["windows", "capacity", "left_committee", "right_committee", "left_q", "right_q",
                         "relation", "classification", "oracle_classification"])
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
                                mismatches += 1
                            for relation in ("incomparable", "right-over-left", "left-over-right"):
                                predicted = formula_class if relation == "incomparable" else "no-conflict"
                                expected = oracle_class if relation == "incomparable" else "no-conflict"
                                if predicted != expected:
                                    mismatches += 1
                                counts[predicted] += 1; rows += 1
                                writer.writerow([json.dumps(ws, separators=(",", ":")), json.dumps(caps),
                                                 json.dumps(left), json.dumps(right), ql, qr, relation,
                                                 predicted, expected])
    if rows != 46_656:
        raise AssertionError(rows)
    return {"cases": rows, "counts": counts, "mismatches": mismatches,
            "incomparable_exposure_margin_histogram": stable_histogram(incomparable_margins)}


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
    if model_count != 3456:
        raise AssertionError(model_count)
    class_margin_rows = {
        f"{classification}|{margin}": count
        for (classification, margin), count in sorted(pair_class_margins.items())
    }
    return {"models": model_count, "result_counts": result_counts,
            "incompatible_view_pairs": pair_total, "joint_exposure_blocked_pairs": joint_blocked,
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
    rows = []
    margins: Counter = Counter()
    for raw in control_models():
        result = audit(raw, include_pairs=True)
        if result["result"] != expected[raw["id"]] or not verify(raw, result):
            raise AssertionError((raw, result))
        rows.append({"model": raw, "result": result})
        margins[result["minimum_exposure_margin"]] += 1
    dump(out / "continuity-controls.json", rows)
    return {"cases": len(rows), "expected_results_equal": True,
            "exposure_margin_histogram": stable_histogram(margins)}


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
    summary = {
        "purpose": "recovery-ordered continuity finite validation",
        "threshold_grid": threshold,
        "graph_grid": graphs,
        "hitting_set_reduction_grid": reduction,
        "policy_pair_grid": policies,
        "controls": controls,
        "capacity_margin_oracle_grid": margins,
        "total_primary_cases": threshold["cases"] + graphs["models"] + reduction["cases"] + policies["cases"] + controls["cases"] + margins["cases"],
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
