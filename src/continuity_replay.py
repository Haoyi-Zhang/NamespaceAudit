"""Independent direct oracle for recovery-ordered namespace audits.

This module intentionally does not import continuity.py, finite_model.py, or the
matching implementation.  It evaluates policy truth tables, enumerates temporal
exposure sets slot by slot, enumerates valid views, and checks reported pair
classifications directly.  Its admitted replay bound is eight distinct keys.
"""
from __future__ import annotations

from itertools import combinations, product
import argparse
import json
import resource
from pathlib import Path

MAX_REPLAY_KEYS = 8
MAX_LINES = 10000
MAX_LINE = 256 * 1024


def _policy_value(nodes: list[dict], root: int, keys: set[int]) -> bool:
    values: list[bool] = []
    for node in nodes:
        if node["op"] == "key":
            values.append(node["key"] in keys)
        else:
            values.append(sum(values[i] for i in node["children"]) >= node["k"])
    return values[root]


def _minimal_supports(policy: dict, key_count: int) -> tuple[tuple[int, ...], ...]:
    result = []
    for mask in range(1 << key_count):
        keys = {i for i in range(key_count) if mask & (1 << i)}
        if not _policy_value(policy["nodes"], policy["root"], keys):
            continue
        if any(_policy_value(policy["nodes"], policy["root"], keys - {i}) for i in keys):
            continue
        result.append(tuple(sorted(keys)))
    return tuple(sorted(result, key=lambda x: (len(x), x)))


def _exposed_sets(raw: dict) -> set[int]:
    key_count = raw["key_count"]
    windows = raw["exposure"]["windows"]
    capacity = raw["exposure"]["capacity"]
    states = {0}
    for slot, cap in enumerate(capacity):
        active = [k for k in range(key_count) if slot in windows[k]]
        choices = [sum(1 << k for k in subset)
                   for size in range(min(cap, len(active)) + 1)
                   for subset in combinations(active, size)]
        states = {old | choice for old in states for choice in choices}
    return states


def _closure(raw: dict) -> set[tuple[str, str]]:
    events = raw["events"]
    relation = {(e["id"], e["id"]) for e in events}
    relation.update((e["id"], old) for e in events for old in e["dominates"])
    changed = True
    while changed:
        changed = False
        snapshot = tuple(relation)
        for a, b in snapshot:
            for c, d in snapshot:
                if b == c and (a, d) not in relation:
                    relation.add((a, d)); changed = True
    return relation


def _valid_views(raw: dict, relation: set[tuple[str, str]]) -> tuple[tuple[str, ...], ...]:
    loci = raw["loci"]
    events = raw["events"]
    by_locus = {l["id"]: [e["id"] for e in events if e["locus"] == l["id"]] for l in loci}
    event_by_name = {e["id"]: e for e in events}
    result = []
    for selection in product(*(by_locus[l["id"]] for l in loci)):
        chosen = {l["id"]: event for l, event in zip(loci, selection)}
        valid = True
        for event_name in selection:
            for parent, required in event_by_name[event_name]["requires"].items():
                if (chosen[parent], required) not in relation:
                    valid = False; break
            if not valid: break
        if valid: result.append(tuple(selection))
    return tuple(result)


def _minimal_masks(rows: dict[int, tuple]) -> dict[int, tuple]:
    keep = {}
    for mask in sorted(rows, key=lambda m: (m.bit_count(), m)):
        if any((old & mask) == old for old in keep):
            continue
        keep[mask] = rows[mask]
    return keep


def _exposure_analysis(mask: int, raw: dict, exposed: set[int]) -> dict:
    key_count = raw["key_count"]
    keys = tuple(k for k in range(key_count) if mask & (1 << k))
    matching_size = max(((state & mask).bit_count() for state in exposed), default=0)
    deficit = len(keys) - matching_size
    best = None
    for submask in range(1, 1 << len(keys)):
        subset = tuple(keys[i] for i in range(len(keys)) if submask & (1 << i))
        slots = tuple(sorted({t for k in subset for t in raw["exposure"]["windows"][k]}))
        available = sum(raw["exposure"]["capacity"][t] for t in slots)
        shortfall = len(subset) - available
        if shortfall <= 0:
            continue
        candidate = (shortfall, -len(subset), tuple(-k for k in subset), slots, available)
        if best is None or candidate > best:
            best = candidate
    if deficit == 0:
        obstruction = None
    else:
        if best is None or best[0] != deficit:
            raise AssertionError("direct exposure enumeration disagrees with Hall deficiency")
        shortfall, _, neg_subset, slots, available = best
        subset = tuple(-k for k in neg_subset)
        obstruction = {"keys": list(subset), "slots": list(slots),
                       "demand": len(subset), "capacity": available,
                       "deficit": shortfall}
    return {"forced_keys": list(keys), "matching_size": matching_size,
            "exposure_deficit": deficit, "hall_obstruction": obstruction}


def _valid_exposure_schedule(raw: dict, forced: list[int], schedule: object) -> bool:
    if not isinstance(schedule, list):
        return False
    used = set(); counts = [0] * len(raw["exposure"]["capacity"])
    for item in schedule:
        if not isinstance(item, list) or len(item) != 2:
            return False
        key, slot = item
        if type(key) is not int or type(slot) is not int or key in used or key not in forced:
            return False
        if slot not in raw["exposure"]["windows"][key]:
            return False
        used.add(key); counts[slot] += 1
    return used == set(forced) and all(a <= b for a, b in zip(counts, raw["exposure"]["capacity"]))


def _valid_support_witness(raw: dict, row: dict, supports: dict[str, tuple[tuple[int, ...], ...]],
                           event_by_name: dict[str, dict], loci: list[dict]) -> bool:
    witness = row.get("fork_witness")
    if not isinstance(witness, dict) or set(witness) != {"forced_keys", "exposures", "supports"}:
        return False
    forced = witness["forced_keys"]
    if forced != sorted(set(forced)) or any(type(k) is not int or not 0 <= k < raw["key_count"] for k in forced):
        return False
    if not _valid_exposure_schedule(raw, forced, witness["exposures"]):
        return False
    entries = witness["supports"]
    if not isinstance(entries, list) or len(entries) != len(row["conflict_loci"]):
        return False
    union = set()
    for expected_locus, entry in zip(row["conflict_loci"], entries):
        if not isinstance(entry, dict) or set(entry) != {"locus", "left_event", "right_event", "left_support", "right_support"}:
            return False
        if entry["locus"] != expected_locus:
            return False
        index = next((i for i, locus in enumerate(loci) if locus["id"] == expected_locus), None)
        if index is None or entry["left_event"] != row["left_view"][index] or entry["right_event"] != row["right_view"][index]:
            return False
        left_event = event_by_name[entry["left_event"]]
        right_event = event_by_name[entry["right_event"]]
        left_support = tuple(entry["left_support"]) if isinstance(entry["left_support"], list) else None
        right_support = tuple(entry["right_support"]) if isinstance(entry["right_support"], list) else None
        if left_support not in supports[left_event["policy"]] or right_support not in supports[right_event["policy"]]:
            return False
        union.update(set(left_support).intersection(right_support))
    return sorted(union) == forced


def oracle(raw: dict, include_pairs: bool = True) -> dict:
    key_count = raw["key_count"]
    if type(key_count) is not int or not 1 <= key_count <= MAX_REPLAY_KEYS:
        raise ValueError("independent replay admits 1..8 keys")
    relation = _closure(raw)
    loci = raw["loci"]
    event_by_name = {e["id"]: e for e in raw["events"]}
    policy_by_name = {p["id"]: p for p in raw["policies"]}
    supports = {name: _minimal_supports(policy, key_count) for name, policy in policy_by_name.items()}
    exposed = _exposed_sets(raw)
    views = _valid_views(raw, relation)
    rows = []
    counts = {"prevented": 0, "accountable-fork": 0, "silent-fork": 0}
    for i, left in enumerate(views):
        for right in views[i + 1:]:
            conflicts = [j for j, (a, b) in enumerate(zip(left, right))
                         if (a, b) not in relation and (b, a) not in relation]
            if not conflicts:
                continue
            states = {0: tuple()}
            option_counts = []
            for index in conflicts:
                le = event_by_name[left[index]]; re = event_by_name[right[index]]
                options = {}
                for ls in supports[le["policy"]]:
                    for rs in supports[re["policy"]]:
                        mask = sum(1 << k for k in set(ls).intersection(rs))
                        witness = (ls, rs)
                        if mask not in options or witness < options[mask]:
                            options[mask] = witness
                options = _minimal_masks(options)
                option_counts.append(len(options))
                merged = {}
                for current, witness_rows in states.items():
                    for intersection, support_pair in options.items():
                        mask = current | intersection
                        witness = witness_rows + ((index,) + support_pair,)
                        if mask not in merged or witness < merged[mask]:
                            merged[mask] = witness
                states = _minimal_masks(merged)
            analyses = [(mask.bit_count(), mask, _exposure_analysis(mask, raw, exposed))
                        for mask in states]
            analyses.sort()
            feasible = sorted(mask for mask in states if any((mask & state) == mask for state in exposed))
            accountable = 0 not in states
            if feasible:
                classification = "accountable-fork" if accountable else "silent-fork"
            else:
                classification = "prevented"
            counts[classification] += 1
            row = {
                "left_view": list(left),
                "right_view": list(right),
                "conflict_loci": [loci[j]["id"] for j in conflicts],
                "option_counts": option_counts,
                "minimal_forced_sets": [[k for k in range(key_count) if mask & (1 << k)]
                                        for mask in sorted(states, key=lambda m: (m.bit_count(), m))],
                "forced_set_analysis": [entry[2] for entry in analyses],
                "exposure_margin": min(entry[2]["exposure_deficit"] for entry in analyses),
                "classification": classification,
                "accountable": accountable,
            }
            if feasible:
                best = min(feasible, key=lambda m: (m.bit_count(), m))
                row["minimal_forced_keys"] = [k for k in range(key_count) if best & (1 << k)]
            rows.append(row)
    if not sum(counts.values()):
        result = "no-conflict"
    elif counts["silent-fork"]:
        result = "silent-fork"
    elif counts["accountable-fork"]:
        result = "accountable-fork"
    else:
        result = "prevented"
    output = {
        "id": raw["id"],
        "result": result,
        "valid_views": len(views),
        "incompatible_view_pairs": sum(counts.values()),
        "pair_counts": counts,
        "globally_prevented": result in {"prevented", "no-conflict"},
        "globally_accountable": counts["silent-fork"] == 0,
        "minimum_exposure_margin": min((row["exposure_margin"] for row in rows), default=None),
    }
    if include_pairs:
        output["pairs"] = rows
    return output


def verify(raw: dict, reported: dict) -> bool:
    try:
        expected = oracle(raw, include_pairs=True)
        top_keys = {"id", "result", "valid_views", "incompatible_view_pairs", "pair_counts",
                    "globally_prevented", "globally_accountable", "minimum_exposure_margin",
                    "pairs"}
        if any(row["classification"] != "prevented" for row in expected["pairs"]):
            top_keys.add("minimal_fork_witness")
        if not isinstance(reported, dict) or set(reported) != top_keys:
            return False
        for key in ["id", "result", "valid_views", "incompatible_view_pairs", "pair_counts",
                    "globally_prevented", "globally_accountable", "minimum_exposure_margin"]:
            if reported.get(key) != expected[key]:
                return False
        got_pairs = reported.get("pairs")
        if not isinstance(got_pairs, list) or len(got_pairs) != len(expected["pairs"]):
            return False
        event_by_name = {e["id"]: e for e in raw["events"]}
        policy_by_name = {p["id"]: p for p in raw["policies"]}
        supports = {name: _minimal_supports(policy, raw["key_count"])
                    for name, policy in policy_by_name.items()}
        feasible_pairs = []
        for got, want in zip(got_pairs, expected["pairs"]):
            pair_keys = {"left_view", "right_view", "conflict_loci", "option_counts",
                         "minimal_forced_sets", "forced_set_analysis", "exposure_margin",
                         "classification", "accountable", "fork_witness"}
            if not isinstance(got, dict) or set(got) != pair_keys:
                return False
            for key in ["left_view", "right_view", "conflict_loci", "option_counts",
                        "minimal_forced_sets", "forced_set_analysis", "exposure_margin",
                        "classification", "accountable"]:
                if got.get(key) != want[key]:
                    return False
            if want["classification"] != "prevented":
                if got["fork_witness"].get("forced_keys") != want["minimal_forced_keys"]:
                    return False
                if not _valid_support_witness(raw, got, supports, event_by_name, raw["loci"]):
                    return False
                feasible_pairs.append(got)
            elif got["fork_witness"] is not None:
                return False
        if feasible_pairs:
            feasible_pairs.sort(key=lambda row: (len(row["fork_witness"]["forced_keys"]),
                                                 len(row["conflict_loci"]),
                                                 row["left_view"], row["right_view"]))
            if reported.get("minimal_fork_witness") != feasible_pairs[0]:
                return False
        return True
    except (KeyError, TypeError, ValueError, IndexError, StopIteration, AssertionError):
        return False


def main() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (3 * 1024**3, 3 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("models", type=Path)
    ap.add_argument("results", type=Path)
    args = ap.parse_args()
    count = 0
    with args.models.open("rb") as models, args.results.open("rb") as results:
        while True:
            a = models.readline(MAX_LINE + 1); b = results.readline(MAX_LINE + 1)
            if not a and not b: break
            if not a or not b: raise SystemExit("different model/result counts")
            if len(a) > MAX_LINE or len(b) > MAX_LINE: raise SystemExit("line exceeds replay bound")
            if count >= MAX_LINES: raise SystemExit("batch exceeds replay bound")
            try:
                raw = json.loads(a); reported = json.loads(b)
            except (ValueError, UnicodeError) as exc:
                raise SystemExit("invalid JSON: " + str(exc))
            if not verify(raw, reported):
                raise SystemExit("continuity result rejected at line " + str(count + 1))
            count += 1
    print(json.dumps({"accepted_models": count, "reader_imports_analyzer": False}))


if __name__ == "__main__":
    main()
