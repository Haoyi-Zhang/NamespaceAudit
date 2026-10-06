"""Independent direct oracle for recovery-ordered namespace audits.

This module intentionally imports neither continuity.py nor finite_model.py.  It
performs its own bounded model admission, evaluates policy truth tables,
enumerates valid views and temporal exposure sets, and verifies reported
results.  For each incompatible view pair it enumerates the full Cartesian
product of support-pair choices across all conflict loci and applies subset
minimalization only once at the end.  It therefore does not reuse the main
checker's local-intersection pruning or layer-by-layer union-antichain dynamic
program.  The admitted replay bound is eight distinct keys.
"""
from __future__ import annotations

from itertools import combinations, product
import argparse
import json
import resource
from pathlib import Path
from typing import Iterable

MAX_REPLAY_KEYS = 8
MAX_LINES = 10_000
MAX_LINE = 256 * 1024
MAX_SLOTS = 12
MAX_POLICIES = 32
MAX_POLICY_NODES = 64
MAX_LOCI = 8
MAX_EVENTS = 32
MAX_EVENTS_PER_LOCUS = 8
MAX_VIEW_CANDIDATES = 100_000
MAX_DIRECT_SUPPORT_COMBINATIONS = 1_000_000


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


def _validate_model_structure(raw: object) -> None:
    """Mirror the analyzer's finite admission checks without importing it."""
    required = {"id", "key_count", "exposure", "policies", "loci", "events"}
    if not isinstance(raw, dict) or set(raw) != required:
        raise ValueError("model must contain exactly id/key_count/exposure/policies/loci/events")

    name = raw["id"]
    if not isinstance(name, str) or not name or len(name) > 100:
        raise ValueError("invalid model identifier")
    key_count = raw["key_count"]
    if type(key_count) is not int or not 1 <= key_count <= MAX_REPLAY_KEYS:
        raise ValueError("independent replay admits 1..8 keys")

    exposure = raw["exposure"]
    if not isinstance(exposure, dict) or set(exposure) != {"windows", "capacity"}:
        raise ValueError("exposure must contain exactly windows/capacity")
    capacity = exposure["capacity"]
    windows = exposure["windows"]
    if not isinstance(capacity, list) or not 1 <= len(capacity) <= MAX_SLOTS:
        raise ValueError("invalid exposure horizon")
    if any(type(value) is not int or not 0 <= value <= 12 for value in capacity):
        raise ValueError("invalid exposure capacity")
    if not isinstance(windows, list) or len(windows) != key_count:
        raise ValueError("one exposure window is required per key")
    for item in windows:
        if not isinstance(item, list) or not item:
            raise ValueError("exposure windows must be nonempty lists")
        if item != sorted(set(item)):
            raise ValueError("exposure slots must be strictly increasing")
        if any(type(slot) is not int or not 0 <= slot < len(capacity) for slot in item):
            raise ValueError("exposure slot outside horizon")

    policies = raw["policies"]
    if not isinstance(policies, list) or not 1 <= len(policies) <= MAX_POLICIES:
        raise ValueError("invalid policy count")
    policy_names: set[str] = set()
    for policy in policies:
        if not isinstance(policy, dict) or set(policy) != {"id", "nodes", "root"}:
            raise ValueError("policy must contain exactly id/nodes/root")
        pid = policy["id"]
        nodes = policy["nodes"]
        root = policy["root"]
        if not isinstance(pid, str) or not pid or len(pid) > 80 or pid in policy_names:
            raise ValueError("invalid or duplicate policy id")
        if not isinstance(nodes, list) or not 1 <= len(nodes) <= MAX_POLICY_NODES:
            raise ValueError("invalid policy node count")
        if type(root) is not int or not 0 <= root < len(nodes):
            raise ValueError("invalid policy root")
        for index, node in enumerate(nodes):
            if not isinstance(node, dict):
                raise ValueError("policy node must be an object")
            if node.get("op") == "key":
                if set(node) != {"op", "key"} or type(node["key"]) is not int or not 0 <= node["key"] < key_count:
                    raise ValueError("invalid key leaf")
            elif node.get("op") == "threshold":
                if set(node) != {"op", "k", "children"}:
                    raise ValueError("invalid threshold node")
                children = node["children"]
                threshold = node["k"]
                if (not isinstance(children, list) or not children or
                        any(type(child) is not int or not 0 <= child < index for child in children) or
                        len(set(children)) != len(children)):
                    raise ValueError("children must be distinct preceding nodes")
                if type(threshold) is not int or not 1 <= threshold <= len(children):
                    raise ValueError("invalid gate threshold")
            else:
                raise ValueError("unknown policy node")
        # Re-evaluation is intentional: it validates index use and fixes the
        # replay's policy semantics independently of the analyzer's compiler.
        _minimal_supports(policy, key_count)
        policy_names.add(pid)

    loci = raw["loci"]
    if not isinstance(loci, list) or not 1 <= len(loci) <= MAX_LOCI:
        raise ValueError("invalid locus count")
    locus_names: set[str] = set()
    locus_parents: dict[str, tuple[str, ...]] = {}
    for locus in loci:
        if not isinstance(locus, dict) or set(locus) != {"id", "parents"}:
            raise ValueError("locus must contain exactly id/parents")
        lid = locus["id"]
        parents = locus["parents"]
        if not isinstance(lid, str) or not lid or len(lid) > 80 or lid in locus_names:
            raise ValueError("invalid or duplicate locus id")
        if not isinstance(parents, list) or parents != sorted(set(parents)):
            raise ValueError("locus parents must be a sorted distinct list")
        if any(not isinstance(parent, str) or parent not in locus_names for parent in parents):
            raise ValueError("locus parents must precede the child")
        locus_names.add(lid)
        locus_parents[lid] = tuple(parents)

    events = raw["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise ValueError("invalid event count")
    event_names: set[str] = set()
    event_locus: dict[str, str] = {}
    per_locus = {lid: 0 for lid in locus_names}
    for event in events:
        fields = {"id", "locus", "policy", "dominates", "requires"}
        if not isinstance(event, dict) or set(event) != fields:
            raise ValueError("event must contain exactly id/locus/policy/dominates/requires")
        eid = event["id"]
        lid = event["locus"]
        pid = event["policy"]
        dominates = event["dominates"]
        requires = event["requires"]
        if not isinstance(eid, str) or not eid or len(eid) > 80 or eid in event_names:
            raise ValueError("invalid or duplicate event id")
        if not isinstance(lid, str) or lid not in locus_names or not isinstance(pid, str) or pid not in policy_names:
            raise ValueError("unknown event locus or policy")
        if not isinstance(dominates, list) or dominates != sorted(set(dominates)):
            raise ValueError("dominates must be a sorted distinct list")
        if any(not isinstance(old, str) or old not in event_names or event_locus[old] != lid for old in dominates):
            raise ValueError("dominance edges must point to preceding events at the same locus")
        if not isinstance(requires, dict):
            raise ValueError("requires must be an object")
        if set(requires) - set(locus_parents[lid]):
            raise ValueError("requirements may name only declared parent loci")
        for parent, target in requires.items():
            if (not isinstance(parent, str) or not isinstance(target, str) or
                    target not in event_names or event_locus[target] != parent):
                raise ValueError("requirement must name a preceding event at the parent locus")
        event_names.add(eid)
        event_locus[eid] = lid
        per_locus[lid] += 1
    if any(count == 0 or count > MAX_EVENTS_PER_LOCUS for count in per_locus.values()):
        raise ValueError("each locus needs 1..8 events")
    candidate_count = 1
    for count in per_locus.values():
        candidate_count *= count
    if candidate_count > MAX_VIEW_CANDIDATES:
        raise ValueError("view product exceeds finite checker bound")


def _exposed_sets(raw: dict) -> set[int]:
    key_count = raw["key_count"]
    windows = raw["exposure"]["windows"]
    capacity = raw["exposure"]["capacity"]
    states = {0}
    for slot, cap in enumerate(capacity):
        active = [key for key in range(key_count) if slot in windows[key]]
        choices = [sum(1 << key for key in subset)
                   for size in range(min(cap, len(active)) + 1)
                   for subset in combinations(active, size)]
        states = {old | choice for old in states for choice in choices}
    return states


def _closure(raw: dict) -> set[tuple[str, str]]:
    events = raw["events"]
    relation = {(event["id"], event["id"]) for event in events}
    relation.update((event["id"], old) for event in events for old in event["dominates"])
    changed = True
    while changed:
        changed = False
        snapshot = tuple(relation)
        for left, middle in snapshot:
            for middle2, right in snapshot:
                if middle == middle2 and (left, right) not in relation:
                    relation.add((left, right))
                    changed = True
    for left, right in relation:
        if left != right and (right, left) in relation:
            raise ValueError("dominance relation is cyclic")
    return relation


def _valid_views(raw: dict, relation: set[tuple[str, str]]) -> tuple[tuple[str, ...], ...]:
    loci = raw["loci"]
    events = raw["events"]
    by_locus = {locus["id"]: [event["id"] for event in events if event["locus"] == locus["id"]]
                for locus in loci}
    event_by_name = {event["id"]: event for event in events}
    result = []
    for selection in product(*(by_locus[locus["id"]] for locus in loci)):
        chosen = {locus["id"]: event for locus, event in zip(loci, selection)}
        valid = True
        for event_name in selection:
            for parent, required in event_by_name[event_name]["requires"].items():
                if (chosen[parent], required) not in relation:
                    valid = False
                    break
            if not valid:
                break
        if valid:
            result.append(tuple(selection))
    if not result:
        raise ValueError("model has no valid namespace view")
    return tuple(result)


def _final_minimal_masks(masks: Iterable[int]) -> tuple[int, ...]:
    """All-pairs final minimalization, with no incremental antichain pruning."""
    unique = set(masks)
    return tuple(sorted(
        (mask for mask in unique
         if not any(other != mask and (other & mask) == other for other in unique)),
        key=lambda mask: (mask.bit_count(), mask),
    ))


def direct_union_antichain(local_families: object) -> dict:
    """Enumerate all unions and minimalize once; used by targeted regressions."""
    if not isinstance(local_families, (list, tuple)) or not local_families:
        raise ValueError("at least one local family is required")
    normalized: list[tuple[int, ...]] = []
    max_key = -1
    combinations_count = 1
    for family in local_families:
        if not isinstance(family, (list, tuple)) or not family:
            raise ValueError("each local family must be nonempty")
        masks = []
        for option in family:
            if not isinstance(option, (list, tuple, set, frozenset)):
                raise ValueError("local option must be a key collection")
            keys = tuple(option)
            if any(type(key) is not int or key < 0 for key in keys) or len(set(keys)) != len(keys):
                raise ValueError("local option keys must be distinct nonnegative integers")
            mask = 0
            for key in keys:
                max_key = max(max_key, key)
                mask |= 1 << key
            masks.append(mask)
        normalized.append(tuple(masks))
        combinations_count *= len(masks)
    if combinations_count > MAX_DIRECT_SUPPORT_COMBINATIONS:
        raise ValueError("direct support combination bound exceeded")
    all_unions = []
    for choices in product(*normalized):
        union = 0
        for mask in choices:
            union |= mask
        all_unions.append(union)
    minimal = _final_minimal_masks(all_unions)
    key_count = max_key + 1
    return {
        "raw_combination_count": combinations_count,
        "distinct_union_count": len(set(all_unions)),
        "minimal_sets": [[key for key in range(key_count) if mask & (1 << key)] for mask in minimal],
    }


def _direct_pair_states(
    raw: dict,
    left: tuple[str, ...],
    right: tuple[str, ...],
    conflicts: list[int],
    supports: dict[str, tuple[tuple[int, ...], ...]],
    event_by_name: dict[str, dict],
) -> tuple[dict[int, tuple], list[int], dict]:
    """Full support-choice product followed by one final minimalization."""
    local_options: list[tuple[tuple[int, tuple[int, ...], tuple[int, ...]], ...]] = []
    option_counts: list[int] = []
    local_raw_counts: list[int] = []
    combination_count = 1
    for index in conflicts:
        left_event = event_by_name[left[index]]
        right_event = event_by_name[right[index]]
        options = []
        local_masks = []
        for left_support in supports[left_event["policy"]]:
            for right_support in supports[right_event["policy"]]:
                common = set(left_support).intersection(right_support)
                mask = sum(1 << key for key in common)
                options.append((mask, left_support, right_support))
                local_masks.append(mask)
        if not options:
            raise ValueError("policy pair has no support combination")
        local_options.append(tuple(options))
        local_raw_counts.append(len(options))
        option_counts.append(len(_final_minimal_masks(local_masks)))
        combination_count *= len(options)
    if combination_count > MAX_DIRECT_SUPPORT_COMBINATIONS:
        raise ValueError("direct support combination bound exceeded")

    all_rows: dict[int, tuple] = {}
    for choices in product(*local_options):
        mask = 0
        witness = []
        for index, (intersection, left_support, right_support) in zip(conflicts, choices):
            mask |= intersection
            witness.append((index, left_support, right_support))
        witness_tuple = tuple(witness)
        if mask not in all_rows or witness_tuple < all_rows[mask]:
            all_rows[mask] = witness_tuple
    minimal_masks = _final_minimal_masks(all_rows)
    states = {mask: all_rows[mask] for mask in minimal_masks}
    stats = {
        "local_raw_support_pair_counts": local_raw_counts,
        "raw_cartesian_combinations": combination_count,
        "distinct_union_count": len(all_rows),
        "final_minimal_set_count": len(states),
        "layerwise_union_pruning": False,
    }
    return states, option_counts, stats


def _exposure_analysis(mask: int, raw: dict, exposed: set[int]) -> dict:
    key_count = raw["key_count"]
    keys = tuple(key for key in range(key_count) if mask & (1 << key))
    matching_size = max(((state & mask).bit_count() for state in exposed), default=0)
    deficit = len(keys) - matching_size
    best = None
    for submask in range(1, 1 << len(keys)):
        subset = tuple(keys[index] for index in range(len(keys)) if submask & (1 << index))
        slots = tuple(sorted({slot for key in subset for slot in raw["exposure"]["windows"][key]}))
        available = sum(raw["exposure"]["capacity"][slot] for slot in slots)
        shortfall = len(subset) - available
        if shortfall <= 0:
            continue
        candidate = (shortfall, -len(subset), tuple(-key for key in subset), slots, available)
        if best is None or candidate > best:
            best = candidate
    if deficit == 0:
        obstruction = None
    else:
        if best is None or best[0] != deficit:
            raise AssertionError("direct exposure enumeration disagrees with Hall deficiency")
        shortfall, _, neg_subset, slots, available = best
        subset = tuple(-key for key in neg_subset)
        obstruction = {
            "keys": list(subset),
            "slots": list(slots),
            "demand": len(subset),
            "capacity": available,
            "deficit": shortfall,
        }
    return {
        "forced_keys": list(keys),
        "matching_size": matching_size,
        "exposure_deficit": deficit,
        "hall_obstruction": obstruction,
    }


def _valid_exposure_schedule(raw: dict, forced: object, schedule: object) -> bool:
    if not isinstance(forced, list) or any(type(key) is not int for key in forced):
        return False
    if forced != sorted(set(forced)) or any(not 0 <= key < raw["key_count"] for key in forced):
        return False
    if not isinstance(schedule, list):
        return False
    used = set()
    counts = [0] * len(raw["exposure"]["capacity"])
    for item in schedule:
        if not isinstance(item, list) or len(item) != 2:
            return False
        key, slot = item
        if type(key) is not int or type(slot) is not int or key in used or key not in forced:
            return False
        if not 0 <= slot < len(counts) or slot not in raw["exposure"]["windows"][key]:
            return False
        used.add(key)
        counts[slot] += 1
    return used == set(forced) and all(used_count <= limit for used_count, limit in zip(counts, raw["exposure"]["capacity"]))


def _valid_support_witness(
    raw: dict,
    row: dict,
    supports: dict[str, tuple[tuple[int, ...], ...]],
    event_by_name: dict[str, dict],
    loci: list[dict],
) -> bool:
    witness = row.get("fork_witness")
    if not isinstance(witness, dict) or set(witness) != {"forced_keys", "exposures", "supports"}:
        return False
    forced = witness["forced_keys"]
    if not _valid_exposure_schedule(raw, forced, witness["exposures"]):
        return False
    entries = witness["supports"]
    conflicts = row.get("conflict_loci")
    left_view = row.get("left_view")
    right_view = row.get("right_view")
    if (not isinstance(entries, list) or not isinstance(conflicts, list) or
            not isinstance(left_view, list) or not isinstance(right_view, list) or
            len(entries) != len(conflicts)):
        return False
    union = set()
    locus_index = {locus["id"]: index for index, locus in enumerate(loci)}
    for expected_locus, entry in zip(conflicts, entries):
        required_fields = {"locus", "left_event", "right_event", "left_support", "right_support"}
        if not isinstance(entry, dict) or set(entry) != required_fields:
            return False
        if entry["locus"] != expected_locus or expected_locus not in locus_index:
            return False
        index = locus_index[expected_locus]
        if index >= len(left_view) or index >= len(right_view):
            return False
        if entry["left_event"] != left_view[index] or entry["right_event"] != right_view[index]:
            return False
        if entry["left_event"] not in event_by_name or entry["right_event"] not in event_by_name:
            return False
        left_event = event_by_name[entry["left_event"]]
        right_event = event_by_name[entry["right_event"]]
        if not isinstance(entry["left_support"], list) or not isinstance(entry["right_support"], list):
            return False
        if any(type(key) is not int for key in entry["left_support"] + entry["right_support"]):
            return False
        left_support = tuple(entry["left_support"])
        right_support = tuple(entry["right_support"])
        if left_support not in supports[left_event["policy"]] or right_support not in supports[right_event["policy"]]:
            return False
        union.update(set(left_support).intersection(right_support))
    return sorted(union) == forced


def oracle(raw: dict, include_pairs: bool = True) -> dict:
    _validate_model_structure(raw)
    relation = _closure(raw)
    loci = raw["loci"]
    event_by_name = {event["id"]: event for event in raw["events"]}
    policy_by_name = {policy["id"]: policy for policy in raw["policies"]}
    supports = {name: _minimal_supports(policy, raw["key_count"])
                for name, policy in policy_by_name.items()}
    exposed = _exposed_sets(raw)
    views = _valid_views(raw, relation)
    rows = []
    counts = {"prevented": 0, "accountable-fork": 0, "silent-fork": 0}
    for left_index, left in enumerate(views):
        for right in views[left_index + 1:]:
            conflicts = [
                index for index, (left_event, right_event) in enumerate(zip(left, right))
                if (left_event, right_event) not in relation and (right_event, left_event) not in relation
            ]
            if not conflicts:
                continue
            states, option_counts, _ = _direct_pair_states(
                raw, left, right, conflicts, supports, event_by_name
            )
            analyses = [
                (mask.bit_count(), mask, _exposure_analysis(mask, raw, exposed))
                for mask in states
            ]
            analyses.sort()
            feasible = sorted(
                (mask for mask in states if any((mask & state) == mask for state in exposed)),
                key=lambda mask: (mask.bit_count(), mask),
            )
            accountable = 0 not in states
            if feasible:
                classification = "accountable-fork" if accountable else "silent-fork"
            else:
                classification = "prevented"
            counts[classification] += 1
            row = {
                "left_view": list(left),
                "right_view": list(right),
                "conflict_loci": [loci[index]["id"] for index in conflicts],
                "option_counts": option_counts,
                "minimal_forced_sets": [
                    [key for key in range(raw["key_count"]) if mask & (1 << key)]
                    for mask in states
                ],
                "forced_set_analysis": [entry[2] for entry in analyses],
                "exposure_margin": min(entry[2]["exposure_deficit"] for entry in analyses),
                "classification": classification,
                "accountable": accountable,
            }
            if feasible:
                best = feasible[0]
                row["minimal_forced_keys"] = [
                    key for key in range(raw["key_count"]) if best & (1 << key)
                ]
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


def _same_json_value(got: object, want: object) -> bool:
    """Compare JSON values without Python's bool/int/float coercion.

    Numeric equality alone is insufficient for this result schema: key indices,
    counts, and deficits are integers, while accountability flags are booleans.
    Recurse through evidence rows so their nested fields obey the same rule.
    """
    if type(got) is not type(want):
        return False
    if isinstance(want, dict):
        return set(got) == set(want) and all(
            _same_json_value(got[key], value) for key, value in want.items()
        )
    if isinstance(want, list):
        return len(got) == len(want) and all(
            _same_json_value(left, right) for left, right in zip(got, want)
        )
    return got == want


def verify(raw: dict, reported: dict) -> bool:
    try:
        expected = oracle(raw, include_pairs=True)
        top_keys = {
            "id", "result", "valid_views", "incompatible_view_pairs", "pair_counts",
            "globally_prevented", "globally_accountable", "minimum_exposure_margin", "pairs",
        }
        if any(row["classification"] != "prevented" for row in expected["pairs"]):
            top_keys.add("minimal_fork_witness")
        if not isinstance(reported, dict) or set(reported) != top_keys:
            return False
        for key in [
            "id", "result", "valid_views", "incompatible_view_pairs", "pair_counts",
            "globally_prevented", "globally_accountable", "minimum_exposure_margin",
        ]:
            if not _same_json_value(reported.get(key), expected[key]):
                return False
        got_pairs = reported.get("pairs")
        if not isinstance(got_pairs, list) or len(got_pairs) != len(expected["pairs"]):
            return False
        event_by_name = {event["id"]: event for event in raw["events"]}
        policy_by_name = {policy["id"]: policy for policy in raw["policies"]}
        supports = {name: _minimal_supports(policy, raw["key_count"])
                    for name, policy in policy_by_name.items()}
        feasible_pairs = []
        for got, want in zip(got_pairs, expected["pairs"]):
            pair_keys = {
                "left_view", "right_view", "conflict_loci", "option_counts",
                "minimal_forced_sets", "forced_set_analysis", "exposure_margin",
                "classification", "accountable", "fork_witness",
            }
            if not isinstance(got, dict) or set(got) != pair_keys:
                return False
            for key in [
                "left_view", "right_view", "conflict_loci", "option_counts",
                "minimal_forced_sets", "forced_set_analysis", "exposure_margin",
                "classification", "accountable",
            ]:
                if not _same_json_value(got.get(key), want[key]):
                    return False
            fork_witness = got.get("fork_witness")
            if want["classification"] != "prevented":
                if not isinstance(fork_witness, dict):
                    return False
                if not _same_json_value(fork_witness.get("forced_keys"), want["minimal_forced_keys"]):
                    return False
                if not _valid_support_witness(raw, got, supports, event_by_name, raw["loci"]):
                    return False
                feasible_pairs.append(got)
            elif fork_witness is not None:
                return False
        if feasible_pairs:
            feasible_pairs.sort(key=lambda row: (
                len(row["fork_witness"]["forced_keys"]),
                len(row["conflict_loci"]),
                row["left_view"],
                row["right_view"],
            ))
            if not _same_json_value(reported.get("minimal_fork_witness"), feasible_pairs[0]):
                return False
        return True
    except (KeyError, TypeError, ValueError, IndexError, StopIteration, AssertionError, AttributeError):
        return False


def main() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (3 * 1024**3, 3 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("models", type=Path)
    parser.add_argument("results", type=Path)
    args = parser.parse_args()
    count = 0
    with args.models.open("rb") as models, args.results.open("rb") as results:
        while True:
            model_line = models.readline(MAX_LINE + 1)
            result_line = results.readline(MAX_LINE + 1)
            if not model_line and not result_line:
                break
            if not model_line or not result_line:
                raise SystemExit("different model/result counts")
            if len(model_line) > MAX_LINE or len(result_line) > MAX_LINE:
                raise SystemExit("line exceeds 256 KiB replay bound")
            if count >= MAX_LINES:
                raise SystemExit("batch exceeds 10,000-line replay bound")
            try:
                raw = json.loads(model_line)
                reported = json.loads(result_line)
            except (ValueError, UnicodeError) as exc:
                raise SystemExit("invalid JSON: " + str(exc))
            if not verify(raw, reported):
                raise SystemExit("continuity result rejected at line " + str(count + 1))
            count += 1
    print(json.dumps({
        "accepted_models": count,
        "reader_imports_analyzer": False,
        "layerwise_union_pruning": False,
        "support_combination": "full-cartesian-then-final-minimalization",
    }, sort_keys=True))


if __name__ == "__main__":
    main()
