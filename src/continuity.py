"""Recovery-ordered namespace continuity audit.

This is a finite symbolic checker.  It performs no cryptographic operations and
contacts no service.  The model is intentionally explicit:

* each namespace locus has a protocol-supplied dominance partial order;
* each event snapshots a monotone authorization policy;
* a valid namespace view selects one event at every locus and satisfies parent
  requirements up to dominance;
* an honest, unexposed key may sign only comparable events at one locus;
* exposed keys are described by a downward-closed temporal matching family.

The checker enumerates valid views and exact minimal policy supports.  It then
classifies every incompatible view pair as prevented, accountable-but-feasible,
or silent.  See proofs/model.md for the theorem and scope.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from typing import Iterable

from finite_model import MAX_KEYS, MAX_POLICY_NODES, hall_obstruction, maximum_exposure, minimal_supports

MAX_LOCI = 8
MAX_EVENTS = 32
MAX_EVENTS_PER_LOCUS = 8
MAX_POLICIES = 32
MAX_VIEW_CANDIDATES = 100_000


@dataclass(frozen=True)
class Policy:
    name: str
    nodes: tuple[dict, ...]
    root: int


@dataclass(frozen=True)
class Locus:
    name: str
    parents: tuple[str, ...]


@dataclass(frozen=True)
class Event:
    name: str
    locus: str
    policy: str
    dominates: tuple[str, ...]
    requires: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class NamespaceModel:
    name: str
    key_count: int
    windows: tuple[tuple[int, ...], ...]
    capacity: tuple[int, ...]
    policies: tuple[Policy, ...]
    loci: tuple[Locus, ...]
    events: tuple[Event, ...]

    @classmethod
    def parse(cls, raw: dict) -> "NamespaceModel":
        required = {"id", "key_count", "exposure", "policies", "loci", "events"}
        if not isinstance(raw, dict) or set(raw) != required:
            raise ValueError("model must contain exactly id/key_count/exposure/policies/loci/events")
        name = raw["id"]
        if not isinstance(name, str) or not name or len(name) > 100:
            raise ValueError("invalid model identifier")
        key_count = raw["key_count"]
        if type(key_count) is not int or not 1 <= key_count <= MAX_KEYS:
            raise ValueError("key_count outside bounded model")

        exposure = raw["exposure"]
        if not isinstance(exposure, dict) or set(exposure) != {"windows", "capacity"}:
            raise ValueError("exposure must contain exactly windows/capacity")
        capacity_raw = exposure["capacity"]
        windows_raw = exposure["windows"]
        if not isinstance(capacity_raw, list) or not 1 <= len(capacity_raw) <= 12:
            raise ValueError("invalid exposure horizon")
        if any(type(v) is not int or not 0 <= v <= MAX_KEYS for v in capacity_raw):
            raise ValueError("invalid exposure capacity")
        if not isinstance(windows_raw, list) or len(windows_raw) != key_count:
            raise ValueError("one exposure window is required per key")
        windows: list[tuple[int, ...]] = []
        for item in windows_raw:
            if not isinstance(item, list) or not item:
                raise ValueError("exposure windows must be nonempty lists")
            if item != sorted(set(item)):
                raise ValueError("exposure slots must be strictly increasing")
            if any(type(t) is not int or not 0 <= t < len(capacity_raw) for t in item):
                raise ValueError("exposure slot outside horizon")
            windows.append(tuple(item))

        policies_raw = raw["policies"]
        if not isinstance(policies_raw, list) or not 1 <= len(policies_raw) <= MAX_POLICIES:
            raise ValueError("invalid policy count")
        policies: list[Policy] = []
        policy_names: set[str] = set()
        for item in policies_raw:
            if not isinstance(item, dict) or set(item) != {"id", "nodes", "root"}:
                raise ValueError("policy must contain exactly id/nodes/root")
            pid = item["id"]
            if not isinstance(pid, str) or not pid or len(pid) > 80 or pid in policy_names:
                raise ValueError("invalid or duplicate policy id")
            # Calling minimal_supports here validates the entire circuit.
            minimal_supports(item["nodes"], item["root"], key_count)
            policy_names.add(pid)
            policies.append(Policy(pid, tuple(item["nodes"]), item["root"]))

        loci_raw = raw["loci"]
        if not isinstance(loci_raw, list) or not 1 <= len(loci_raw) <= MAX_LOCI:
            raise ValueError("invalid locus count")
        loci: list[Locus] = []
        locus_names: set[str] = set()
        for item in loci_raw:
            if not isinstance(item, dict) or set(item) != {"id", "parents"}:
                raise ValueError("locus must contain exactly id/parents")
            lid = item["id"]
            parents = item["parents"]
            if not isinstance(lid, str) or not lid or len(lid) > 80 or lid in locus_names:
                raise ValueError("invalid or duplicate locus id")
            if not isinstance(parents, list) or parents != sorted(set(parents)):
                raise ValueError("locus parents must be a sorted distinct list")
            if any(not isinstance(p, str) or p not in locus_names for p in parents):
                raise ValueError("locus parents must precede the child")
            locus_names.add(lid)
            loci.append(Locus(lid, tuple(parents)))

        events_raw = raw["events"]
        if not isinstance(events_raw, list) or not 1 <= len(events_raw) <= MAX_EVENTS:
            raise ValueError("invalid event count")
        events: list[Event] = []
        event_names: set[str] = set()
        event_locus: dict[str, str] = {}
        for item in events_raw:
            if not isinstance(item, dict) or set(item) != {"id", "locus", "policy", "dominates", "requires"}:
                raise ValueError("event must contain exactly id/locus/policy/dominates/requires")
            eid = item["id"]
            lid = item["locus"]
            pid = item["policy"]
            dom = item["dominates"]
            req = item["requires"]
            if not isinstance(eid, str) or not eid or len(eid) > 80 or eid in event_names:
                raise ValueError("invalid or duplicate event id")
            if lid not in locus_names or pid not in policy_names:
                raise ValueError("unknown event locus or policy")
            if not isinstance(dom, list) or dom != sorted(set(dom)):
                raise ValueError("dominates must be a sorted distinct list")
            if any(d not in event_names or event_locus[d] != lid for d in dom):
                raise ValueError("dominance edges must point to preceding events at the same locus")
            if not isinstance(req, dict):
                raise ValueError("requires must be an object")
            locus_obj = next(x for x in loci if x.name == lid)
            if set(req) - set(locus_obj.parents):
                raise ValueError("requirements may name only declared parent loci")
            req_pairs: list[tuple[str, str]] = []
            for parent in sorted(req):
                target = req[parent]
                if not isinstance(target, str) or target not in event_names or event_locus[target] != parent:
                    raise ValueError("requirement must name a preceding event at the parent locus")
                req_pairs.append((parent, target))
            event_names.add(eid)
            event_locus[eid] = lid
            events.append(Event(eid, lid, pid, tuple(dom), tuple(req_pairs)))

        by_locus = {lid: 0 for lid in locus_names}
        for event in events:
            by_locus[event.locus] += 1
        if any(v == 0 or v > MAX_EVENTS_PER_LOCUS for v in by_locus.values()):
            raise ValueError("each locus needs 1..8 events")
        candidate_count = 1
        for v in by_locus.values():
            candidate_count *= v
        if candidate_count > MAX_VIEW_CANDIDATES:
            raise ValueError("view product exceeds finite checker bound")

        return cls(
            name,
            key_count,
            tuple(windows),
            tuple(capacity_raw),
            tuple(policies),
            tuple(loci),
            tuple(events),
        )


class Audit:
    def __init__(self, model: NamespaceModel):
        self.model = model
        self.policy_by_name = {p.name: p for p in model.policies}
        self.event_by_name = {e.name: e for e in model.events}
        self.locus_by_name = {l.name: l for l in model.loci}
        self.events_by_locus = {
            l.name: tuple(e for e in model.events if e.locus == l.name) for l in model.loci
        }
        self.supports = {
            p.name: minimal_supports(list(p.nodes), p.root, model.key_count) for p in model.policies
        }
        self._dominates = self._dominance_closure()
        self.valid_views = self._enumerate_valid_views()
        self._exposure_parameters = None
        self._exposure_cache: dict[tuple[int, ...], tuple] = {}

    def _dominance_closure(self) -> set[tuple[str, str]]:
        relation = {(e.name, e.name) for e in self.model.events}
        relation.update((e.name, old) for e in self.model.events for old in e.dominates)
        changed = True
        while changed:
            changed = False
            for a, b in tuple(relation):
                for c, d in tuple(relation):
                    if b == c and (a, d) not in relation:
                        relation.add((a, d))
                        changed = True
        # Parser's backwards-only edges already make cycles impossible, but retain the check.
        for a, b in relation:
            if a != b and (b, a) in relation:
                raise ValueError("dominance relation is cyclic")
        return relation

    def comparable(self, left: str, right: str) -> bool:
        return (left, right) in self._dominates or (right, left) in self._dominates

    def _enumerate_valid_views(self) -> tuple[tuple[str, ...], ...]:
        loci = self.model.loci
        choices = [tuple(e.name for e in self.events_by_locus[l.name]) for l in loci]
        views: list[tuple[str, ...]] = []
        for selection in product(*choices):
            chosen = {l.name: event for l, event in zip(loci, selection)}
            valid = True
            for event_name in selection:
                event = self.event_by_name[event_name]
                for parent, required_event in event.requires:
                    if (chosen[parent], required_event) not in self._dominates:
                        valid = False
                        break
                if not valid:
                    break
            if valid:
                views.append(tuple(selection))
        if not views:
            raise ValueError("model has no valid namespace view")
        return tuple(views)

    def conflict_loci(self, left: tuple[str, ...], right: tuple[str, ...]) -> tuple[int, ...]:
        return tuple(i for i, (a, b) in enumerate(zip(left, right)) if not self.comparable(a, b))

    @staticmethod
    def _minimal_masks(rows: dict[int, tuple]) -> dict[int, tuple]:
        masks = sorted(rows, key=lambda m: (m.bit_count(), m))
        keep: dict[int, tuple] = {}
        for mask in masks:
            if any((old & mask) == old for old in keep):
                continue
            keep[mask] = rows[mask]
        return keep

    def _intersection_options(self, left_event: str, right_event: str) -> dict[int, tuple[tuple[int, ...], tuple[int, ...]]]:
        lp = self.event_by_name[left_event].policy
        rp = self.event_by_name[right_event].policy
        rows: dict[int, tuple[tuple[int, ...], tuple[int, ...]]] = {}
        for left_support in self.supports[lp]:
            lset = set(left_support)
            for right_support in self.supports[rp]:
                common = lset.intersection(right_support)
                mask = sum(1 << k for k in common)
                witness = (left_support, right_support)
                if mask not in rows or witness < rows[mask]:
                    rows[mask] = witness
        return self._minimal_masks(rows)

    def _exposure_for_mask(self, mask: int) -> tuple[bool, tuple[tuple[int, int], ...]]:
        keys = tuple(k for k in range(self.model.key_count) if mask & (1 << k))
        assignment = maximum_exposure(keys, self.model.windows, self.model.capacity)
        feasible = len(assignment) == len(keys)
        schedule = tuple((k, assignment[k]) for k in keys if k in assignment)
        return feasible, schedule

    def _exposure_record(self, mask: int) -> tuple:
        # At most 2**key_count entries for the current immutable exposure input.
        # Keep no caller-owned lists/dicts; do not cache mutable policy nodes.
        parameters = (self.model.key_count, self.model.windows, self.model.capacity)
        if parameters != self._exposure_parameters:
            self._exposure_cache.clear()
            self._exposure_parameters = parameters
        keys = tuple(k for k in range(self.model.key_count) if mask & (1 << k))
        if keys in self._exposure_cache:
            return self._exposure_cache[keys]
        assignment = maximum_exposure(keys, self.model.windows, self.model.capacity)
        deficit = len(keys) - len(assignment)
        obstruction = hall_obstruction(keys, self.model.windows, self.model.capacity)
        if (obstruction is None) != (deficit == 0):
            raise AssertionError("matching and Hall certificates disagree")
        hall = None if obstruction is None else (
            tuple(obstruction["keys"]), tuple(obstruction["slots"]),
            obstruction["demand"], obstruction["capacity"], obstruction["deficit"],
        )
        schedule = tuple((k, assignment[k]) for k in keys if k in assignment)
        record = (keys, len(assignment), deficit, hall, schedule)
        self._exposure_cache[keys] = record
        return record

    def _exposure_analysis(self, mask: int) -> dict:
        keys, matching_size, deficit, hall, _ = self._exposure_record(mask)
        obstruction = None if hall is None else {
            "keys": list(hall[0]), "slots": list(hall[1]), "demand": hall[2],
            "capacity": hall[3], "deficit": hall[4],
        }
        return {
            "forced_keys": list(keys),
            "matching_size": matching_size,
            "exposure_deficit": deficit,
            "hall_obstruction": obstruction,
        }

    def audit_view_pair(self, left: tuple[str, ...], right: tuple[str, ...]) -> dict | None:
        conflicts = self.conflict_loci(left, right)
        if not conflicts:
            return None

        # Dynamic program over conflict loci.  State is the union of signers forced
        # to double-sign incomparable events; supersets can be discarded because
        # the exposure family is downward closed.
        states: dict[int, tuple[tuple[int, tuple[int, ...], tuple[int, ...]], ...]] = {0: tuple()}
        option_counts: list[int] = []
        for index in conflicts:
            options = self._intersection_options(left[index], right[index])
            option_counts.append(len(options))
            merged: dict[int, tuple] = {}
            for current_mask, current_witness in states.items():
                for intersection_mask, (ls, rs) in options.items():
                    new_mask = current_mask | intersection_mask
                    row = current_witness + ((index, ls, rs),)
                    if new_mask not in merged or row < merged[new_mask]:
                        merged[new_mask] = row
            states = self._minimal_masks(merged)

        forced_set_analysis = []
        feasible_rows = []
        for mask, witness in states.items():
            analysis = self._exposure_analysis(mask)
            forced_set_analysis.append((mask.bit_count(), mask, analysis))
            if analysis["exposure_deficit"] == 0:
                keys, matching_size, _, _, schedule = self._exposure_record(mask)
                feasible = matching_size == len(keys)
                if not feasible:
                    raise AssertionError("zero deficit lacks an exposure assignment")
                feasible_rows.append((mask.bit_count(), mask, witness, schedule))
        forced_set_analysis.sort()
        feasible_rows.sort()
        exposure_margin = min(row[2]["exposure_deficit"] for row in forced_set_analysis)
        accountable = 0 not in states
        if feasible_rows:
            _, mask, witness, schedule = feasible_rows[0]
            classification = "accountable-fork" if accountable else "silent-fork"
            fork_witness = {
                "forced_keys": [k for k in range(self.model.key_count) if mask & (1 << k)],
                "exposures": [[k, t] for k, t in schedule],
                "supports": [
                    {
                        "locus": self.model.loci[index].name,
                        "left_event": left[index],
                        "right_event": right[index],
                        "left_support": list(ls),
                        "right_support": list(rs),
                    }
                    for index, ls, rs in witness
                ],
            }
        else:
            classification = "prevented"
            fork_witness = None

        return {
            "left_view": list(left),
            "right_view": list(right),
            "conflict_loci": [self.model.loci[i].name for i in conflicts],
            "option_counts": option_counts,
            "minimal_forced_sets": [
                [k for k in range(self.model.key_count) if mask & (1 << k)]
                for mask in sorted(states, key=lambda m: (m.bit_count(), m))
            ],
            "forced_set_analysis": [row[2] for row in forced_set_analysis],
            "exposure_margin": exposure_margin,
            "classification": classification,
            "accountable": accountable,
            "fork_witness": fork_witness,
        }

    def run(self, include_pairs: bool = True) -> dict:
        pair_rows = []
        counts = {"prevented": 0, "accountable-fork": 0, "silent-fork": 0}
        views = self.valid_views
        for i, left in enumerate(views):
            for right in views[i + 1 :]:
                row = self.audit_view_pair(left, right)
                if row is None:
                    continue
                counts[row["classification"]] += 1
                pair_rows.append(row)
        if not sum(counts.values()):
            result = "no-conflict"
        elif counts["silent-fork"]:
            result = "silent-fork"
        elif counts["accountable-fork"]:
            result = "accountable-fork"
        else:
            result = "prevented"
        margins = [row["exposure_margin"] for row in pair_rows]
        output = {
            "id": self.model.name,
            "result": result,
            "valid_views": len(views),
            "incompatible_view_pairs": sum(counts.values()),
            "pair_counts": counts,
            "globally_prevented": result in {"prevented", "no-conflict"},
            "globally_accountable": counts["silent-fork"] == 0,
            "minimum_exposure_margin": min(margins) if margins else None,
        }
        if include_pairs:
            output["pairs"] = pair_rows
        if pair_rows:
            candidates = [r for r in pair_rows if r["fork_witness"] is not None]
            if candidates:
                candidates.sort(
                    key=lambda r: (
                        len(r["fork_witness"]["forced_keys"]),
                        len(r["conflict_loci"]),
                        r["left_view"],
                        r["right_view"],
                    )
                )
                output["minimal_fork_witness"] = candidates[0]
        return output


def audit(raw: dict, include_pairs: bool = True) -> dict:
    return Audit(NamespaceModel.parse(raw)).run(include_pairs=include_pairs)
