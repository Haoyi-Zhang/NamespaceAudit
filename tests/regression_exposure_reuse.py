"""Finite exposure-reuse checks; no campaigns, resource calls or measurements.

The independent reference enumerates partial key assignments and Hall subsets.
It imports neither matching nor the producer for its calculations. POSIX-only
modules receive a deny-all import shim on Windows; their CLI is never invoked.
"""
import copy
import dataclasses
import itertools
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
if sys.platform == "win32" and "resource" not in sys.modules:
    shim = types.ModuleType("resource")
    def deny(name):
        raise RuntimeError("POSIX resource operation outside this pure regression: " + name)
    shim.__getattr__ = deny
    sys.modules["resource"] = shim
import continuity as producer
import continuity_replay as replay
from run_continuity import branching_model, control_models


def fixtures():
    rows = control_models() + [branching_model("reuse-forward"),
                              branching_model("reuse-reversed", True)]
    for feasible in (False, True):
        raw = copy.deepcopy(rows[6])
        raw["id"] = "reuse-repeated-" + str(feasible).lower()
        raw["events"] = [dict(id="e" + str(i), locus="name", policy="all",
                              dominates=[], requires={}) for i in range(8)]
        if feasible:
            raw["exposure"]["capacity"] = [2, 0, 1]
        rows.append(raw)
    return rows


def literal_analysis(keys, raw):
    windows, capacity = raw["exposure"]["windows"], raw["exposure"]["capacity"]
    best_size = 0
    for placement in itertools.product(*(list(windows[k]) + [None] for k in keys)):
        if all(placement.count(t) <= cap for t, cap in enumerate(capacity)):
            best_size = max(best_size, sum(t is not None for t in placement))
    deficient = []
    for size in range(1, len(keys) + 1):
        for subset in itertools.combinations(keys, size):
            slots = sorted(set(itertools.chain.from_iterable(windows[k] for k in subset)))
            available = sum(capacity[t] for t in slots)
            if size > available:
                deficient.append((-(size - available), size, subset, slots, available))
    obstruction = None
    if deficient:
        negative, size, subset, slots, available = min(deficient)
        obstruction = dict(keys=list(subset), slots=slots, demand=size,
                           capacity=available, deficit=-negative)
    deficit = len(keys) - best_size
    assert deficit == (0 if obstruction is None else obstruction["deficit"])
    return dict(forced_keys=list(keys), matching_size=best_size,
                exposure_deficit=deficit, hall_obstruction=obstruction)


def negatives(raw, good):
    rows = []
    for key in ("valid_views", "incompatible_view_pairs", "globally_accountable"):
        bad = copy.deepcopy(good)
        old = bad[key]
        bad[key] = int(old) if type(old) is bool else float(old)
        rows.append(replay.verify(raw, bad))
    if good["pairs"]:
        bad = copy.deepcopy(good)
        bad["pairs"][0]["forced_set_analysis"][0]["matching_size"] += 1
        rows.append(replay.verify(raw, bad))
        bad = copy.deepcopy(good)
        bad["pairs"][0]["exposure_margin"] += 1
        rows.append(replay.verify(raw, bad))
        bad = copy.deepcopy(good)
        bad["pairs"][0]["fork_witness"] = {} if bad["pairs"][0]["fork_witness"] is None else None
        rows.append(replay.verify(raw, bad))
    assert not any(rows)
    return rows


def refusals():
    base = fixtures()[2]
    rows = []
    for field, value in (("key_count", 13), ("key_count", True),
                         ("exposure", {"windows": [[]], "capacity": [0]}),
                         ("exposure", {"windows": [[0]], "capacity": [True]}),
                         ("events", [dict(id="x" + str(i), locus="name", policy="p",
                                          dominates=[], requires={}) for i in range(9)])):
        raw = copy.deepcopy(base)
        raw[field] = value
        try:
            producer.audit(raw)
        except ValueError as exc:
            rows.append(str(exc))
        else:
            raise AssertionError("bounded parser must refuse owned invalid input")
        assert not replay.verify(raw, {})
    return rows


def snapshot():
    rows = []
    for raw in fixtures():
        engine = producer.Audit(producer.NamespaceModel.parse(raw))
        full = engine.run()
        assert replay.verify(raw, full)
        assert full == engine.run()
        for mask in range(1 << raw["key_count"]):
            keys = tuple(k for k in range(raw["key_count"]) if mask & (1 << k))
            assert engine._exposure_analysis(mask) == literal_analysis(keys, raw)
        rows.append(dict(model=raw, result=full, summary=engine.run(False),
                         oracle=replay.oracle(raw), negatives=negatives(raw, full)))
    return dict(records=rows, refusals=refusals())


class ExposureReuseTests(unittest.TestCase):
    def test_full_evidence_against_independent_references(self):
        self.assertEqual(len(snapshot()["records"]), 12)

    def test_single_immutable_record_for_repeated_pairs_and_fresh_results(self):
        for raw in fixtures()[-2:]:
            engine = producer.Audit(producer.NamespaceModel.parse(raw))
            with patch.object(producer, "maximum_exposure", wraps=producer.maximum_exposure) as matching, \
                 patch.object(producer, "hall_obstruction", wraps=producer.hall_obstruction) as hall:
                good = engine.run()
                self.assertEqual(good["incompatible_view_pairs"], 28)
                self.assertEqual((matching.call_count, hall.call_count), (1, 1))
                expected = copy.deepcopy(good)
                good["pairs"][0]["forced_set_analysis"][0]["forced_keys"].append(99)
                obstruction = good["pairs"][0]["forced_set_analysis"][0]["hall_obstruction"]
                if obstruction:
                    obstruction["keys"].clear()
                    obstruction["slots"].append(99)
                if good.get("minimal_fork_witness"):
                    good["minimal_fork_witness"]["fork_witness"]["exposures"].clear()
                self.assertEqual(engine.run(), expected)
                self.assertEqual((matching.call_count, hall.call_count), (1, 1))
            def immutable(value):
                return value is None or type(value) is int or (
                    type(value) is tuple and all(immutable(item) for item in value))
            self.assertTrue(all(immutable(item) for item in engine._exposure_cache.values()))

    def test_capacity_isolation_parameter_change_and_bound(self):
        raw = fixtures()[-2]
        first = producer.Audit(producer.NamespaceModel.parse(raw))
        blocked = first.run()
        model = dataclasses.replace(first.model, capacity=(2, 0, 1))
        second = producer.Audit(model)
        self.assertEqual(second.run()["result"], "accountable-fork")
        self.assertEqual(first.run(), blocked)
        first.model = model
        self.assertEqual(first.run(), second.run())
        for mask in range(1 << model.key_count):
            first._exposure_analysis(mask)
        self.assertEqual(len(first._exposure_cache), 1 << model.key_count)
        first._exposure_analysis((1 << model.key_count) + 1)
        self.assertEqual(len(first._exposure_cache), 1 << model.key_count)
        with patch.object(producer, "hall_obstruction", return_value=None):
            with self.assertRaises(AssertionError):
                producer.Audit(producer.NamespaceModel.parse(raw)).run()


if __name__ == "__main__":
    unittest.main()
