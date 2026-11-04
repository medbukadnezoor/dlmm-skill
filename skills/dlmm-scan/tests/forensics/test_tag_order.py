"""HS-FOLLOWUPS-T1: helius_forensics.tag_summary orders tags with equal counts by label (count descending, then label
ascending). Before, equal counts kept the order of a set, which Python's per-process hash seed changes from run to run
(seen as "oak_grove 25, kiwi 25" in one run and "kiwi 25, oak_grove 25" in the next), and the top-6 cut could keep
different tags on a tie. Covers: the tie order, the top-6 cut, unchanged counts, and the same bytes under different hash
seeds in separate processes (started with -s -P and a cleaned environment: -I would ignore PYTHONHASHSEED)."""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402

# The HS-LABELS-T1 control scenario's Jupiter tags: every fourth row carries kiwi and oak_grove (25 each).
TIES = [{"address": f"w{i}", "holderTags": ["bundler", "oak_grove", "kiwi"] if i % 4 == 0 else ["bundler"]} for i in range(100)]
# Nine tags of equal count: the top-6 cut falls inside the tie.
WIDE = [{"address": f"w{i}", "tags": [f"t{j}" for j in range(9)]} for i in range(3)]
LABELS = [f"t{j}" for j in range(9)]
KEYS = ("tags", "maker_token_tags", "maker_tags", "holderTags", "walletCategories")


def reference_counts(payload) -> dict[str, int]:
    """Independent count: rows per inert lowercase label (a row counts each label once)."""
    counts: dict[str, int] = {}
    for row in hf._unwrap(payload):
        labels = {label.lower() for key in KEYS for tag in (row.get(key) if isinstance(row.get(key), list) else [])
                  if isinstance(tag, str) and (label := hf.safe_label(tag))}
        for label in labels:
            counts[label] = counts.get(label, 0) + 1
    return counts


CHILD = """
import json, sys
sys.path.insert(0, sys.argv[1])
import helius_forensics as hf
ties, wide, labels = (json.loads(a) for a in sys.argv[2:5])
print(json.dumps({"ties": list(hf.tag_summary(ties).items()), "wide": list(hf.tag_summary(wide).items()), "control_set_order": list(set(labels))}))
"""


def run_child(seed: int) -> dict:
    """One fresh process with PYTHONHASHSEED really in effect: -s -P (not -I, which ignores PYTHON* variables) and an
    environment with no other PYTHON* variable."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")} | {"PYTHONHASHSEED": str(seed)}
    done = subprocess.run([sys.executable, "-s", "-P", "-B", "-c", CHILD, str(SCRIPTS), json.dumps(TIES), json.dumps(WIDE), json.dumps(LABELS)],
                          env=env, capture_output=True, text=True, timeout=120, check=True)
    return json.loads(done.stdout)


class TagOrderTests(unittest.TestCase):
    def test_equal_counts_are_ordered_by_label(self):
        self.assertEqual(list(hf.tag_summary(TIES).items()), [("bundler", 100), ("kiwi", 25), ("oak_grove", 25)])
        self.assertEqual(list(hf.tag_summary(list(reversed(TIES))).items()), [("bundler", 100), ("kiwi", 25), ("oak_grove", 25)])

    def test_the_top_six_cut_keeps_the_first_labels_of_a_tie(self):
        self.assertEqual(list(hf.tag_summary(WIDE).items()), [(f"t{j}", 3) for j in range(6)])
        rows = [{"address": "a", "tags": ["zeta", "eta", "theta", "iota", "kappa", "lambda", "mu", "alpha"]}] + [{"address": f"b{i}", "tags": ["alpha"]} for i in range(4)]
        self.assertEqual(list(hf.tag_summary(rows).items()), [("alpha", 5), ("eta", 1), ("iota", 1), ("kappa", 1), ("lambda", 1), ("mu", 1)])

    def test_the_counts_are_unchanged(self):
        """Over 150 seeded random payloads: every kept tag has the independent count, the kept tags are the six with the
        highest counts (every kept count is at least every dropped count), and only the order among equal counts and
        which equal-count tags the cut keeps are fixed by the label."""
        rng = random.Random(1020)
        vocabulary = ["bundler", "sniper", "kol", "smart_money", "dev", "kiwi", "oak_grove", "whale", "fresh", "insider", "BUNDLER", "Kol"]
        for n in range(150):
            payload = [{"address": f"w{i}", rng.choice(KEYS): rng.sample(vocabulary, rng.randint(0, 6))} for i in range(rng.randint(0, 20))]
            if rng.random() < 0.3:
                payload = {"data": {"list": payload}} if rng.random() < 0.5 else {"holders": payload}
            with self.subTest(n):
                got, ref = hf.tag_summary(payload), reference_counts(payload)
                self.assertEqual({k: ref[k] for k in got}, got)
                self.assertEqual(list(got.items()), sorted(ref.items(), key=lambda kv: (-kv[1], kv[0]))[:6])
                dropped = [v for k, v in ref.items() if k not in got]
                self.assertTrue(not dropped or min(got.values()) >= max(dropped))

    def test_the_same_bytes_under_three_hash_seeds(self):
        runs = {seed: run_child(seed) for seed in (1, 2, 3)}
        self.assertGreater(len({json.dumps(r["control_set_order"]) for r in runs.values()}), 1,
                           "control: a plain set of the same labels iterates differently, so the seeds were in effect")
        self.assertEqual(len({json.dumps({k: r[k] for k in ("ties", "wide")}) for r in runs.values()}), 1)
        self.assertEqual(runs[1]["ties"], [["bundler", 100], ["kiwi", 25], ["oak_grove", 25]])
        self.assertEqual(runs[1]["wide"], [[f"t{j}", 3] for j in range(6)])


if __name__ == "__main__":
    unittest.main()
