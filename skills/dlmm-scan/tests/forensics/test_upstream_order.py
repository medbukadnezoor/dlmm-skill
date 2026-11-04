"""Upstream trace rows stay in batch order when there is more than one upstream row and the lookups finish out of order
(carried from the HF-T1 verifier caveat into HOLDER-SCAN-T1). Offline: fakes only, no network, dummy key.

The fake below holds every upstream lookup in flight at once and releases them in REVERSE batch order (the last batch
funder's lookup returns first, each earlier one waits until its successor has returned), so completion order is the
exact opposite of batch order. The rows must still come out in batch order, identical to the one-at-a-time run."""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_holder_forensics import MINT, addr  # noqa: E402
from test_parallel_rows import T0, _MainMixin, funder_addr, normalize_report  # noqa: E402

WAIT_S = 10.0  # generous: a broken pool fails the assertion instead of hanging the suite


def upstream_addr(tag: str) -> str:
    return ("U" + tag).ljust(44, "u")


def batch_scenario(tags=("A", "B", "C", "D", "E"), per=5):
    """One pool and five unlabeled funders, each feeding five holders inside 25 s; every funder has its own upstream."""
    pool = addr(900)
    accounts = [{"owner": pool, "amount": 50_000}]
    funded = {}
    n = 0
    for k, tag in enumerate(tags):
        for j in range(per):
            wallet = addr(n)
            accounts.append({"owner": wallet, "amount": 1000 - 7 * n})
            funded[wallet] = {"funder": funder_addr(tag), "timestamp": T0 + 3600 * k + 5 * j, "amount": 2.5}
            n += 1
        funded[funder_addr(tag)] = {"funder": upstream_addr(tag), "funderName": f"Exchange {tag}", "funderType": "Centralized Exchange",
                                    "timestamp": T0 - 86_400 * (k + 1), "amount": 10.0 + k}
    return pool, accounts, funded, per * len(tags)


class ReverseFinishFake:
    """Helius stand-in. Holder lookups answer at once. Lookups of the addresses in `reverse` (the batch funders, in
    batch order) all wait until every one of them is in flight, then finish in reverse batch order."""

    def __init__(self, accounts, funded, reverse=(), missing=(), fail=()):
        self.accounts, self.funded = accounts, funded
        self.budget = hf.Budget(10**9)
        self.reverse = list(reverse)
        self.missing, self.fail = set(missing), set(fail)
        self.calls: list[str] = []
        self.completed: list[str] = []
        self._lock = threading.Lock()
        self._barrier = threading.Barrier(len(self.reverse)) if self.reverse else None
        self._done = {a: threading.Event() for a in self.reverse}

    def token_accounts(self, mint, **_):
        return self.accounts, False

    def funded_by(self, address):
        self.budget.charge(hf.COST_FUNDED_BY)
        with self._lock:
            self.calls.append(address)
        if address not in self._done:
            return self.funded.get(address)
        try:
            self._barrier.wait(timeout=WAIT_S)  # every upstream lookup is in flight at the same time
            nxt = self.reverse.index(address) + 1
            if nxt < len(self.reverse) and not self._done[self.reverse[nxt]].wait(timeout=WAIT_S):
                raise AssertionError("successor lookup never finished")
            if address in self.fail:
                raise hf.ForensicsError("helius funded-by failed (http 500)")
            return None if address in self.missing else self.funded.get(address)
        finally:
            with self._lock:
                self.completed.append(address)
            self._done[address].set()


def batch_order(funders_result):
    return [b["funder"] for b in funders_result["batches"] if not b["labeled"]]


class UpstreamOrderTests(_MainMixin, unittest.TestCase):
    def sequential(self):
        pool, accounts, funded, top = batch_scenario()
        fake = ReverseFinishFake(accounts, funded)
        with mock.patch.object(hf, "dexscreener_pairs", return_value=([{"pairAddress": pool}], True)):
            holders = hf.run_holders(fake, MINT)
        return holders, hf.run_funders(fake, holders, top=top, workers=1), (pool, accounts, funded, top)

    def test_trace_upstream_rows_keep_batch_order_when_lookups_finish_in_reverse(self):
        funders = [funder_addr(t) for t in "ABCDE"]
        answers = {f: {"funder": upstream_addr(f[1]), "funderName": "Exchange", "timestamp": T0, "amount": 1.0} for f in funders}
        batches = [{"funder": f} for f in funders]
        one = hf.trace_upstream(batches, ReverseFinishFake([], answers).funded_by, workers=1)
        fake = ReverseFinishFake([], answers, reverse=funders)
        many = hf.trace_upstream(batches, fake.funded_by, workers=5)
        self.assertEqual(fake.completed, list(reversed(funders)), "the lookups really finished in reverse batch order")
        self.assertEqual([r["batch_funder"] for r in many], funders)
        self.assertEqual(len(many), 5)
        self.assertEqual(many, one)

    def test_gaps_from_missing_and_failed_lookups_do_not_reorder_the_rest(self):
        funders = [funder_addr(t) for t in "ABCDE"]
        answers = {f: {"funder": upstream_addr(f[1]), "timestamp": T0} for f in funders}
        batches = [{"funder": f} for f in funders]
        fake = ReverseFinishFake([], answers, reverse=funders, missing={funders[1]}, fail={funders[3]})
        rows = hf.trace_upstream(batches, fake.funded_by, workers=5)
        self.assertEqual(fake.completed, list(reversed(funders)))
        self.assertEqual([r["batch_funder"] for r in rows], [funders[0], funders[2], funders[4]])

    def test_run_funders_upstream_identical_between_one_and_six_workers(self):
        holders, seq, (_, accounts, funded, top) = self.sequential()
        order = batch_order(seq)
        self.assertGreater(len(order), 1)
        self.assertEqual([u["batch_funder"] for u in seq["upstream"]], order)
        fake = ReverseFinishFake(accounts, funded, reverse=order)
        par = hf.run_funders(fake, holders, top=top, workers=6)
        self.assertEqual(fake.completed[-len(order):], list(reversed(order)), "upstream lookups finished out of order")
        self.assertEqual(par["upstream"], seq["upstream"])
        self.assertEqual(json.dumps(par, sort_keys=True), json.dumps(seq, sort_keys=True))

    def test_report_files_identical_between_one_and_six_workers(self):
        _, seq, (pool, accounts, funded, top) = self.sequential()
        order = batch_order(seq)
        outputs = []
        for workers, reverse in ((1, ()), (6, order)):
            fake = ReverseFinishFake(accounts, funded, reverse=reverse)
            with tempfile.TemporaryDirectory() as tmp:
                code, _, _ = self.run_main(["report", MINT, "--top", str(top), "--out", tmp, "--workers", str(workers)], fake, pool)
                self.assertEqual(code, 0)
                files = {name: (Path(tmp) / name).read_text() for name in ("funders.json", "assessment.json", "report.md")}
            if reverse:
                self.assertEqual(fake.completed[-len(order):], list(reversed(order)))
            outputs.append(files)
        self.assertEqual(outputs[0]["funders.json"], outputs[1]["funders.json"])
        self.assertEqual(outputs[0]["assessment.json"], outputs[1]["assessment.json"])
        self.assertEqual(normalize_report(outputs[0]["report.md"]), normalize_report(outputs[1]["report.md"]))
        upstream = json.loads(outputs[1]["funders.json"])["upstream"]
        self.assertEqual([u["batch_funder"] for u in upstream], order)
        self.assertGreater(len(upstream), 1)


if __name__ == "__main__":
    unittest.main()
