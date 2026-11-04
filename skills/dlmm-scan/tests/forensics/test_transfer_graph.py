"""HS-GRAPH-T1: the `transfer_graph` follow-up lane (scripts/transfer_graph.py) and its offline `--present` block.

Offline only: a fake Helius transport (no network, dummy keys). Two kinds of data:
- synthetic holders and transfers built here, for the rules one by one;
- the prototype replay (fixtures/transfer_graph/*_replay_20261020.json.gz): public Helius rows of the HS-GRAPH-T1
  prototype of 2026-10-20 for DKYc, 9A1V, 78rn and GezC (trimmed; signatures replaced by placeholders), plus, for DKYc,
  the reads the prototype did not make, read live once by this lane.

Covers: request construction (method, params, sortOrder, the key only in the header, no proxy, no redirects, the hard
deadline, at most one retry and only after a 429); the budget (estimate, --hop-max lowered first, refusal, charge before
send, parallel reads never past the cap, credits per stage); each edge type and its thresholds; burst windows and
sessions; repeated rounds; exclusions (the service rule, the app list, pools, off-curve addresses, mints) and the
mutation that proves the exclusions bite; components, the merged view and the Bubblemaps overlap; partial runs (budget,
failures in a row, Ctrl-C); key echo; --present (wording, empty, damaged files); presentation only (assess gives the same
files with or without the lane's file); and the prototype replay (DKYc clusters 5, 7, 8, 9, 10; the 78rn and GezC bursts;
no burst on DKYc or 9A1V). Repair round 2: call C (SOL, newest 100) is on by default for the first 100 holders read; the
78rn and GezC default lists are pinned (fixtures/transfer_graph/default_lists_20261020.json); the key-echo backstop of
_save and the budget lock are tested directly."""

from __future__ import annotations

import contextlib
import copy
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
import transfer_graph as tg  # noqa: E402
from ha.solana import is_on_curve  # noqa: E402
from test_assess import _map, _run, case_negative_space_inu, run_assess  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
REPLAY = FIX / "transfer_graph"
KEY = "dummy-helius-key-0123456789"
REASSURING = re.compile(r"\b(clean|safe|low)\b", re.IGNORECASE)
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
T0 = 1_790_000_000  # 2026-09-21


def b58(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def placeholder_sig(i: int) -> str:
    """The replay fixtures replace signatures by short ids (the same transfer keeps one id); this is the valid placeholder
    signature the fixture builder used for id i."""
    out = ""
    while True:
        i, r = divmod(i, 58)
        out = B58[r] + out
        if not i:
            break
    return "S" + out.rjust(8, "1") + "1" * 55


def wallet(seed: str) -> str:
    """A valid address on the ed25519 curve (a wallet)."""
    for i in range(1000):
        a = b58(hashlib.sha256(f"wallet {seed} {i}".encode()).digest())
        if len(a) >= 32 and is_on_curve(a):
            return a
    raise AssertionError(seed)


def pda(seed: str) -> str:
    """A valid address off the curve (a program account)."""
    for i in range(1000):
        a = b58(hashlib.sha256(f"pda {seed} {i}".encode()).digest())
        if len(a) >= 32 and not is_on_curve(a):
            return a
    raise AssertionError(seed)


def sig(seed: str) -> str:
    return b58(hashlib.sha512(f"sig {seed}".encode()).digest())


MINT = wallet("mint")
POOL = pda("pool")


def make_holders(mint: str, n: int = 30, *, pools: tuple[str, ...] = (POOL,), extra: dict[str, float] | None = None) -> tuple[dict, list[str]]:
    """A holders.json that the forensics loader accepts: n ordinary wallets (rank 2..), one pool at rank 1."""
    wallets = [wallet(f"h{i}") for i in range(n)]
    balances = {POOL: 1000.0} | {w: float(500 - i) for i, w in enumerate(wallets)} | dict(extra or {})
    dist = hf.distribution(balances, set(pools))
    ranked = dist.pop("ranked")
    raw = {"mint": mint, "token_accounts": len(balances), "truncated": False, "earliest_pair_created_at": None, "pool_addresses": list(pools),
           "distribution": dist, "warnings": [], "top_holders": hf.top_holder_rows(ranked, set(pools), 250), "owner_balances": balances, "credits_spent": 20}
    return raw, wallets


def row(frm: str, to: str, asset: str, amount: int, t: int, seed: str | None = None, mint: str = MINT, decimals: int | None = None) -> dict:
    m = {"SOL": tg.SOL_MINT, "WSOL": tg.WSOL_MINT, "TOKEN": mint}[asset]
    dec = decimals if decimals is not None else (9 if asset in ("SOL", "WSOL") else 6)
    return {"signature": sig(seed or f"{frm}{to}{asset}{amount}{t}"), "slot": 1, "blockTime": t, "type": "transfer", "fromUserAccount": frm,
            "toUserAccount": to, "mint": m, "amount": str(amount), "decimals": dec, "uiAmount": "x"}


class Resp:
    def __init__(self, body: bytes, status: int = 200):
        self.status, self._b = status, body

    def read(self, n: int = -1) -> bytes:
        return self._b if n is None or n < 0 else self._b[:n]

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return None


def http_error(url: str, code: int) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, code, "x", {}, io.BytesIO(b"{}"))


class FakeHelius:
    """The Helius side of the transport: getTransfersByAddress answers keyed by (address, 'T' | 'S', order), batch
    identity rows by address. Records every request. `behave(kind, payload, n)` may return an exception to raise or a
    callable to run (for 429s, slow answers, errors)."""

    def __init__(self, mint: str = MINT, transfers: dict | None = None, identities: dict | None = None, behave=None):
        self.mint, self.transfers, self.identities, self.behave = mint, dict(transfers or {}), dict(identities or {}), behave
        self.requests: list[dict] = []
        self.lock = threading.Lock()

    def open(self, req, timeout=None):
        body = json.loads(req.data)
        with self.lock:
            n = len(self.requests)
            self.requests.append({"url": req.full_url, "body": body, "headers": dict(req.headers), "method": req.get_method(), "timeout": timeout})
        kind = "identity" if req.full_url.endswith("/v1/wallet/batch-identity") else "transfers"
        if self.behave:
            action = self.behave(kind, body, n)
            if isinstance(action, BaseException):
                raise action
            if callable(action):
                return action()
        if kind == "identity":
            return Resp(json.dumps([dict(self.identities[a], address=a) for a in body["addresses"] if a in self.identities]).encode())
        address, opts = body["params"]
        key = (address, "T" if opts.get("mint") == self.mint else "S", opts.get("sortOrder", "desc"))
        answer = self.transfers.get(key, {"data": [], "paginationToken": None})
        return Resp(json.dumps({"jsonrpc": "2.0", "id": 1, "result": answer}).encode())

    def calls(self, kind: str = "transfers") -> list[dict]:
        return [r for r in self.requests if (r["url"].endswith("batch-identity")) == (kind == "identity")]


def add(transfers: dict, holder: str, key: tuple[str, str], rows: list[dict], more: bool = False) -> None:
    transfers[(holder, *key)] = {"data": rows, "paginationToken": "next" if more else None}


A_KEY, B_KEY, C_KEY, HB_KEY, HN_KEY = ("T", "desc"), ("S", "asc"), ("S", "desc"), ("S", "asc"), ("S", "desc")


def new_run(holders_raw: dict, **files) -> Path:
    run = Path(tempfile.mkdtemp(prefix="tg-run-"))
    (run / "holders.json").write_text(json.dumps(holders_raw))
    for name, value in files.items():
        path = run / name.replace("__", "/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value))
    return run


@contextlib.contextmanager
def no_real_network():
    def refuse(*a, **k):
        raise AssertionError("a real network call was attempted")

    with mock.patch.object(tg, "default_opener", side_effect=refuse), mock.patch("socket.create_connection", side_effect=refuse):
        yield


def graph_run(run: Path, fake: FakeHelius, *, mint: str = MINT, **kw) -> dict:
    kw.setdefault("sleep", lambda s: None)
    with no_real_network():
        return tg.GraphRun(mint, run, key=KEY, inner_opener=fake, **kw).run()


# ----------------------------------------------------------------------------- requests


class RequestTests(unittest.TestCase):
    def setUp(self):
        self.holders, self.w = make_holders(MINT, 3)
        self.run_dir = new_run(self.holders)

    def tearDown(self):
        shutil.rmtree(self.run_dir, ignore_errors=True)

    def test_each_read_asks_exactly_the_documented_params_with_the_key_only_in_the_header(self):
        fake = FakeHelius()
        r = graph_run(self.run_dir, fake)
        self.assertEqual(r["status"], "empty")
        calls = fake.calls()
        self.assertEqual(len(calls), 9)  # 3 holders x A, B, C (C is on by default for the first 100); no counterparty, no identity
        seen = set()
        for c in calls:
            self.assertEqual(c["url"], "https://mainnet.helius-rpc.com/")
            self.assertEqual((c["method"], c["body"]["method"], c["body"]["jsonrpc"]), ("POST", "getTransfersByAddress", "2.0"))
            address, opts = c["body"]["params"]
            self.assertIn(address, self.w)
            self.assertEqual(opts["limit"], 100)
            seen.add((address, opts["mint"], opts.get("sortOrder")))
            self.assertEqual(c["headers"].get("X-api-key"), KEY)
            self.assertNotIn(KEY, c["url"] + json.dumps(c["body"]))
        for w in self.w:
            self.assertEqual({s for s in seen if s[0] == w}, {(w, MINT, None), (w, tg.SOL_MINT, "asc"), (w, tg.SOL_MINT, None)})
        self.assertEqual(r["request"]["calls"], {"A": 3, "B": 3, "C": 3})
        self.assertEqual(r["request"]["credits"], {"stage1": 90, "identity": 0, "stage3": 0, "total": 90})

    def test_recent_sol_is_on_by_default_for_the_first_100_holders_read(self):
        """Repair round 2: C (SOL, newest 100) for the first 100 holders read by default, the prototype's scope."""
        self.assertEqual(tg.DEFAULT_RECENT_SOL_TOP, 100)
        holders, w = make_holders(MINT, 105)
        run = new_run(holders)
        try:
            runs = {}
            for tag, kw in (("default", {}), ("off", {"recent_sol_top": 0}), ("top 3", {"recent_sol_top": 3}), ("every holder", {"recent_sol": True})):
                fake = FakeHelius()
                r = graph_run(run, fake, **kw)
                c_reads = [c["body"]["params"][0] for c in fake.calls() if c["body"]["params"][1]["mint"] == tg.SOL_MINT and c["body"]["params"][1].get("sortOrder") is None]
                runs[tag] = (c_reads, r)
        finally:
            shutil.rmtree(run, ignore_errors=True)
        rank_order = [h["wallet"] for h in runs["default"][1]["holders"]]
        self.assertEqual(sorted(runs["default"][0]), sorted(rank_order[:100]), "C for the first 100 holders read, in rank order")
        self.assertEqual(runs["default"][1]["request"]["calls"], {"A": 105, "B": 105, "C": 100})
        self.assertEqual(runs["default"][1]["settings"]["recent_sol_top"], 100)
        self.assertEqual(runs["default"][1]["settings"]["recent_sol_holders"], 100)
        self.assertEqual(runs["default"][1]["reads"]["stage1"]["planned"], 310)
        self.assertEqual(runs["off"][0], [])
        self.assertEqual(sorted(runs["top 3"][0]), sorted(rank_order[:3]))
        self.assertEqual(len(runs["every holder"][0]), 105)
        self.assertEqual(runs["every holder"][1]["settings"]["recent_sol_top"], 250, "the older switch: every holder read (--top)")

    def test_main_passes_the_recent_sol_scope(self):
        seen = []

        class Spy:
            def __init__(self, *a, **k):
                seen.append(k.get("recent_sol_top"))

            def run(self):
                return tg._base(MINT, "2026-10-20T00:00:00Z")

        holders, _ = make_holders(MINT, 2)
        run = new_run(holders)
        try:
            with mock.patch.dict(os.environ, {"HELIUS_API_KEY": KEY}), mock.patch.object(tg, "GraphRun", Spy), contextlib.redirect_stdout(io.StringIO()):
                tg.main([MINT, "--out", str(run)])
                tg.main([MINT, "--out", str(run), "--recent-sol-top", "0"])
                tg.main([MINT, "--out", str(run), "--recent-sol-top", "40"])
                tg.main([MINT, "--out", str(run), "--recent-sol", "--top", "120"])
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(tg.main([MINT, "--out", str(run), "--recent-sol-top", "-1"]), 2)
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual(seen, [100, 0, 40, 120])

    def test_the_method_is_on_the_shared_client_allowlist(self):
        from ha.helius import ALLOWED_METHODS

        self.assertIn("getTransfersByAddress", ALLOWED_METHODS)

    def test_the_default_opener_has_no_proxy_and_refuses_redirects(self):
        with mock.patch.dict(os.environ, {"https_proxy": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9"}):
            opener = tg.default_opener()
            plain = urllib.request.build_opener()
        self.assertFalse([h for h in opener.handlers if isinstance(h, urllib.request.ProxyHandler) and h.proxies])
        self.assertTrue([h for h in plain.handlers if isinstance(h, urllib.request.ProxyHandler) and h.proxies], "negative check: a plain opener takes the proxy")
        self.assertTrue(any(isinstance(h, tg.NoRedirect) for h in opener.handlers))
        self.assertIsNone(tg.NoRedirect().redirect_request(None, None, 302, "x", {}, "https://elsewhere.example/"))

    def test_a_redirect_answer_is_refused(self):
        fake = FakeHelius(behave=lambda kind, body, n: http_error("https://mainnet.helius-rpc.com/", 302))
        r = graph_run(self.run_dir, fake, top=1)  # one holder: A, B and C, under the 5-failures-in-a-row stop
        self.assertEqual(r["reads"]["stage1"]["failed_reasons"], {"redirect_disallowed": 3})
        self.assertEqual(len(fake.calls()), 3, "never retried")

    def test_hard_deadline_per_attempt(self):
        def slow():
            time.sleep(0.6)
            return Resp(b"{}")

        fake = FakeHelius(behave=lambda kind, body, n: slow)
        opener = tg.DeadlineOpener(fake, timeout_s=0.1)
        started = time.monotonic()
        with self.assertRaises(tg.TransportError) as ctx:
            opener.open(urllib.request.Request("https://mainnet.helius-rpc.com/", data=b"{}"))
        self.assertEqual(ctx.exception.reason, "timeout")
        self.assertLess(time.monotonic() - started, 0.5)

    def test_one_retry_only_after_a_429_and_none_after_other_errors(self):
        url = "https://mainnet.helius-rpc.com/"
        # one holder, workers 1: the A read comes first and gets the scripted answers, then the B and C reads answer normally
        for codes, a_requests, expect in (([429], 2, None), ([429, 429], 2, "rate_limited"), ([500], 1, "http_error"),
                                          ([503], 1, "http_error"), ([401], 1, "auth_failed"), ([404], 1, "not_found")):
            with self.subTest(codes):
                fake = FakeHelius(behave=lambda kind, body, n, codes=codes: http_error(url, codes[n]) if n < len(codes) else None)
                run = new_run(make_holders(MINT, 1)[0])
                try:
                    r = graph_run(run, fake, top=1, workers=1)
                finally:
                    shutil.rmtree(run, ignore_errors=True)
                self.assertEqual(len(fake.requests), a_requests + 2)
                read = r["reads"]["stage1"]
                self.assertEqual(read["failed_reasons"], {expect: 1} if expect else {})
                self.assertEqual(read["ok"], 2 if expect else 3)

    def test_identity_calls_are_retried_once_after_a_429_too(self):
        """The shared transport would retry a batch-identity call twice; this lane's opener stops it after one retry."""
        holders, w = make_holders(MINT, 3)
        x = wallet("shared")
        tr = {}
        add(tr, w[0], B_KEY, [row(x, w[0], "SOL", 50_000_000, T0), row(x, w[1], "SOL", 50_000_000, T0 + 1)])
        url = "https://api.helius.xyz/v1/wallet/batch-identity"
        fake = FakeHelius(transfers=tr, behave=lambda kind, body, n: http_error(url, 429) if kind == "identity" else None)
        run = new_run(holders)
        try:
            r = graph_run(run, fake, workers=1, groups=True)
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual(len(fake.calls("identity")), 2, "one identity call, one retry after its 429, never a third request")
        self.assertEqual(r["reads"]["identity"], {"calls": 1, "failed": 1})

    def test_a_429_pauses_every_worker(self):
        pauses = []
        fake = FakeHelius(behave=lambda kind, body, n: http_error("https://mainnet.helius-rpc.com/", 429) if n == 0 else None)
        orig = hf.RateGate.pause

        def record(gate, seconds):
            pauses.append(seconds)
            return orig(gate, seconds)

        with mock.patch.object(hf.RateGate, "pause", record):
            graph_run(self.run_dir, fake)
        self.assertEqual(pauses, [1.0])

    def test_the_pace_is_six_per_second(self):
        self.assertEqual(tg.REQUEST_RATE_CAP_PER_S, 6)
        starts = []
        orig = hf.RateGate.wait_turn

        def record(gate):
            t = orig(gate)
            starts.append(t)
            return t

        holders, _ = make_holders(MINT, 8)  # 8 holders x A, B, C
        run = new_run(holders)
        try:
            with mock.patch.object(hf.RateGate, "wait_turn", record):
                graph_run(run, FakeHelius(), sleep=time.sleep, workers=6)
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual(len(starts), 24)
        for i in range(len(starts) - 6):
            self.assertGreaterEqual(starts[i + 6] - starts[i], 1.0, "never more than 6 starts in any 1 s window")


# ----------------------------------------------------------------------------- budget


class BudgetTests(unittest.TestCase):
    def test_the_estimate_and_the_default_cap(self):
        self.assertEqual(tg.DEFAULT_MAX_CREDITS, 12_000)
        self.assertEqual(tg.estimate(250, 300, 0), {"stage1": 5000, "identity": 1000, "stage3": 6000, "total": 12000})
        self.assertEqual(tg.estimate(250, 300, 250)["stage1"], 7500)
        self.assertEqual(tg.estimate(250, 0, 100), {"stage1": 6000, "identity": 1000, "stage3": 0, "total": 7000}, "the default: C for the first 100")
        self.assertEqual(tg.estimate(40, 0, 100)["stage1"], 1200, "C is never asked for more holders than are read")
        with self.assertRaises(TypeError):
            tg.estimate(250, 0, True)  # the old boolean switch is refused: a count of holders is needed
        hop, note, est = tg.plan_budget(250, 300, 0, 12_000)
        self.assertEqual((hop, note, est["total"]), (300, None, 12_000))

    def test_hop_max_is_lowered_first_and_the_run_says_so(self):
        hop, note, est = tg.plan_budget(250, 300, 250, 12_000)
        self.assertEqual(hop, 175)
        self.assertEqual(note, "--hop-max lowered from 300 to 175 so the estimate fits --max-credits 12,000")
        self.assertLessEqual(est["total"], 12_000)
        hop, note, _ = tg.plan_budget(250, 300, 100, 12_000)
        self.assertEqual((hop, note), (250, "--hop-max lowered from 300 to 250 so the estimate fits --max-credits 12,000"), "--groups with the default C")
        hop, note, _ = tg.plan_budget(250, 300, 0, 6_000)
        self.assertEqual(hop, 0)
        hop, note, _ = tg.plan_budget(250, 300, 0, 5_999)
        self.assertIsNone(hop)
        self.assertIn("the run did not start", note)

    def test_a_run_over_the_cap_refuses_before_any_request(self):
        holders, _ = make_holders(MINT, 30)
        run = new_run(holders)
        try:
            fake = FakeHelius()
            r = graph_run(run, fake, max_credits=500)
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual((r["status"], r["reason"]), ("unavailable", "credit_estimate_over_cap"))
        self.assertEqual(fake.requests, [])
        self.assertEqual(r["request"]["credits"]["total"], 0)

    def test_charge_before_send_and_a_stopped_run_is_marked(self):
        holders, _ = make_holders(MINT, 30)
        run = new_run(holders)
        try:
            fake = FakeHelius()
            with mock.patch.object(tg, "plan_budget", return_value=(0, None, tg.estimate(30, 0, 30))):  # let a short budget start
                r = graph_run(run, fake, max_credits=250, workers=6)
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual(r["stopped_early"], {"reason": "credit budget reached"})
        self.assertEqual(r["request"]["credits"]["total"], 250)
        self.assertEqual((len(fake.requests), r["request"]["requests_sent"]), (25, 25), "a refused charge is never sent")
        self.assertEqual(r["reads"]["stage1"]["not_reached"], 65, "30 holders x A, B, C = 90 planned, 25 sent")
        self.assertEqual(r["request"]["calls"].get("identity"), None, "no later stage starts after the budget stopped the run")
        self.assertIn("RUN STOPPED EARLY: credit budget reached", tg.status_line(r))
        (run_dir := new_run(holders)) and (run_dir / "followup").mkdir()
        try:
            (run_dir / "followup" / "transfer_graph.json").write_text(json.dumps(r))
            self.assertIn("  RUN STOPPED EARLY: credit budget reached; what follows uses only the reads that finished.", tg.present(run_dir))
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)

    def test_parallel_reads_never_pass_the_cap(self):
        for workers in (1, 3, 10):
            with self.subTest(workers=workers):
                holders, _ = make_holders(MINT, 40)
                run = new_run(holders)
                try:
                    fake = FakeHelius()
                    with mock.patch.object(tg, "plan_budget", return_value=(0, None, tg.estimate(40, 0, 40))):
                        r = graph_run(run, fake, max_credits=333, workers=workers)
                finally:
                    shutil.rmtree(run, ignore_errors=True)
                self.assertLessEqual(r["request"]["credits"]["total"], 333)
                self.assertEqual(len(fake.requests) * 10, r["request"]["credits"]["total"])

    def test_credits_are_reported_per_stage(self):
        for over in (VALIDATED, {}):
            with self.subTest(**over):
                r = Replay("dkyc", **over).result
                c, calls = r["request"]["credits"], r["request"]["calls"]
                self.assertEqual(c["total"], c["stage1"] + c["identity"] + c["stage3"])
                self.assertEqual(c["stage1"], 10 * (calls["A"] + calls["B"] + calls.get("C", 0)))
                self.assertEqual(c["stage3"], 10 * (calls.get("HB", 0) + calls.get("HN", 0)))
                self.assertEqual(c["identity"], 100 * calls.get("identity", 0))
                self.assertLessEqual(c["total"], 12_000)

    def test_the_budget_lock_holds_parallel_charges_to_the_cap(self):
        """Four workers charge at once against a cap of one read. The budget's check reads `spent` and then waits at a
        barrier for the other three: without the lock all four pass the check together (four requests, 40 credits);
        with it the other three wait on the lock, the barrier gives up after 1 s, and only one read is charged and sent.
        No timing race decides the outcome: the barrier forces the interleaving."""
        barrier = threading.Barrier(4)

        class InterleavingBudget(hf.Budget):
            def __init__(self, max_credits):
                self._first, self._value = threading.local(), 0
                super().__init__(max_credits)

            @property
            def spent(self):
                value = self._value
                if threading.current_thread() is not threading.main_thread() and not getattr(self._first, "done", False):
                    self._first.done = True  # the check of this thread's first charge
                    with contextlib.suppress(threading.BrokenBarrierError):
                        barrier.wait(timeout=1.0)
                return value

            @spent.setter
            def spent(self, value):
                self._value = value

        holders, _ = make_holders(MINT, 4)
        run = new_run(holders)
        try:
            fake = FakeHelius()
            with mock.patch.object(hf, "Budget", InterleavingBudget), mock.patch.object(tg, "plan_budget", return_value=(0, None, tg.estimate(4, 0, 4))):
                r = graph_run(run, fake, max_credits=10, workers=4)
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual(len(fake.requests), 1, "one read fits the cap; the other parallel charges are refused before sending")
        self.assertEqual(r["request"]["credits"]["total"], 10)
        self.assertEqual(r["stopped_early"], {"reason": "credit budget reached"})


# ----------------------------------------------------------------------------- edges, bursts, exclusions (pure rules)


def facts(*rows: dict, mint: str = MINT, reads: list | None = None) -> list[dict]:
    out = []
    for r in rows:
        f = tg.parse_row(r, mint)
        assert f is not None, r
        f["reads"] = reads or [["B", r["toUserAccount"]]]
        out.append(f)
    return out


def holders_used(n: int = 20) -> list[dict]:
    return [{"rank": i + 2, "wallet": wallet(f"h{i}"), "share_pct": 1.0} for i in range(n)]


def build(hs, fs, static=frozenset(), app=None, services=None, hop_read=frozenset()):
    return tg.build_graph(hs, fs, static=set(static), app=app or {}, services=services or {}, hop_read=set(hop_read))


class EdgeTests(unittest.TestCase):
    def setUp(self):
        self.hs = holders_used(20)
        self.w = [h["wallet"] for h in self.hs]

    def test_direct_this_token_any_amount_or_sol_from_0_001(self):
        g = build(self.hs, facts(row(self.w[0], self.w[1], "TOKEN", 1, T0), row(self.w[2], self.w[3], "SOL", 1_000_000, T0),
                                 row(self.w[4], self.w[5], "SOL", 999_999, T0), row(self.w[6], self.w[7], "WSOL", 1_000_000, T0)))
        pairs = {(e["rank_a"], e["rank_b"]) for e in g["edges"]["direct"]}
        self.assertEqual(pairs, {(2, 3), (4, 5), (8, 9)})
        self.assertEqual(len(g["clusters"]), 3)
        ev = g["edges"]["direct"][0]["evidence"][0]
        self.assertEqual(set(ev), {"signature", "t", "time", "from", "to", "asset", "amount", "raw", "decimals", "read", "read_of"})

    def test_via_wallet_needs_two_holders_and_0_01_sol_or_any_token(self):
        x, y, z = wallet("x"), wallet("y"), wallet("z")
        g = build(self.hs, facts(row(x, self.w[0], "SOL", 10_000_000, T0), row(self.w[1], x, "SOL", 10_000_000, T0 + 1),
                                 row(y, self.w[2], "SOL", 9_999_999, T0), row(y, self.w[3], "SOL", 20_000_000, T0),
                                 row(self.w[4], z, "TOKEN", 1, T0), row(self.w[5], z, "TOKEN", 1, T0)))
        via = {e["wallet"]: e["holders"] for e in g["edges"]["via_wallet"]}
        self.assertEqual(via, {x: [2, 3], z: [6, 7]})
        self.assertEqual([c["size"] for c in g["clusters"]], [2, 2])

    def test_via_wallet_pair_needs_both_wallets_read_and_0_1_sol_between_them(self):
        a, b = wallet("pa"), wallet("pb")
        fs = facts(row(a, self.w[0], "SOL", 1_000_000_000, T0), row(b, self.w[1], "SOL", 1_000_000_000, T0),
                   row(a, b, "SOL", 100_000_000, T0 + 5, seed="bridge"), reads=None)
        fs[2]["reads"] = [["HB", a]]
        self.assertEqual(build(self.hs, fs, hop_read={a})["edges"]["via_wallet_pair"], [], "both wallets must be read one hop out")
        g = build(self.hs, fs, hop_read={a, b})
        self.assertEqual([(e["wallets"], e["holders"]) for e in g["edges"]["via_wallet_pair"]], [(sorted([a, b]), [2, 3])])
        self.assertEqual(g["clusters"][0]["edge_counts"], {"direct": 0, "via_wallet": 0, "via_wallet_pair": 1})
        fs_small = copy.deepcopy(fs)
        fs_small[2]["raw"] = 99_999_999
        self.assertEqual(build(self.hs, fs_small, hop_read={a, b})["edges"]["via_wallet_pair"], [])

    def test_a_link_never_goes_through_a_blocked_address(self):
        svc, app, off = wallet("svc"), wallet("app"), pda("prog")
        rows = []
        for blocked in (svc, app, off, POOL):
            rows += [row(blocked, self.w[0], "SOL", 50_000_000, T0, seed=f"{blocked}a"), row(blocked, self.w[1], "SOL", 50_000_000, T0, seed=f"{blocked}b")]
        g = build(self.hs, facts(*rows), static={POOL}, app={app: {}}, services={svc: ["category:exchange"]})
        self.assertEqual(g["clusters"], [])
        self.assertEqual(g["edges"]["via_wallet"], [])

    def test_a_service_holder_never_links(self):
        g = build(self.hs, facts(row(self.w[0], self.w[1], "TOKEN", 5, T0)), services={self.w[0]: ["type:exchange"]})
        self.assertEqual(g["edges"]["direct"], [])
        self.assertEqual(g["holders_not_linked"], [{"rank": 2, "wallet": self.w[0], "why": "service"}])

    def test_rows_that_cannot_link_are_dropped_at_parse(self):
        good = row(self.w[0], self.w[1], "SOL", 5, T0)
        self.assertIsNotNone(tg.parse_row(good, MINT))
        bad = [dict(good, type="mint"), dict(good, fromUserAccount=None), dict(good, mint=wallet("other mint")), dict(good, amount="1.5"),
               dict(good, decimals=6), dict(good, signature="short"), dict(good, toUserAccount=self.w[0]), dict(good, blockTime="x"),
               dict(good, fromUserAccount="0OIl" * 10)]
        for b in bad:
            self.assertIsNone(tg.parse_row(b, MINT), b)
        echo = dict(good, fromUserAccount=KEY[:20] + "AAAAAAAAAAAAAAAAAAAAAA")
        self.assertIsNone(tg.parse_row(echo, MINT, KEY))

    def test_an_unwrap_into_another_wallet_moves_sol_and_counts(self):
        """startupSI, 2026-10-20: every Bubblemaps linking wallet funded its holder by closing a wSOL account into the holder's
        balance (Helius type unwrap, fromUserAccount = owner, toUserAccount = lamport destination)."""
        unwrap = dict(row(self.w[0], self.w[1], "SOL", 5_689_434_771, T0), type="unwrap")
        f = tg.parse_row(unwrap, MINT)
        self.assertEqual((f["from"], f["to"], f["asset"], f["raw"]), (self.w[0], self.w[1], "SOL", 5_689_434_771))
        self.assertIsNone(tg.parse_row(dict(unwrap, toUserAccount=self.w[0]), MINT), "rent back to the owner moves nothing between wallets")
        self.assertIsNone(tg.parse_row(dict(unwrap, toUserAccount=None), MINT))
        self.assertIsNone(tg.parse_row(dict(row(self.w[0], self.w[1], "TOKEN", 5, T0), type="unwrap"), MINT), "only SOL unwraps")
        for other in ("wrap", "mint", "burn", "changeOwner", "withdrawWithheldFee"):
            self.assertIsNone(tg.parse_row(dict(unwrap, type=other), MINT), other)
        x = wallet("unwrapper")
        g = build(self.hs, facts(dict(row(x, self.w[0], "SOL", 5_000_000_000, T0), type="unwrap"), dict(row(x, self.w[1], "SOL", 5_000_000_000, T0 + 9), type="unwrap")))
        self.assertEqual([e["wallet"] for e in g["edges"]["via_wallet"]], [x])


class BurstTests(unittest.TestCase):
    def setUp(self):
        self.hs = holders_used(30)
        self.w = [h["wallet"] for h in self.hs]
        self.sender = wallet("sender")

    def sends(self, times, asset="SOL", amount=10_000_000, sender=None):
        return [row(sender or self.sender, self.w[i], asset, amount, t, seed=f"b{i}{t}{asset}") for i, t in enumerate(times)]

    def test_ten_holders_within_five_minutes_is_a_burst_and_nine_is_not(self):
        g = build(self.hs, facts(*self.sends([T0 + 30 * i for i in range(10)])))
        self.assertEqual([(b["count"], b["span_s"], b["kind"]) for b in g["bursts"]], [(10, 270, "wallet")])
        self.assertEqual(build(self.hs, facts(*self.sends([T0 + 30 * i for i in range(9)])))["bursts"], [])

    def test_the_window_edge(self):
        at_edge = [T0] * 9 + [T0 + 300]
        self.assertEqual(len(build(self.hs, facts(*self.sends(at_edge)))["bursts"]), 1)
        past = [T0] * 9 + [T0 + 301]
        self.assertEqual(build(self.hs, facts(*self.sends(past)))["bursts"], [])

    def test_slow_sends_are_never_a_burst_and_sends_close_together_extend_one(self):
        slow = [T0 + 400 * i for i in range(30)]
        self.assertEqual(build(self.hs, facts(*self.sends(slow)))["bursts"], [])
        chained = [T0 + 20 * i for i in range(12)] + [T0 + 240 + 200 * i for i in range(1, 19)]
        b = build(self.hs, facts(*self.sends(chained)))["bursts"]
        self.assertEqual([(x["count"], x["peak_in_window"]) for x in b], [(30, 12)])
        self.assertEqual(b[0]["span_s"], chained[-1] - chained[0])

    def test_dust_is_not_a_send_and_this_token_counts_at_any_amount(self):
        self.assertEqual(build(self.hs, facts(*self.sends([T0] * 10, amount=999_999)))["bursts"], [])
        self.assertEqual(len(build(self.hs, facts(*self.sends([T0] * 10, asset="TOKEN", amount=1)))["bursts"]), 1)

    def test_never_capped_and_a_dust_spray_never_merges(self):
        g = build(self.hs, facts(*self.sends([T0 + i for i in range(30)], amount=5_000_000)))  # 0.005 SOL each: a send, under 0.01 SOL: a dust spray
        self.assertEqual((g["bursts"][0]["count"], g["bursts"][0]["dust_spray"], g["bursts"][0]["max_per_recipient_sol"]), (30, True, "0.005"))
        self.assertEqual((g["clusters"], g["merged_view"]), ([], []), "a dust spray is no transfer link and is left out of the merged view")
        g = build(self.hs, facts(*self.sends([T0 + i for i in range(30)], asset="TOKEN", amount=5)))
        self.assertEqual((g["bursts"][0]["dust_spray"], [m["size"] for m in g["merged_view"]]), (False, [30]))

    def test_the_dust_label(self):
        """A SOL burst is a dust spray only when every recipient got under 0.01 SOL in the burst; a token burst never is; the floor and
        the window are unchanged."""
        under = build(self.hs, facts(*self.sends([T0 + i for i in range(12)], amount=9_999_999)))["bursts"][0]
        self.assertTrue(under["dust_spray"])
        rows = self.sends([T0 + i for i in range(12)], amount=1_000_000)
        rows[3] = row(self.sender, self.w[3], "SOL", 10_000_000, T0 + 3, seed="one big")
        self.assertFalse(build(self.hs, facts(*rows))["bursts"][0]["dust_spray"], "one recipient with 0.01 SOL: not a dust spray")
        two = self.sends([T0 + i for i in range(12)], amount=1_000_000) + [row(self.sender, self.w[0], "SOL", 9_000_000, T0 + 20, seed="second send")]
        self.assertFalse(build(self.hs, facts(*two))["bursts"][0]["dust_spray"], "per recipient: two sends adding up to 0.01 SOL")
        self.assertEqual(build(self.hs, facts(*self.sends([T0 + i for i in range(9)], amount=1_000_000)))["bursts"], [], "the count threshold is unchanged")
        self.assertEqual(build(self.hs, facts(*self.sends([T0] * 10, amount=999_999)))["bursts"], [], "the 0.001 SOL floor is unchanged")

    def test_a_burst_of_0_01_sol_or_more_is_also_a_via_wallet_link_of_its_sender(self):
        g = build(self.hs, facts(*self.sends([T0 + i for i in range(30)], amount=10_000_000)))
        self.assertEqual((len(g["bursts"]), [e["wallet"] for e in g["edges"]["via_wallet"]], g["clusters"][0]["size"]), (1, [self.sender], 30))

    def test_program_accounts_and_services_are_reported_apart_and_never_link(self):
        prog, svc, app = pda("disperse"), wallet("cex"), wallet("relayer")
        rows = self.sends([T0] * 10, sender=prog) + self.sends([T0] * 10, sender=svc) + self.sends([T0] * 10, sender=app) + self.sends([T0] * 10, sender=POOL)
        g = build(self.hs, facts(*rows), static={POOL}, app={app: {}}, services={svc: ["category:exchange"]})
        self.assertEqual(g["bursts"], [])
        self.assertEqual(sorted(b["kind"] for b in g["bursts_not_linked"]), ["program_account", "service"])
        self.assertEqual(g["merged_view"], [])

    def test_a_program_account_paying_out_this_token_is_a_pool_trade_counted_only(self):
        prog = pda("other pool authority")
        g = build(self.hs, facts(*self.sends([T0] * 12, sender=prog, asset="TOKEN", amount=5)))
        self.assertEqual((g["bursts"], g["bursts_not_linked"], g["program_token_bursts_not_listed"]), ([], [], 1))
        g = build(self.hs, facts(*self.sends([T0] * 12, sender=prog, asset="SOL")))
        self.assertEqual([b["kind"] for b in g["bursts_not_linked"]], ["program_account"], "SOL from a program account is still listed apart")

    def test_repeated_rounds_are_summarised(self):
        rows = []
        for k in range(4):
            rows += self.sends([T0 + 1000 * k] * 20, sender=wallet(f"round{k}"))
        rows += self.sends([T0 + 9000] * 10, sender=wallet("other"))
        g = build(self.hs, facts(*rows))
        self.assertEqual([(r["senders"], r["typical_holders"], r["bursts"]) for r in g["rounds"]], [(4, 20, 4)])


class ServiceRuleTests(unittest.TestCase):
    def test_the_exact_rule(self):
        cases = {("Centralized Exchange", "exchange"): True, ("Cross-chain Bridge", "protocol"): True, ("Trading App or Trading Bot", "wallet"): True,
                 ("Authority", "wallet"): True, ("Transaction Sending", "protocol"): True, ("Fees", "protocol"): True, ("DeFi", "protocol"): True,
                 ("Individual", "wallet"): False, ("Treasury", "wallet"): False, (None, "unknown"): False, ("Fee Payer", "wallet"): False,
                 ("Approved", "wallet"): False}
        for (cat, typ), service in cases.items():
            self.assertEqual(bool(tg.is_service({"category": cat, "type": typ})), service, (cat, typ))

    def test_names_and_tags_are_not_used(self):
        self.assertEqual(tg.is_service({"name": "Binance Hot Wallet", "category": None, "type": "unknown", "tags": ["Binance Deposit", "exchange"]}), [])

    def test_the_rule_text_names_every_word(self):
        for w in tg.SERVICE_WORDS:
            self.assertIn(w, tg.SERVICE_RULE)
        for c in ("Authority", "Transaction Sending", "Fees"):
            self.assertIn(c, tg.SERVICE_RULE)


class AppListTests(unittest.TestCase):
    PINNED = {"AgmLJBMDCqWynYnQiPCuj9ewsNNsBJXyzoUhD9LJzN51", "6Mvb6rmQ3p8o954wEHndriNf7smn33XZaHTVL32ndGPH", "6Dp9t57fP3RY6rZx1QAvX7Y1Ang2taez34BCyECwWCvS",
              "ARu4n5mFdZogZAravu7CcizaojWnS6oqka37gdLT5SZn", "8FnX3xo2yYw3EUE6w3nQA4GfXGS9wpK6oj3veJpbFzLo", "8ekCy2jHHUbW2yeNGFWYJT9Hm9FW7SvZcZK66dSZCDiF",
              "2LAYGGSiF3QfyQEG1Gb3UGAsuzvD21zjHEW88v2XZ7cW", "FHpcNSe6tb2n15bAdq4BkeYWGyZKFD7yLYrH92ng7wCT"}

    def test_the_list_keeps_the_prototype_wallets_each_with_a_reason_and_a_source(self):
        app = tg.load_app_list()
        self.assertLessEqual(self.PINNED, set(app), "additions only: a listed wallet is removed only by a ticket")
        data = json.loads(tg.APP_LIST_PATH.read_text())
        self.assertIn("Additions only", data["rule"])
        for e in data["entries"]:
            self.assertTrue(e["reason"].strip() and e["source"].strip() and e["ticket"] and e["added"], e["address"])
            self.assertIsNone(REASSURING.search(e["reason"]))

    def test_a_damaged_list_stops_the_run_before_any_credit(self):
        holders, _ = make_holders(MINT, 3)
        run = new_run(holders, **{"bad.json": "{\"schema\": \"x\"}"})
        try:
            fake = FakeHelius()
            with no_real_network():
                r = tg.GraphRun(MINT, run, key=KEY, inner_opener=fake, app_list_path=run / "bad.json").run()
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual((r["status"], r["reason"], fake.requests), ("unavailable", "app_list_unreadable", []))


# ----------------------------------------------------------------------------- the run: inputs, stages, partial runs, key


class RunTests(unittest.TestCase):
    def test_holders_input_is_validated_and_off_curve_rows_are_skipped_and_named(self):
        off = pda("holder pda")
        holders, w = make_holders(MINT, 5, extra={off: 499.5})
        run = new_run(holders)
        try:
            r = graph_run(run, FakeHelius())
            self.assertEqual([h["wallet"] for h in r["holders"]], w)
            self.assertEqual([(s["wallet"], s["reason"]) for s in r["holders_skipped"]], [(off, "off the curve (a program account, not a wallet)")])
            for broken, reason in ((dict(holders, mint=wallet("x")), "holders_json_other_mint"), (dict(holders, top_holders=holders["top_holders"][:1] + [{"rank": 9}]), "holders_json_unreadable"),
                                   ("not json", "holders_json_unreadable")):
                (run / "holders.json").write_text(broken if isinstance(broken, str) else json.dumps(broken))
                fake = FakeHelius()
                r = graph_run(run, fake)
                self.assertEqual((r["status"], r["reason"], fake.requests), ("unavailable", reason, []))
            (run / "holders.json").unlink()
            self.assertEqual(graph_run(run, FakeHelius())["reason"], "holders_json_missing")
        finally:
            shutil.rmtree(run, ignore_errors=True)

    def test_stage_three_reads_the_ranked_counterparties_that_are_not_services(self):
        holders, w = make_holders(MINT, 6)
        big, small, svc, tiny, off = wallet("big"), wallet("small"), wallet("svc2"), wallet("tiny"), pda("o")
        tr = {}
        add(tr, w[0], B_KEY, [row(big, w[0], "SOL", 5_000_000_000, T0), row(svc, w[0], "SOL", 9_000_000_000, T0), row(tiny, w[0], "SOL", 99_999_999, T0),
                              row(off, w[0], "SOL", 9_000_000_000, T0)])
        add(tr, w[1], B_KEY, [row(w[1], small, "SOL", 200_000_000, T0)])
        add(tr, big, HB_KEY, [row(big, w[3], "SOL", 10_000_000, T0 + 5)])
        fake = FakeHelius(transfers=tr, identities={svc: {"name": "X Exchange", "category": "Centralized Exchange", "type": "exchange", "tags": []}})
        run = new_run(holders)
        try:
            r = graph_run(run, fake, groups=True)
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual([x["wallet"] for x in r["stage3"]["read"]], [big, small])
        self.assertEqual(r["stage3"]["services_skipped"], 1)
        hop = [c["body"]["params"] for c in fake.calls() if c["body"]["params"][0] in (big, small)]
        self.assertEqual(sorted((p[0], p[1].get("sortOrder", "desc")) for p in hop), sorted([(big, "asc"), (big, "desc"), (small, "asc"), (small, "desc")]))
        self.assertEqual([e["wallet"] for e in r["edges"]["via_wallet"]], [big], "w[0] and w[3] appear in big's own transfers")
        ident = fake.calls("identity")
        self.assertEqual(len(ident), 1)
        self.assertEqual(ident[0]["body"]["addresses"], [svc, big, small], "hop candidates ranked by the SOL they moved; under 0.1 SOL and program accounts are no candidates")
        self.assertIn("X Exchange", json.dumps(r["exclusions"]["services"]))

    def test_five_failures_in_a_row_stop_the_run(self):
        holders, _ = make_holders(MINT, 10)
        run = new_run(holders)
        try:
            fake = FakeHelius(behave=lambda kind, body, n: http_error("https://mainnet.helius-rpc.com/", 500))
            r = graph_run(run, fake, workers=1)
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual(r["stopped_early"], {"reason": "5 reads failed in a row"})
        self.assertEqual(len(fake.requests), 5)
        self.assertEqual((r["status"], r["reason"]), ("unavailable", "stopped_before_any_read"))

    def test_ctrl_c_writes_the_partial_file_and_exits_130(self):
        holders, _ = make_holders(MINT, 10)
        run = new_run(holders)
        try:
            def behave(kind, body, n):
                if n == 4:
                    raise KeyboardInterrupt
                return None

            fake = FakeHelius(behave=behave)
            with no_real_network(), mock.patch.dict(os.environ, {"HELIUS_API_KEY": KEY}), mock.patch.object(tg, "default_opener", return_value=fake), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                code = tg.main([MINT, "--out", str(run), "--workers", "1"])
            saved = json.loads((run / "followup" / "transfer_graph.json").read_text())
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual(code, 130)
        self.assertEqual(saved["stopped_early"], {"reason": "interrupted (Ctrl-C)"})
        self.assertIn("RUN STOPPED EARLY: interrupted (Ctrl-C)", out.getvalue())

    def test_the_key_never_reaches_the_file_or_the_output(self):
        holders, w = make_holders(MINT, 4)
        echo_addr = wallet("echo")
        tr = {}
        add(tr, w[0], B_KEY, [row(echo_addr, w[0], "SOL", 5_000_000_000, T0), row(echo_addr, w[1], "SOL", 5_000_000_000, T0)])
        ids = {echo_addr: {"name": f"Wallet {KEY}", "category": f"{KEY[:12]} Exchange", "type": "unknown", "tags": [KEY]}}

        def behave(kind, body, n):
            if kind == "transfers" and body["params"][0] == w[2]:
                return lambda: Resp(json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": f"bad key {KEY}"}}).encode())
            return None

        fake = FakeHelius(transfers=tr, identities=ids, behave=behave)
        run = new_run(holders)
        try:
            with no_real_network(), mock.patch.dict(os.environ, {"HELIUS_API_KEY": KEY}), mock.patch.object(tg, "default_opener", return_value=fake), \
                    contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                code = tg.main([MINT, "--out", str(run), "--groups"])  # with --groups the shared wallet's identity (echoing the key) is read
                present = io.StringIO()
                with contextlib.redirect_stdout(present):
                    tg.main(["--present", str(run), "--groups"])
                    tg.main(["--present", str(run)])
            text = (run / "followup" / "transfer_graph.json").read_text()
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual(code, 0)
        for blob in (text, out.getvalue(), err.getvalue(), present.getvalue()):
            self.assertFalse(any(KEY[i:i + 8] in blob for i in range(len(KEY) - 7)), "no 8-character piece of the key anywhere (checked here, not with the script's own helper)")
        self.assertIn("rpc_error", text)

    def test_the_save_backstop_refuses_a_result_that_echoes_the_key(self):
        """The last guard in _save: a result holding any 8-character piece of the key is replaced by a bare unavailable
        record (reason key_echo_refused) before it is written or summarised; a result without one is saved as it is."""
        holders, _ = make_holders(MINT, 2)
        run = new_run(holders)
        (run / "followup").mkdir()
        try:
            leaky = tg._base(MINT, "2026-10-20T00:00:00Z")
            leaky.update(status="ok", bursts=[{"sender": "x", "note": "echo " + KEY[3:14] + " echo"}], clusters=[], bursts_not_linked=[])
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = tg._save(run, leaky, KEY)
            text = (run / "followup" / "transfer_graph.json").read_text()
            saved = json.loads(text)
            self.assertEqual(code, 0)
            self.assertEqual((saved["status"], saved["reason"], saved["mint"]), ("unavailable", "key_echo_refused", MINT))
            self.assertNotIn("bursts", saved)
            self.assertFalse(any(KEY[i:i + 8] in text + out.getvalue() for i in range(len(KEY) - 7)))
            self.assertTrue(out.getvalue().startswith("unavailable (key_echo_refused; "), out.getvalue())
            plain = tg._base(MINT, "2026-10-20T00:00:00Z")
            plain.update(status="empty", bursts=[], clusters=[], bursts_not_linked=[])
            with contextlib.redirect_stdout(io.StringIO()) as out:
                tg._save(run, plain, KEY)
            self.assertEqual(json.loads((run / "followup" / "transfer_graph.json").read_text())["status"], "empty", "a result without a key piece is kept")
        finally:
            shutil.rmtree(run, ignore_errors=True)

    def test_the_merged_facts_never_depend_on_the_order_the_reads_finished(self):
        """The same transfer seen by two reads (B and C of one holder, or HB and HN of one counterparty) always names the
        same reads, whichever finished first (repair round 2: the order came from the worker pool before)."""
        holders, w = make_holders(MINT, 2)
        run = new_run(holders)
        try:
            same = row(w[0], w[1], "SOL", 5_000_000, T0, seed="both")
            reads = [(("B", w[0]), {"status": "ok", "rows": [tg.parse_row(same, MINT)]}), (("C", w[0]), {"status": "ok", "rows": [tg.parse_row(same, MINT)]}),
                     (("C", w[1]), {"status": "ok", "rows": [tg.parse_row(same, MINT)]})]
            out = []
            for order in (reads, reads[::-1], [reads[1], reads[2], reads[0]]):
                g = tg.GraphRun(MINT, run, key=KEY)
                g.reads = dict(order)
                out.append(g._facts())
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual(out[0], out[1])
        self.assertEqual(out[0], out[2])
        self.assertEqual(out[0][0]["reads"], [["B", w[0]]] + [["C", a] for a in sorted((w[0], w[1]))], "kinds in a fixed order (A, B, C, HB, HN), then the address")

    def test_a_missing_or_malformed_key_saves_a_file_and_sends_nothing(self):
        holders, _ = make_holders(MINT, 2)
        run = new_run(holders)
        try:
            for env, reason in (({}, "missing_key"), ({"HELIUS_API_KEY": "bad key with spaces"}, "key_format")):
                clean = {k: v for k, v in os.environ.items() if k not in ("HELIUS_API_KEY", "HOLDER_FORENSICS_ENV")}
                with no_real_network(), mock.patch.dict(os.environ, {**clean, **env}, clear=True), mock.patch.object(hf, "find_env_file", side_effect=hf.ConfigError("no .env found")), \
                        contextlib.redirect_stdout(io.StringIO()) as out:
                    code = tg.main([MINT, "--out", str(run)])
                saved = json.loads((run / "followup" / "transfer_graph.json").read_text())
                self.assertEqual((code, saved["status"], saved["reason"]), (0, "unavailable", reason))
                self.assertNotIn("bad key", out.getvalue())
        finally:
            shutil.rmtree(run, ignore_errors=True)

    def test_bad_options_exit_2_before_anything(self):
        for argv in (["notamint", "--out", "x"], [MINT], [MINT, "--out", "x", "--hop-max", "-1"], [MINT, "--out", "x", "--workers", "11"], ["--present", "/nonexistent/x"]):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(tg.main(argv), 2, argv)


# ----------------------------------------------------------------------------- the prototype replay


VALIDATED = {"groups": True, "recent_sol_top": 0}  # the DKYc --groups configuration of the validation (C off, hop 300): replayed exactly
DEFAULT_LISTS = REPLAY / "default_lists_20261020.json"  # repair round 2: the 78rn and GezC default-mode lists, pinned


def burst_list(result: dict) -> dict:
    """The lists the default block shows, in a form a pin can hold: funding bursts, dust sprays, program or service
    bursts (sender, asset, holders, span, start, kind) and the count of program-account token bursts not listed."""
    def rows(bursts):
        return [[b["sender"], b["asset"], b["count"], b["span_s"], b["start"], b["kind"]] for b in bursts]

    bursts = result["bursts"]
    return {"funding": rows([b for b in bursts if not b["dust_spray"]]), "dust": rows([b for b in bursts if b["dust_spray"]]),
            "program_or_service": rows(result["bursts_not_linked"]), "program_token_bursts_not_listed": result["program_token_bursts_not_listed"],
            "rounds": [[x["asset"], x["senders"], x["typical_holders"], x["bursts"]] for x in result["rounds"]]}


class Replay:
    """GraphRun over a replay fixture: the fake answers from the trimmed public rows; 0 credits, no network."""

    cache: dict[str, "Replay"] = {}

    def __new__(cls, case: str, **overrides):
        key = case + json.dumps(overrides, sort_keys=True)
        if key not in cls.cache:
            obj = super().__new__(cls)
            obj._load(case, overrides)
            cls.cache[key] = obj
        return cls.cache[key]

    def _load(self, case: str, overrides: dict) -> None:
        with gzip.open(REPLAY / f"{case}_replay_20261020.json.gz", "rt", encoding="utf-8") as fh:
            self.fx = json.load(fh)
        self.mint = self.fx["mint"]
        addrs = self.fx["addresses"]
        codes = {"S": tg.SOL_MINT, "W": tg.WSOL_MINT, "T": self.mint, "U": tg.SOL_MINT}  # U: a SOL unwrap into another wallet
        transfers = {}
        for k, v in self.fx["transfers"].items():
            a, m, o = k.split("|")
            data = [{"signature": placeholder_sig(s), "blockTime": t, "type": "unwrap" if c == "U" else "transfer", "fromUserAccount": addrs[f],
                     "toUserAccount": addrs[to], "mint": codes[c], "amount": amt, "decimals": dec} for s, t, f, to, c, amt, dec in v["rows"]]
            transfers[(addrs[int(a)], m, o)] = {"data": data, "paginationToken": "next" if v["more"] else None}
        self.fake = FakeHelius(self.mint, transfers, self.fx["identities"])
        self.run_dir = new_run(self.fx["holders"])
        settings = dict(self.fx["settings"], **{k: v for k, v in overrides.items() if not k.startswith("_")})
        self.result = graph_run(self.run_dir, self.fake, mint=self.mint, **settings)
        (self.run_dir / "followup").mkdir(exist_ok=True)
        (self.run_dir / "followup" / "transfer_graph.json").write_text(json.dumps(self.result))

    def members(self, fixture: str) -> tuple[dict, list]:
        """The prototype's Bubblemaps member read, resolved to full addresses the way assess does."""
        d = json.loads((FIX / fixture).read_text())
        holders, _ = hf.load_run_holders(self.fx["holders"], self.mint)
        clusters = [{"cluster": c["cluster"], "wallets": c["wallets"], "supply_pct": c["supply_pct"], "members": copy.deepcopy(c["members"]), "members_complete": True}
                    for c in d["clusters"]]
        hf.resolve_members([c["members"] for c in clusters], holders)
        return {"read": True, "clusters": clusters}, holders["_ranked"]


def tearDownModule():
    for r in Replay.cache.values():
        shutil.rmtree(r.run_dir, ignore_errors=True)


class PrototypeReplayTests(unittest.TestCase):
    def test_dkyc_bubblemaps_clusters_5_7_8_9_10_are_reproduced(self):
        rp = Replay("dkyc", **VALIDATED)
        self.assertEqual(rp.fake.calls()[0]["url"], "https://mainnet.helius-rpc.com/")
        members, ranked = rp.members("proto_dkyc_members_20261020.json")
        o = tg.bubblemaps_overlap(rp.result, members, "read", ranked)
        by = {c["cluster"]: c for c in o["clusters"]}
        for n in (5, 7, 8, 9, 10):
            with self.subTest(cluster=n):
                c = by[n]
                self.assertGreaterEqual(c["seen_by_both"], 2)
                self.assertEqual(c["matched"], c["seen_by_both"], f"cluster {n}: every holder both sides saw sits in one linked group")
        self.assertEqual(by[9]["rows"][0]["status"], "seen")
        group9 = next(g for g in rp.result["clusters"] if g["id"] == by[9]["group"])
        self.assertEqual(group9["edge_counts"]["via_wallet_pair"], 1, "cluster 9: two linking wallets, DpV1y8 sent 29.5 SOL to Go8oJ2")
        pair = next(e for e in rp.result["edges"]["via_wallet_pair"] if set(e["wallets"]) == {"DpV1y8TyG137Wzxd1iRm6eW4iDXg1TZea9yWiMmpFp2c", "Go8oJ2dgm1mEyLe6zaoJN9bRXK5GwkGa2TMq5NUb3pw6"})
        self.assertEqual(pair["bridge"][0]["amount"], "29.500579481")
        self.assertEqual(by[3]["matched"], 0, "cluster 3 links through a PumpSwap pool row with no address: not reproducible")
        self.assertLessEqual(max(c["size"] for c in rp.result["clusters"]), 15, "the app relayers (6Mvb6r..., FOMO Co-signer, ...) do not merge the holders")

    def test_dkyc_and_9a1v_have_no_burst_of_ten_holders(self):
        for case, over in (("dkyc", {}), ("dkyc", {"recent_sol_top": 0}), ("9a1v", {}), ("9a1v", {"recent_sol_top": 0})):
            with self.subTest(case=case, **over):
                r = Replay(case, **over).result
                self.assertEqual(r["bursts"], [])
                self.assertEqual(r["bursts_not_linked"], [])

    def test_78rn_token_distribution_burst_and_the_198_holder_sol_rounds(self):
        r = Replay("78rn").result
        sender = "5EW4P2WHZD91PYsuHphx5oMoLMXb2AmgG6kfkENAfHPL"
        tok = [b for b in r["bursts"] if b["sender"] == sender and b["asset"] == "TOKEN"]
        self.assertEqual([(b["count"], b["span_s"], b["start"]) for b in tok], [(198, 23, "2026-10-20T02:29:55Z")])
        sol = [b for b in r["bursts"] if b["sender"] == sender and b["asset"] == "SOL"]
        self.assertEqual([(b["count"], b["span_s"], b["start"]) for b in sol], [(100, 108, "2026-10-20T02:28:30Z")], "C rows exist for the top 100 only")
        rounds = [x for x in r["rounds"] if x["asset"] == "SOL" and x["typical_holders"] == 198]
        self.assertEqual(len(rounds), 1)
        self.assertGreaterEqual(rounds[0]["senders"], 10)
        big = [b for b in r["bursts"] + r["bursts_not_linked"] if b["asset"] == "SOL" and b["count"] == 198]
        self.assertGreaterEqual(len(big), 10)
        self.assertTrue(all(b["span_s"] <= 60 for b in big), "each round reached the same 198 holders within a minute")
        self.assertEqual(Replay("78rn", groups=True).result["clusters"][0]["size"], 200, "with --groups every holder read is linked")
        self.assertEqual(r["clusters"], [], "groups are held by default")
        text = "\n".join(tg.present(Replay("78rn").run_dir))
        self.assertIn(f"{sender} sent this token to 198 holders within 0.3 min at 2026-10-20 02:29 UTC", text)
        dust = [b for b in r["bursts"] if b["dust_spray"]]
        self.assertEqual((len(r["bursts"]) - len(dust), len(dust)), (24, 40), "40 rounds of 0.0015-0.0018 SOL per holder are labelled dust sprays, still shown")
        self.assertIn("  Dust sprays (one wallet sent 10 or more of these holders under 0.01 SOL each within 5 min", text)
        self.assertRegex(text, r"Repeated rounds: \d+ senders each sent SOL to about the same 198 holders")

    def test_gezc_bursts_from_hurqmuoh_and_fknGexsd_are_reported_and_never_link(self):
        r = Replay("gezc").result
        other = {(b["sender"][:8], b["count"]): b for b in r["bursts_not_linked"]}
        self.assertIn(("HuRQMuoH", 62), other)
        self.assertIn(("FknGexsd", 58), other)
        for k in (("HuRQMuoH", 62), ("FknGexsd", 58)):
            self.assertEqual(other[k]["kind"], "program_account")
        self.assertEqual(round(other[("HuRQMuoH", 62)]["span_s"] / 60, 1), 2.3)
        self.assertEqual(r["bursts"], [], "program accounts are off the curve: never a funding burst group")
        linking = {w.get("wallet") for c in r["clusters"] for w in c["linking_wallets"]}
        self.assertFalse({b["sender"] for b in r["bursts_not_linked"]} & linking)
        text = "\n".join(tg.present(Replay("gezc").run_dir))
        self.assertIn("HuRQMuoHpf4uLFY1otdWh63S6ShvvV6Mzcftq41iDafR (program account, off the curve, not a wallet) sent SOL to 62 holders within 2.3 min", text)

    def test_the_default_reads_c_and_keeps_the_78rn_and_gezc_lists(self):
        """Repair round 2: with the default (C for the first 100 holders read) the 78rn and GezC lists are exactly the pinned
        ones; HuRQMuoH (62 holders) and FknGexsd (58) are among the GezC program-account bursts, and C off loses them."""
        pinned = json.loads(DEFAULT_LISTS.read_text())["cases"]
        for case in ("78rn", "gezc"):
            with self.subTest(case=case):
                rp = Replay(case)
                self.assertNotIn("recent_sol", rp.fx["settings"], "the fixture asks for nothing: the replay runs the lane's default")
                self.assertEqual(rp.result["settings"]["recent_sol_top"], 100)
                self.assertEqual(rp.result["request"]["calls"], {"A": 200, "B": 200, "C": 100, "identity": 1})
                self.assertEqual(rp.result["request"]["credits"]["total"], 5100)
                got = json.loads(json.dumps(burst_list(rp.result)))
                want = {k: v for k, v in pinned[case].items() if k not in ("credits", "calls")}
                self.assertEqual(got, want)
        lists = pinned["78rn"]
        self.assertEqual((len(lists["funding"]), len(lists["dust"]), len(lists["program_or_service"])), (24, 40, 43))
        gezc = {(b[0], b[2], b[5]) for b in pinned["gezc"]["program_or_service"]}
        self.assertEqual(len(pinned["gezc"]["program_or_service"]), 62)
        self.assertIn(("HuRQMuoHpf4uLFY1otdWh63S6ShvvV6Mzcftq41iDafR", 62, "program_account"), gezc)
        self.assertIn(("FknGexsd6AcCwRvC9hkxYphxdV6a3XXB6S1Yy7MhydkX", 58, "program_account"), gezc)
        self.assertEqual(pinned["gezc"]["funding"], [])
        off = {case: burst_list(Replay(case, recent_sol_top=0).result) for case in ("78rn", "gezc")}
        self.assertEqual((len(off["78rn"]["funding"]), len(off["78rn"]["dust"]), len(off["78rn"]["program_or_service"])), (1, 40, 20), "C off: 23 funding bursts fewer")
        self.assertEqual(len(off["gezc"]["program_or_service"]), 45)
        self.assertFalse({(b[0][:8], b[2]) for b in off["gezc"]["program_or_service"]} & {("HuRQMuoH", 62), ("FknGexsd", 58)}, "C off misses both")

    def test_the_fixtures_are_the_documented_public_trim(self):
        for case in ("dkyc", "9a1v", "78rn", "gezc"):
            with gzip.open(REPLAY / f"{case}_replay_20261020.json.gz", "rt", encoding="utf-8") as fh:
                fx = json.load(fh)
            self.assertIn("trimmed public data", fx["note"])
            self.assertNotIn("api-key", json.dumps(fx).lower())


class MutationTests(unittest.TestCase):
    """The exclusions and the window bite: turned off or widened, the prototype data changes the way the rules predict."""

    def test_removing_the_exclusions_merges_the_dkyc_app_wallets(self):
        rp = Replay("dkyc", **VALIDATED)
        normal = max(c["size"] for c in rp.result["clusters"])
        run = new_run(rp.fx["holders"])
        try:
            with mock.patch.object(tg, "on_curve", lambda a: True), mock.patch.object(tg, "is_service", lambda ident: []), \
                    mock.patch.object(tg, "load_app_list", lambda path=None: {"11111111111111111111111111111112": {"reason": "x", "source": "x"}}):
                r = graph_run(run, FakeHelius(rp.mint, rp.fake.transfers, rp.fake.identities), mint=rp.mint, **VALIDATED, **rp.fx["settings"])
        finally:
            shutil.rmtree(run, ignore_errors=True)
        merged = max(c["size"] for c in r["clusters"])
        self.assertLessEqual(normal, 15)
        self.assertGreater(merged, 150, "without the exclusions the app relayers (FOMO Co-signer, 6Mvb6r..., ...) link most holders")
        app = set(tg.load_app_list())
        linking = {w.get("wallet") for c in r["clusters"] for w in c["linking_wallets"]}
        self.assertTrue(app & linking)

    def test_widening_the_burst_window_finds_bursts_on_the_negative_tokens(self):
        with mock.patch.object(tg, "BURST_WINDOW_S", 86_400 * 7):
            r = Replay("9a1v", recent_sol_top=0, _mutation="window").result
        self.assertTrue(r["bursts"] or r["bursts_not_linked"], "a one-week window turns ordinary activity into bursts: the 5 min window matters")


# ----------------------------------------------------------------------------- the overlap and the present block


class OverlapAndPresentTests(unittest.TestCase):
    def test_overlap_reasons_and_pairs(self):
        hs = holders_used(6)
        w = [h["wallet"] for h in hs]
        res = {"holders": hs, "holders_skipped": [{"rank": 50, "wallet": pda("sk"), "share_pct": 0.1, "reason": "off the curve (a program account, not a wallet)"}],
               "clusters": [{"id": 1, "members": [{"rank": 2, "wallet": w[0]}, {"rank": 3, "wallet": w[1]}]}, {"id": 2, "members": [{"rank": 4, "wallet": w[2]}, {"rank": 5, "wallet": w[3]}]}],
               "merged_view": [], "reads": {"stage1_failed_holders": []}}
        outside = wallet("outside")
        members = {"read": True, "clusters": [{"cluster": 1, "wallets": 6, "supply_pct": 3.0, "members_complete": True, "members": [
            {"kind": "holder", "address": w[0]}, {"kind": "holder", "address": w[1]}, {"kind": "holder", "address": w[2]}, {"kind": "holder", "address": w[5]},
            {"kind": "holder", "address": outside}, {"kind": "holder", "address": None, "shown": "AbC...xYz", "unresolved": "no holder in holders.json shows as AbC...xYz"},
            {"kind": "linking", "shown": "LiNk...WaLl"}]}]}
        o = tg.bubblemaps_overlap(res, members, "read", [(outside, 0.5)])
        c = o["clusters"][0]
        self.assertEqual((c["seen_by_both"], c["matched"], c["group"]), (4, 2, 1))
        whys = [r.get("why") for r in c["rows"]]
        self.assertEqual(whys, [None, None, "linked, but in group 2", tg.EMPTY_NOTE, "outside the holders read (Helius rank 1)",
                                "the map row was not resolved to a full address (no holder in holders.json shows as AbC...xYz)"])
        self.assertEqual(o["pairs"], {"universe_holders": 6, "bubblemaps": 6, "graph": 2, "shared": 1, "recall": round(1 / 6, 4), "precision": 0.5})
        self.assertEqual(o["groups"], {"1": [{"bm_cluster": 1, "in_group": 2, "seen_by_both": 4}], "2": [{"bm_cluster": 1, "in_group": 1, "seen_by_both": 4}]})
        self.assertEqual(tg.bubblemaps_overlap(res, None, "assessment.json not present"), {"status": "not_read", "reason": "assessment.json not present"})
        listed = {"read": True, "clusters": [], "list_only": [{"cluster": 4, "wallets": 2, "supply_pct": 1.0, "members": [{"kind": "holder", "address": w[2]}, {"kind": "holder", "address": w[3]}]}]}
        o = tg.bubblemaps_overlap(res, listed, "read")
        self.assertEqual([(c["cluster"], c.get("list_only"), c["matched"], c["seen_by_both"]) for c in o["clusters"]], [(4, True, 2, 2)],
                         "clusters only the map's member list saw count in the overlap too (display only)")

    def test_present_block_wording(self):
        rp = Replay("dkyc", **VALIDATED)
        run = rp.run_dir
        members, ranked = rp.members("proto_dkyc_members_20261020.json")
        (run / "assessment.json").write_text(json.dumps({"bubblemaps_members": members}))
        try:
            lines = tg.present(run, groups=True)
        finally:
            (run / "assessment.json").unlink()
        text = "\n".join(lines)
        self.assertTrue(lines[0].startswith("Transfer graph (follow-up lane transfer_graph; Helius, 9,940 credits of the 12,000 cap; top 249 holders read"))
        self.assertIn("linked groups (experimental)", lines[0])
        for line in lines:
            if line.startswith("  Group "):
                self.assertRegex(line, r"^  Group \d+ \(experimental\): ")
        self.assertIn("matches Bubblemaps cluster 5 (2 of 2)", text)
        self.assertRegex(text, r"cluster 9: 2 of 2 seen by both linked in group \d+")
        self.assertIn(tg.LINKED_NOTE, text)
        self.assertIn("cannot see:", text)
        self.assertIn("Credits: stage 1 (holders)", text)
        self.assertIn("pairs within the holders both saw", text)
        self.assertIsNone(REASSURING.search(text))
        self.assertNotIn("no clusters", text)
        for line in lines:
            for share in re.findall(r"(\d+\.\d+)% of supply", line):
                self.assertLessEqual(len(share.split(".")[1]), 2)

    def test_shares_are_cut_toward_zero(self):
        self.assertEqual(tg.cut(7.4099), "7.40")
        self.assertEqual(tg.cut(0.29999999999), "0.29")
        self.assertEqual(tg.sol_text(29_500_579_481), "29.5005")

    def test_empty_reads_as_no_links_seen_never_no_clusters(self):
        holders, _ = make_holders(MINT, 3)
        run = new_run(holders)
        try:
            r = graph_run(run, FakeHelius())
            (run / "followup").mkdir(exist_ok=True)
            (run / "followup" / "transfer_graph.json").write_text(json.dumps(r))
            text = "\n".join(tg.present(run))
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual(r["status"], "empty")
        self.assertTrue(tg.status_line(r).startswith("empty (no funding bursts or dust sprays seen among the transfers read; 90 Helius credits; "))
        self.assertIn("no funding bursts or dust sprays seen among the transfers read", text)
        self.assertNotIn("no clusters", text.lower())
        self.assertIsNone(REASSURING.search(text))

    def test_damaged_or_missing_files_never_crash(self):
        rp = Replay("dkyc")
        good = json.loads((rp.run_dir / "followup" / "transfer_graph.json").read_text())
        run = Path(tempfile.mkdtemp())
        try:
            self.assertIn("not read (followup/transfer_graph.json missing)", tg.present(run)[0])
            (run / "followup").mkdir()
            for damaged in ("{", json.dumps({"schema": "x"}), json.dumps(dict(good, clusters="x")), json.dumps(dict(good, clusters=[{"id": 1}])),
                            json.dumps(dict(good, bursts=[{"sender": 5}])), json.dumps(dict(good, request=None))):
                (run / "followup" / "transfer_graph.json").write_text(damaged)
                lines = tg.present(run)
                self.assertTrue(lines and "Transfer graph" in lines[0])
        finally:
            shutil.rmtree(run, ignore_errors=True)

    def test_provider_words_in_identity_labels_are_removed_and_counted(self):
        holders, w = make_holders(MINT, 3)
        svc = wallet("safe svc")
        tr = {}
        add(tr, w[0], B_KEY, [row(svc, w[0], "SOL", 5_000_000_000, T0), row(svc, w[1], "SOL", 5_000_000_000, T0)])
        fake = FakeHelius(transfers=tr, identities={svc: {"name": "Safe Clean Exchange", "category": "Centralized Exchange", "type": "exchange", "tags": []}})
        run = new_run(holders)
        try:
            r = graph_run(run, fake, groups=True)
        finally:
            shutil.rmtree(run, ignore_errors=True)
        name = r["exclusions"]["services"][0]["name"]
        self.assertNotIn("Safe", name)
        self.assertIn("[provider word removed", name)


class BurstsByDefaultTests(unittest.TestCase):
    """Repair round 1 (owner decision 2026-10-20, "Ship bursts, hold groups (Recommended)"): the default run and block are
    the bursts; the linked groups need --groups and are labelled experimental; without --groups stage 3 is skipped (it
    changed no burst and no round on any recorded mint) and a scan costs about half."""

    def holders_with_a_hop_candidate_and_a_service_burst(self):
        holders, w = make_holders(MINT, 14)
        big, cex = wallet("hop candidate"), wallet("cex burst")
        tr = {}
        add(tr, w[0], B_KEY, [row(big, w[0], "SOL", 5_000_000_000, T0), row(big, w[1], "SOL", 5_000_000_000, T0 + 1)])
        for i in range(12):
            add(tr, w[2 + i], A_KEY, [row(cex, w[2 + i], "TOKEN", 7, T0 + 100 + i, seed=f"cex{i}")])
        ids = {cex: {"name": "Some Exchange", "category": "Centralized Exchange", "type": "exchange", "tags": []}}
        return holders, w, big, cex, tr, ids

    def test_the_default_run_reads_no_stage_three_and_keeps_no_groups(self):
        holders, w, big, cex, tr, ids = self.holders_with_a_hop_candidate_and_a_service_burst()
        run = new_run(holders)
        try:
            fake = FakeHelius(transfers=tr, identities=ids)
            r = graph_run(run, fake)
            fake_g = FakeHelius(transfers=tr, identities=ids)
            g = graph_run(run, fake_g, groups=True)
        finally:
            shutil.rmtree(run, ignore_errors=True)
        read = {c["body"]["params"][0] for c in fake.calls()}
        self.assertEqual(read, set(w), "only the holders are read: no one-hop-out read without --groups")
        self.assertIn(big, {c["body"]["params"][0] for c in fake_g.calls()}, "with --groups the hop candidate is read")
        self.assertEqual(r["request"]["calls"], {"A": 14, "B": 14, "C": 14, "identity": 1})
        self.assertEqual(r["request"]["credits"], {"stage1": 420, "identity": 100, "stage3": 0, "total": 520})
        for key in ("edges", "merged_view", "bubblemaps_overlap", "stage3"):
            self.assertNotIn(key, r, key)
        self.assertEqual((r["clusters"], r["groups"]["collected"], r["settings"]["groups"], r["settings"]["hop_max_used"]), ([], False, False, 0))
        self.assertTrue(r["settings"]["stage3"].startswith("skipped"))
        self.assertEqual((g["groups"]["collected"], [c["size"] for c in g["clusters"]]), (True, [2]))
        self.assertEqual([b["kind"] for b in r["bursts_not_linked"]], ["service"], "the burst sender's identity is still read: an exchange is listed apart")
        self.assertEqual(fake.calls("identity")[0]["body"]["addresses"], [cex], "without --groups only the burst senders are looked up")
        self.assertEqual(r["bursts"], [])

    def test_the_default_budget_and_status_line(self):
        hop, note, est = tg.plan_budget(250, 0, tg.DEFAULT_RECENT_SOL_TOP, tg.DEFAULT_MAX_CREDITS)
        self.assertEqual((hop, note, est["total"]), (0, None, 7000), "the estimate without stage 3: 6,000 for the holders (A and B for 250, C for "
                         "the first 100) and the 1,000 identity reserve")
        self.assertEqual(Replay("dkyc").result["request"]["credits"]["total"], 5980, "249 holders x A, B + 100 x C; no burst sender to look up")
        self.assertEqual(Replay("dkyc", recent_sol_top=0).result["request"]["credits"]["total"], 4980)
        self.assertEqual(Replay("dkyc", **VALIDATED).result["request"]["credits"]["total"], 9940)
        line = tg.status_line(Replay("78rn").result)
        self.assertTrue(line.startswith("ok (24 funding bursts, 40 dust sprays, 43 program or service bursts; 5,100 Helius credits; "), line)
        self.assertIn("linked groups (experimental)", tg.status_line(Replay("78rn", groups=True).result))

    def test_no_funding_burst_reads_as_such_and_the_pool_trades_are_counted_in_the_first_line(self):
        """Repair round 2 (the Pokemon run): with no funding burst and no dust spray, the first line says exactly that and
        then counts the pool-trade bursts it does not list; it never says "no bursts" above a line that counts 55."""
        holders, w = make_holders(MINT, 3)
        run = new_run(holders)
        try:
            r = graph_run(run, FakeHelius())
            r["program_token_bursts_not_listed"] = 55
            (run / "followup").mkdir(exist_ok=True)
            (run / "followup" / "transfer_graph.json").write_text(json.dumps(r))
            lines = tg.present(run)
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual(r["status"], "empty")
        self.assertTrue(lines[0].endswith("): no funding bursts or dust sprays seen among the transfers read; 55 bursts of this token from program accounts "
                                          "counted, not listed (pool trades, not funding)."), lines[0])
        self.assertNotIn("no bursts", "\n".join(lines))
        self.assertIn("55 program-account token bursts counted (pool trades, not listed)", tg.status_line(r))
        self.assertTrue(tg.status_line(r).startswith("empty (no funding bursts or dust sprays seen among the transfers read; 55 program-account"))

    def test_stage_three_changes_no_burst_and_no_round_on_the_replays(self):
        for case, plain_over, full_over in (("dkyc", {"recent_sol_top": 0}, VALIDATED), ("dkyc", {}, {"groups": True}), ("9a1v", {}, {"groups": True}),
                                            ("78rn", {}, {"groups": True}), ("gezc", {}, {"groups": True})):
            with self.subTest(case=case, **full_over):
                plain, full = Replay(case, **plain_over).result, Replay(case, **full_over).result
                self.assertEqual(json.dumps([plain[k] for k in ("bursts", "bursts_not_linked", "rounds", "program_token_bursts_not_listed")], sort_keys=True),
                                 json.dumps([full[k] for k in ("bursts", "bursts_not_linked", "rounds", "program_token_bursts_not_listed")], sort_keys=True))
        self.assertGreater(Replay("dkyc", **VALIDATED).result["request"]["calls"]["HB"], 0, "the DKYc replay holds real stage-3 reads to compare")

    def test_the_default_block_holds_the_groups_back_with_the_numbers(self):
        lines = tg.present(Replay("dkyc", **VALIDATED).run_dir)
        text = "\n".join(lines)
        self.assertEqual(text.count(tg.VALIDATION_LINE), 1)
        for needle in ("pooled recall 11.4% and precision 3.1%", "10 live mints (2026-10-20)", "--groups"):
            self.assertIn(needle, tg.VALIDATION_LINE)
        self.assertNotRegex(text, r"(?m)^  Group \d|Merged view|Bubblemaps overlap|linking wallets", "no group line without --groups, even when the file holds groups")
        self.assertIn("cannot see: sends beyond each holder's rows read", text)
        self.assertIn("Credits: stage 1 (holders)", text)
        self.assertIn(tg.BURST_NOTE, text)
        bursts_only = tg.present(Replay("dkyc").run_dir, groups=True)
        self.assertIn("  " + tg.GROUPS_NOT_COLLECTED, bursts_only)
        self.assertNotRegex("\n".join(bursts_only), r"(?m)^  Group \d")
        self.assertIn("one hop out: not read (linked groups off", "\n".join(bursts_only))
        self.assertIsNone(REASSURING.search(text + "\n".join(bursts_only)))

    def test_the_default_block_on_a_farm_shows_bursts_rounds_dust_and_programs(self):
        text = "\n".join(tg.present(Replay("78rn").run_dir))
        for needle in ("  Funding bursts (one wallet sent SOL or this token to 10 or more", "  Dust sprays (", "  Repeated rounds: 20 senders each sent SOL to about the same 198 holders",
                       "  Bursts from program accounts or labelled services", "dust spray: every recipient got under 0.01 SOL, the most 0.0018 SOL"):
            self.assertIn(needle, text)
        gezc = "\n".join(tg.present(Replay("gezc").run_dir))
        self.assertIn("Funding bursts: none seen", gezc)
        self.assertIn("HuRQMuoHpf4uLFY1otdWh63S6ShvvV6Mzcftq41iDafR (program account, off the curve, not a wallet) sent SOL to 62 holders", gezc)

    def test_main_passes_the_groups_flag_and_the_registered_command_has_none(self):
        seen = []

        class Spy:
            def __init__(self, *a, **k):
                seen.append(k.get("groups"))

            def run(self):
                return tg._base(MINT, "2026-10-20T00:00:00Z")

        holders, _ = make_holders(MINT, 2)
        run = new_run(holders)
        try:
            with mock.patch.dict(os.environ, {"HELIUS_API_KEY": KEY}), mock.patch.object(tg, "GraphRun", Spy), contextlib.redirect_stdout(io.StringIO()):
                tg.main([MINT, "--out", str(run)])
                tg.main([MINT, "--out", str(run), "--groups"])
        finally:
            shutil.rmtree(run, ignore_errors=True)
        self.assertEqual(seen, [False, True])
        registry = json.loads((SCRIPTS.parent / "collectors.json").read_text())
        entry = next(e for e in registry["entries"] if e["id"] == "transfer_graph")
        self.assertNotIn("--groups", entry["command"])
        self.assertFalse(any("transfer_graph" in k and "--groups" in k for k in next(e for e in registry["entries"] if e["id"] == "synthesis")["present_commands"]))


class PresentationOnlyRuleTests(unittest.TestCase):
    """assess never reads followup/transfer_graph.json: the same assessment.json and report.md with or without it."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        case = case_negative_space_inu()
        cls.mint = case.mint
        cls.run_dir = cls.tmp / "space-run"
        code, _, _ = _run(["funders", case.mint, "--top", str(case.top), "--workers", "6", *case.collector_args, "--out", str(cls.run_dir)], fake=case.fake(), pairs=case.pairs)
        assert code == 0
        cls.space_map = cls.tmp / "space-map.json"
        cls.space_map.write_text(json.dumps(case.inputs["--bubblemaps-json"]))
        cls.alarm_map = cls.tmp / "alarm-map.json"
        cls.alarm_map.write_text(json.dumps(_map(case.mint, [(40, 25.0)], age=2.0)))
        cls.graph = json.loads((Replay("78rn").run_dir / "followup" / "transfer_graph.json").read_text())
        cls.graph["mint"] = cls.mint

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def assess(self, extra, name):
        out = self.tmp / name
        code, _, err = run_assess(self.mint, self.run_dir, extra, out=out)
        return code, err, ((out / "assessment.json").read_bytes() if code == 0 else None), ((out / "report.md").read_bytes() if code == 0 else None)

    def test_the_followup_file_changes_nothing(self):
        for extra, tag in ((["--bubblemaps-json", str(self.space_map)], "map"), (["--bubblemaps-json", str(self.alarm_map)], "alarm"), ([], "no-map")):
            with self.subTest(tag):
                code, err, before, md_before = self.assess(extra, f"{tag}-without")
                self.assertEqual(code, 0, err)
                (self.run_dir / "followup").mkdir(exist_ok=True)
                (self.run_dir / "followup" / "transfer_graph.json").write_text(json.dumps(self.graph))
                try:
                    code, err, after, md_after = self.assess(extra, f"{tag}-with")
                finally:
                    shutil.rmtree(self.run_dir / "followup")
                self.assertEqual(code, 0, err)
                self.assertEqual((after, md_after), (before, md_before), "byte-identical assessment.json and report.md")
        _, _, alarm, _ = self.assess(["--bubblemaps-json", str(self.alarm_map)], "alarm-check")
        self.assertTrue(json.loads(alarm)["flag"]["label"].startswith(hf.FLAG_DANGER), "the map alarm stands; the graph never softens it")

    def test_refused_as_providers_json_and_unknown_to_both_engines(self):
        (self.run_dir / "followup").mkdir(exist_ok=True)
        (self.run_dir / "followup" / "transfer_graph.json").write_text(json.dumps(self.graph))
        try:
            code, err, _, _ = self.assess(["--providers-json", str(self.run_dir / "followup" / "transfer_graph.json")], "refused")
        finally:
            shutil.rmtree(self.run_dir / "followup")
        self.assertEqual(code, 2)
        for path in [SCRIPTS / "helius_forensics.py", SCRIPTS / "holder_analysis.py", *sorted((SCRIPTS / "ha").glob("*.py"))]:
            self.assertNotIn("transfer_graph", path.read_text(encoding="utf-8"), path.name)


if __name__ == "__main__":
    unittest.main()
