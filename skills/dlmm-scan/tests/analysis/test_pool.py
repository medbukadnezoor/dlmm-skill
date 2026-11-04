"""HS-POOL-T1: the analysis engine's wallet checks in a bounded pool (shared pace, shared 429 pause, exact call cap,
deterministic output, Ctrl-C), and criterion 7: --external-artifact refuses presentation-only provider names.

Offline only: a fake HTTP layer stands in for Helius, a duck-typed fake for Jupiter, the key is a dummy, and the rate
checks run on an injected clock (no wall time)."""

from __future__ import annotations

import _thread
import contextlib
import inspect
import io
import json
import os
import random
import signal
import subprocess
import sys
import textwrap
import threading
import time
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

import pytest

import helius_forensics as hf
import holder_analysis
from ha import analysis, transport
from ha import helius as ha_helius
from ha.helius import HeliusClient
from ha.solana import is_on_curve

SECRET = "poolTestKEY0000notReal"
MINT = "Hg5Ja55T5wESq4vyFoiVCMeHXtGyVA69X2UHq8hgpump"
NOW = datetime(2026, 10, 19, 6, 0, tzinfo=timezone.utc)
LAUNCH_ISO = "2026-10-12T00:00:00Z"
LAUNCH_TS = int(datetime(2026, 10, 12, tzinfo=timezone.utc).timestamp())
SUPPLY = 1_000_000_000
SYSTEM = "11111111111111111111111111111111"
TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
POOL_PROGRAM = "LBUZKhRxPF3XUpBCjp4YzTKgLccjZhTSDM9YuVaPwxo"
FIXED = ["getTokenSupply", "getAccountInfo", "getTokenLargestAccounts", "getMultipleAccounts", "getTokenAccounts", "getMultipleAccounts", "identity"]
INTERRUPT_LINE = "error: interrupted (Ctrl-C); no new Helius lookups were started"
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    n, out = int.from_bytes(raw, "big"), ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def addresses(count: int, seed: int, on_curve: bool = True) -> list[str]:
    """Synthetic, valid-looking addresses (deterministic). on_curve=True gives keypair wallets, False program addresses."""
    rng, found = random.Random(seed), []
    while len(found) < count:
        a = b58encode(bytes(rng.getrandbits(8) for _ in range(32)))
        if len(a) >= 32 and is_on_curve(a) == on_curve and a not in found:
            found.append(a)
    return found


WALLETS = addresses(24, seed=11)
FUNDERS = addresses(12, seed=12)
EXCHANGE = addresses(1, seed=13)[0]
POOL_OWNER = addresses(1, seed=14, on_curve=False)[0]
CHECKED = WALLETS[:20]  # --funding-top 20 (default): the top 20 ordinary wallets get funded-by + first activity


def max_in_window(times: list[float], window: float = 1.0) -> int:
    """Most starts inside any window [t, t + window)."""
    ts = sorted(times)
    return max((sum(1 for u in ts if t <= u < t + window) for t in ts), default=0)


def holders() -> list[tuple[str, int]]:
    return [(POOL_OWNER, 200_000_000), (EXCHANGE, 100_000_000)] + [(w, 30_000_000 - i * 1_000_000) for i, w in enumerate(WALLETS)]


def funded_by_answers() -> dict[str, object]:
    """Two unlabeled shared funders (clusters), one exchange funder, two wallets without a record (404), single funders,
    one rent-level top-up."""
    out: dict[str, object] = {}
    for i, w in enumerate(CHECKED):
        if i < 5:
            out[w] = {"funder": FUNDERS[0], "amount": 2.5, "timestamp": LAUNCH_TS - 3600 + i}
        elif i < 8:
            out[w] = {"funder": FUNDERS[1], "amount": 1.8, "timestamp": LAUNCH_TS - 7200 + i}
        elif i < 12:
            out[w] = {"funder": FUNDERS[2], "funderName": "Binance Hot Wallet 2", "funderType": "Centralized Exchange", "amount": 5.0, "timestamp": LAUNCH_TS - 86_400 * i}
        elif i < 14:
            out[w] = 404
        else:
            out[w] = {"funder": FUNDERS[i - 11], "amount": 0.002 if i == 16 else 1.0 + i / 10, "timestamp": LAUNCH_TS - 600 * i}
    return out


def first_tx_answers() -> dict[str, list]:
    out: dict[str, list] = {}
    for i, w in enumerate(CHECKED):
        if i < 8:
            out[w] = [{"blockTime": LAUNCH_TS + 60 * i}]
        elif i < 13:
            out[w] = [{"blockTime": LAUNCH_TS - 30 * 86_400}]
        elif i == 13:
            out[w] = []
        else:
            out[w] = [{"blockTime": LAUNCH_TS - 2 * 86_400}]
    return out


class FakeJupiter:
    """Duck-typed Jupiter client (free provider; not part of this change). Its funders agree with Helius for wallets 0-4,
    differ substantively for 5-7 (ordered disagreement rows) and are service-level for 8-9."""

    def __init__(self):
        self.calls = 0

    def token(self, mint):
        self.calls += 1
        return {"symbol": "POOLT", "name": "Pool Test", "holderCount": 26, "totalSupply": float(SUPPLY), "firstPool": {"createdAt": LAUNCH_ISO},
                "launchpad": "synthetic", "organicScore": 12.5,
                "audit": {"mintAuthorityDisabled": True, "freezeAuthorityDisabled": True, "botHoldersPercentage": 3.0, "bundlerStats": {"holdingPct": 1.0}}}

    def holders(self, mint, limit=100):
        self.calls += 1
        rows = []
        for i, (owner, amount) in enumerate(holders()[2:12]):
            funder = FUNDERS[0] if i < 5 else FUNDERS[11 - (i - 5)] if i < 8 else FUNDERS[2]
            rows.append({"owner": owner, "amount": float(amount), "tags": ["bundler"] if i in (2, 3) else [], "funder": funder, "funding_amount": 3.0 if i < 8 else 0.002})
        return {"count": 26, "holders": rows}

    def pools(self, mint):
        self.calls += 1
        return [{"id": POOL_OWNER}]


class Resp:
    def __init__(self, payload):
        self.status, self._buf = 200, io.BytesIO(json.dumps(payload).encode())

    def read(self, n=-1):
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class Seq(list):
    """A sequence of outcomes for one wallet, consumed one per request (the last one repeats)."""


class RoutingOpener:
    """Thread-safe fake Helius HTTP layer. Answers by method and wallet, never by arrival order; records every request
    (label, wallet, clock time, thread, url, headers, body), the completion order and the concurrency. A wallet's
    answer may be a Seq (consumed one per request), an int (HTTP error status) or an exception to raise."""

    def __init__(self, *, clock=None, latency=0.0, seed=0, funded_by=None, first_tx=None, on_request=None):
        self.clock, self.latency, self._rng, self.on_request = clock, latency, random.Random(seed), on_request
        self.funded_by = funded_by_answers() if funded_by is None else funded_by
        self.first_tx = first_tx_answers() if first_tx is None else first_tx
        self.owner_of = {f"TokenAcct{i}": owner for i, (owner, _) in enumerate(holders())}
        self.requests: list[dict] = []
        self.completed: list[tuple[str, str]] = []
        self.active = self.max_active = 0
        self._lock = threading.Lock()

    @staticmethod
    def _pick(answer):
        if isinstance(answer, Seq):
            return answer.pop(0) if len(answer) > 1 else answer[0]
        return answer

    def _answer(self, label, wallet, body):
        if label == "funded_by":
            return self._pick(self.funded_by.get(wallet, 404))
        if label == "identity":
            return [{"address": EXCHANGE, "name": "OKX Hot Wallet", "category": "Exchange", "type": "exchange", "tags": ["Exchange"]}]
        params = body["params"]
        if label == "getTransactionsForAddress":
            rows = self._pick(self.first_tx.get(wallet, []))
            return rows if isinstance(rows, (int, Exception)) else {"jsonrpc": "2.0", "id": 1, "result": rows if isinstance(rows, dict) else {"data": rows}}
        result = {
            "getTokenSupply": lambda: {"value": {"amount": str(SUPPLY), "decimals": 0}},
            "getAccountInfo": lambda: {"value": {"owner": TOKEN_PROGRAM, "data": {"parsed": {"type": "mint", "info": {"mintAuthority": None, "freezeAuthority": None}}}}},
            "getTokenLargestAccounts": lambda: {"value": [{"address": f"TokenAcct{i}", "amount": str(a)} for i, (_, a) in enumerate(holders()[:20])]},
            "getTokenAccounts": lambda: {"token_accounts": [{"owner": o, "amount": a} for o, a in holders()], "cursor": None},
            "getMultipleAccounts": lambda: {"value": [
                {"data": {"parsed": {"info": {"owner": self.owner_of[x]}}}} if params[1]["encoding"] == "jsonParsed" else {"owner": POOL_PROGRAM if x == POOL_OWNER else SYSTEM}
                for x in params[0]]},
        }[label]()
        return {"jsonrpc": "2.0", "id": 1, "result": result}

    def open(self, req, timeout=None):
        url = req.full_url
        body = json.loads(req.data) if req.data else None
        if url.endswith("/v1/wallet/batch-identity"):
            label, wallet = "identity", ""
        elif "/funded-by" in url:
            label, wallet = "funded_by", url.split("/v1/wallet/")[1].split("/")[0]
        else:
            label = body["method"]
            wallet = body["params"][0] if label == "getTransactionsForAddress" else ""
        with self._lock:
            self.requests.append({"label": label, "wallet": wallet, "t": self.clock() if self.clock else time.monotonic(), "thread": threading.get_ident(),
                                  "url": url, "headers": dict(req.header_items()), "body": req.data or b""})
            n = len(self.requests)
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            delay = self._rng.uniform(0, self.latency) if self.latency else 0.0
            answer = self._answer(label, wallet, body)
        try:
            if self.on_request:
                self.on_request(n, label, wallet)
            if delay and not isinstance(answer, (int, Exception)):  # errors answer at once
                time.sleep(delay)
            if isinstance(answer, Exception):
                raise answer
            if isinstance(answer, int):
                raise urllib.error.HTTPError(url, answer, "x", {}, io.BytesIO(b"{}"))
            return Resp(answer)
        finally:
            with self._lock:
                self.active -= 1
                self.completed.append((label, wallet))

    def sequence(self) -> list[tuple[str, str]]:
        return [(r["label"], r["wallet"]) for r in self.requests]


class FakeClock:
    """Injected clock and sleep (no wall time). sleep(d) moves the shared clock to this thread's last reading + d."""

    def __init__(self, start=1_000.0):
        self.now = start
        self._lock = threading.Lock()
        self._seen = threading.local()

    def __call__(self):
        with self._lock:
            self._seen.t = self.now
            return self.now

    def sleep(self, seconds):
        with self._lock:
            self.now = max(self.now, getattr(self._seen, "t", self.now) + max(0.0, seconds))


class FrozenDatetime(datetime):
    @classmethod
    def now(cls, tz=None):
        return NOW if tz else NOW.replace(tzinfo=None)


def make_client(opener, clock, *, max_calls=150, starts=None, pauses=None):
    client = HeliusClient(SECRET, max_calls=max_calls, opener=opener, clock=clock, sleep=clock.sleep)
    wait_turn, pause, lock = client.gate.wait_turn, client.gate.pause, threading.Lock()
    if starts is not None:
        def recording_wait():
            s = wait_turn()
            with lock:
                starts.append(s)
            return s
        client.gate.wait_turn = recording_wait
    if pauses is not None:
        def recording_pause(seconds):
            pause(seconds)
            with lock:  # the instant the pause was set and its length
                pauses.append((client.gate._pause_until - seconds, seconds))
        client.gate.pause = recording_pause
    return client


def run_engine(opener, clock, *, workers, max_calls=150, starts=None, pauses=None):
    client = make_client(opener, clock, max_calls=max_calls, starts=starts, pauses=pauses)
    return analysis.run(MINT, helius=client, jupiter=FakeJupiter(), now=NOW, workers=workers), client


def run_cli(argv, opener, clock, *, made=None):
    """The real CLI entry point with the fake HTTP layer, a fake Jupiter, a frozen clock for the artifact time and a
    dummy key in the environment (no .env is read)."""
    made = [] if made is None else made

    def build(key, *, max_calls):
        made.append(make_client(opener, clock, max_calls=max_calls))
        return made[-1]

    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, {"HELIUS_API_KEY": SECRET}), mock.patch.object(holder_analysis, "HeliusClient", side_effect=build), \
         mock.patch.object(holder_analysis, "JupiterClient", side_effect=FakeJupiter), mock.patch.object(analysis, "datetime", FrozenDatetime), \
         contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = holder_analysis.main([MINT, *argv])
    return code, out.getvalue(), err.getvalue()


def expected_old_order() -> list[tuple[str, str]]:
    """The old one-at-a-time loop: the fixed calls, then funded-by and first activity, wallet after wallet."""
    return [(m, "") for m in FIXED] + [pair for w in CHECKED for pair in (("funded_by", w), ("getTransactionsForAddress", w))]


# ---------------------------------------------------------------------------------------------------- constants


def test_rate_constants_keep_both_engines_within_eight_per_second():
    assert ha_helius.ANALYSIS_RATE_CAP_PER_S == 2
    assert ha_helius.COMBINED_RATE_CAP_PER_S == 8
    assert hf.REQUEST_RATE_CAP_PER_S == 6  # the forensics cap is unchanged by this ticket
    assert ha_helius.ANALYSIS_RATE_CAP_PER_S + hf.REQUEST_RATE_CAP_PER_S <= ha_helius.COMBINED_RATE_CAP_PER_S
    assert (analysis.DEFAULT_WORKERS, analysis.MAX_WORKERS) == (4, 10)
    assert inspect.signature(analysis.run).parameters["workers"].default == 1  # library callers keep the old loop


def test_the_forensics_helpers_are_reused_not_copied():
    assert ha_helius.RateGate is hf.RateGate
    assert analysis.run_lookups is hf.run_lookups
    assert analysis.presentation_only_provider is hf.presentation_only_provider
    assert isinstance(HeliusClient(SECRET).gate, hf.RateGate)


# ---------------------------------------------------------------------------------------------------- ordering


def test_outputs_byte_identical_between_one_and_many_workers(tmp_path):
    results = {}
    for workers, seed in ((1, 1), (4, 2), (4, 3), (10, 4)):
        opener = RoutingOpener(clock=FakeClock(), latency=0.004, seed=seed)
        out_json = tmp_path / f"w{workers}-{seed}.json"
        code, out, err = run_cli(["--workers", str(workers), "--json", str(out_json)], opener, opener.clock)
        assert code == 0 and err == ""
        results[(workers, seed)] = (out_json.read_bytes(), out, opener)
    base_json, base_md, base_opener = results[(1, 1)]
    assert base_opener.max_active == 1
    assert base_opener.sequence() == expected_old_order()
    art = json.loads(base_json)
    assert art["providers"]["helius.wallet_forensics"] == {"status": "ok", "wallets": 20}
    assert art["crosscheck"]["funding"]["disagreements"]  # order-sensitive rows exist, so the check below means something
    assert art["clusters"]["clusters"] and art["freshness"]["status"] == "partial"
    for (workers, seed), (body, md, opener) in results.items():
        if workers == 1:
            continue
        wallet_stage = [(r["label"], r["wallet"]) for r in opener.requests[len(FIXED):]]
        assert 1 < opener.max_active <= workers
        assert sorted(opener.sequence()) == sorted(base_opener.sequence())  # the same calls, so the same Helius cost
        assert [p for p in opener.completed[len(FIXED):]] != wallet_stage, "random latencies must shuffle the completion order"
        assert body == base_json, (workers, seed)
        assert md == base_md, (workers, seed)


def test_one_worker_runs_the_old_loop_in_the_calling_thread():
    opener = RoutingOpener(clock=FakeClock())
    art, client = run_engine(opener, opener.clock, workers=1)
    assert opener.sequence() == expected_old_order()
    assert {r["thread"] for r in opener.requests} == {threading.get_ident()}
    assert client.calls == {"getTokenSupply": 1, "getAccountInfo": 1, "getTokenLargestAccounts": 1, "getMultipleAccounts": 2, "getTokenAccounts": 1,
                            "wallet_batch_identity": 1, "wallet_funded_by": 20, "getTransactionsForAddress": 20}


def test_duck_typed_client_sees_the_old_call_order_with_one_worker():
    from test_analysis import W1, W2, FakeHelius, FakeJupiter as SmallJupiter

    order = []

    class Recording(FakeHelius):
        def funded_by(self, wallet):
            order.append(("funded_by", wallet))
            return super().funded_by(wallet)

        def first_activity(self, wallet):
            order.append(("first_activity", wallet))
            return super().first_activity(wallet)

    analysis.run(MINT, helius=Recording(), jupiter=SmallJupiter(), now=NOW)
    assert order == [("funded_by", W1), ("first_activity", W1), ("funded_by", W2), ("first_activity", W2)]


# ---------------------------------------------------------------------------------------------------- call cap


def test_spend_is_atomic_under_racing_threads():
    client = HeliusClient(SECRET, max_calls=500)
    barrier, accepted, lock = threading.Barrier(16), [], threading.Lock()

    def hammer():
        barrier.wait()
        for _ in range(100):
            try:
                client._spend("x")
                with lock:
                    accepted.append(1)
            except ha_helius.BudgetExhausted:
                pass

    threads = [threading.Thread(target=hammer) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(accepted) == 500 and client.total_calls == 500


@pytest.mark.parametrize("seed", [1, 2, 3, 4, 5])
def test_call_cap_is_exact_with_ten_racing_workers(seed):
    cap = len(FIXED) + 13  # 6.5 wallets' worth of calls for the wallet stage
    opener = RoutingOpener(clock=FakeClock(), latency=0.003, seed=seed)
    art, client = run_engine(opener, opener.clock, workers=10, max_calls=cap)
    assert client.total_calls == cap
    assert len(opener.requests) == cap  # a refused call is never sent
    stage = art["providers"]["helius.wallet_forensics"]
    assert stage["status"] == "partial" and stage["reason"] == "budget_exhausted"
    funded = [h for h in art["top_holders"] if h["owner"] in CHECKED and h["funder"]]
    assert stage["wallets_done"] == client.calls["wallet_funded_by"]  # every funded-by answer is recorded
    assert client.calls["wallet_funded_by"] + client.calls["getTransactionsForAddress"] == 13
    assert len(funded) <= stage["wallets_done"]


def test_call_cap_with_one_worker_stops_exactly_where_the_old_loop_stopped():
    cap = len(FIXED) + 13
    opener = RoutingOpener(clock=FakeClock())
    art, client = run_engine(opener, opener.clock, workers=1, max_calls=cap)
    assert opener.sequence() == expected_old_order()[:cap]  # 6 wallets in full, then the 7th wallet's funded-by
    assert art["providers"]["helius.wallet_forensics"] == {"status": "partial", "reason": "budget_exhausted", "wallets_done": 7}
    assert sum(h["first_activity"] is not None for h in art["top_holders"]) == 6


def test_cli_max_helius_calls_is_exact_under_workers(tmp_path):
    opener, made = RoutingOpener(clock=FakeClock(), latency=0.002, seed=7), []
    code, out, err = run_cli(["--workers", "10", "--max-helius-calls", "30", "--json", str(tmp_path / "a.json")], opener, opener.clock, made=made)
    assert code == 0
    assert made[0].total_calls == 30 and len(opener.requests) == 30
    assert json.loads((tmp_path / "a.json").read_text())["budget"]["helius_total"] == 30


# ---------------------------------------------------------------------------------------------------- rate cap


def test_rate_cap_two_starts_per_second_single_thread():
    clock = FakeClock()
    opener = RoutingOpener(clock=clock)
    client = make_client(opener, clock)
    for w in CHECKED:
        client.funded_by(w)
    times = [r["t"] for r in opener.requests]
    assert max_in_window(times) == 2
    assert times[2] >= times[0] + 1.0  # the cap really binds at zero latency
    assert times[-1] - times[0] == pytest.approx(9 * (1.0 + hf.RATE_WINDOW_MARGIN_S))  # 20 starts at 2/s: nine steps of 1.05 s


@pytest.mark.parametrize("workers", [4, 10])
def test_rate_cap_holds_across_workers_for_every_helius_request(workers):
    clock, starts = FakeClock(), []
    opener = RoutingOpener(clock=clock, latency=0.002, seed=workers)
    art, client = run_engine(opener, clock, workers=workers, starts=starts)
    assert len(starts) == len(opener.requests) == 47  # every request, the fixed ones included, passed the gate
    assert max_in_window(starts) <= ha_helius.ANALYSIS_RATE_CAP_PER_S
    assert max(starts) - min(starts) >= (47 / 2 - 1) * 1.0


# ---------------------------------------------------------------------------------------------------- 429


def test_transport_retry_semantics_unchanged_and_429_pauses_the_gate():
    from test_foundation import FakeOpener, FakeResponse, http_error

    class Gate:
        def __init__(self):
            self.turns, self.pauses = 0, []

        def wait_turn(self):
            self.turns += 1

        def pause(self, seconds):
            self.pauses.append(seconds)

    for gate in (None, Gate()):
        sleeps = []
        opener = FakeOpener(http_error(429), http_error(503), FakeResponse(b"[]"))
        got = transport.request_json("GET", "https://api.helius.xyz/v1/x", allowed_hosts={"api.helius.xyz"}, opener=opener, sleep=sleeps.append, gate=gate)
        assert got == [] and len(opener.requests) == 3 and sleeps == [1.0, 2.0]  # the same retries and backoff with or without a gate
        if gate:
            assert gate.turns == 3 and gate.pauses == [1.0]  # every attempt waited for the gate; only the 429 paused it


def test_429_pauses_every_worker_retries_the_same_request_and_counts_once(tmp_path):
    no_429 = RoutingOpener(clock=FakeClock())
    base, _ = run_engine(no_429, no_429.clock, workers=4)
    clock, starts, pauses = FakeClock(), [], []
    answers = funded_by_answers()
    target = CHECKED[6]
    answers[target] = Seq([429, answers[target]])
    opener = RoutingOpener(clock=clock, latency=0.002, seed=5, funded_by=answers)
    art, client = run_engine(opener, clock, workers=4, starts=starts, pauses=pauses)
    assert len(pauses) == 1
    p, seconds = pauses[0]
    assert seconds == 1.0  # the transport's own first backoff
    assert not [s for s in starts if p < s < p + seconds], "no worker may start a request during the shared pause"
    assert max_in_window(starts) <= 2
    hits = [r for r in opener.requests if r["label"] == "funded_by" and r["wallet"] == target]
    assert len(hits) == 2 and hits[0]["url"] == hits[1]["url"] and hits[1]["t"] >= p + seconds
    assert client.calls["wallet_funded_by"] == 20  # the retry is not counted, as before
    assert art == base  # the same artifact as without the 429


def test_429_that_never_clears_keeps_the_old_retry_limit_and_stops_the_stage():
    answers = funded_by_answers()
    target = CHECKED[3]
    answers[target] = 429
    for workers in (1, 4):
        clock, pauses = FakeClock(), []
        opener = RoutingOpener(clock=clock, latency=0.001, funded_by=dict(answers))
        art, client = run_engine(opener, clock, workers=workers, pauses=pauses)
        assert sum(r["wallet"] == target and r["label"] == "funded_by" for r in opener.requests) == 3  # 1 + 2 retries, as before
        assert [s for _, s in pauses] == [1.0, 2.0, 4.0]
        stage = art["providers"]["helius.wallet_forensics"]
        assert stage["status"] == "partial" and stage["reason"] == "rate_limited"
        if workers == 1:
            assert stage["wallets_done"] == 3 and opener.sequence()[-1] == ("funded_by", target)
        assert clock.now - 1_000.0 >= 1.0 + 2.0


# ---------------------------------------------------------------------------------------------------- failures


def test_provider_failure_stops_new_wallets_and_names_the_first_failure_in_wallet_order():
    first = funded_by_answers()
    first[CHECKED[9]] = 401  # not retried: fails at once
    first[CHECKED[12]] = 403  # a later failure: never the one named
    for workers in (1, 4, 10):
        opener = RoutingOpener(clock=FakeClock(), latency=0.003, seed=workers, funded_by=dict(first))
        art, _ = run_engine(opener, opener.clock, workers=workers)
        stage = art["providers"]["helius.wallet_forensics"]
        assert stage["status"] == "partial" and stage["reason"] == "auth_failed"
        wallets = list(dict.fromkeys(r["wallet"] for r in opener.requests if r["label"] == "funded_by"))
        assert set(CHECKED[:10]) <= set(wallets)
        assert max(CHECKED.index(w) for w in wallets) < 10 + 2 * workers  # no new wallets once the failure was seen
        assert stage["wallets_done"] == sum(1 for w in wallets if w not in (CHECKED[9], CHECKED[12]))  # in-flight wallets are kept
        if workers == 1:
            assert wallets == CHECKED[:10] and stage["wallets_done"] == 9


def test_unexpected_error_in_a_wallet_check_is_recorded_at_every_worker_count():
    tx = first_tx_answers()
    tx[CHECKED[4]] = {"data": {"not": "a list"}}  # malformed answer: the old loop crashed here with a KeyError traceback
    for workers in (1, 4):
        opener = RoutingOpener(clock=FakeClock(), latency=0.001, first_tx=dict(tx))
        art, _ = run_engine(opener, opener.clock, workers=workers)
        stage = art["providers"]["helius.wallet_forensics"]
        assert (stage["status"], stage["reason"], stage["error_type"]) == ("partial", "unexpected_error", "KeyError")


@pytest.mark.parametrize("workers", [1, 4, 10])
def test_the_first_failure_in_wallet_order_is_named_even_when_a_later_wallet_fails_first(workers):
    """Wallet 3 fails slowly (401), wallet 5 fails at once (403): with several workers wallet 5's failure arrives first,
    yet the stage names wallet 3's, the one the old loop would have stopped on."""
    answers = funded_by_answers()
    answers[CHECKED[3]], answers[CHECKED[5]] = 401, 403

    def slow_wallet_3(n, label, wallet):
        if label == "funded_by" and wallet == CHECKED[3]:
            time.sleep(0.3)

    opener = RoutingOpener(clock=FakeClock(), latency=0.001, funded_by=answers, on_request=slow_wallet_3)
    art, _ = run_engine(opener, opener.clock, workers=workers)
    stage = art["providers"]["helius.wallet_forensics"]
    funded = [h["owner"] for h in art["top_holders"] if h["owner"] in CHECKED and h["funder"]]
    if workers == 1:
        assert ("funded_by", CHECKED[5]) not in opener.sequence()  # the old loop stopped at wallet 3
        assert stage == {"status": "partial", "reason": "auth_failed", "wallets_done": 3}
        return
    done = opener.completed
    assert done.index(("funded_by", CHECKED[5])) < done.index(("funded_by", CHECKED[3])), "wallet 5 must fail first in time"
    assert stage["status"] == "partial" and stage["reason"] == "auth_failed"  # wallet 3: first in wallet order, not in time
    assert CHECKED[3] not in funded and CHECKED[5] not in funded


# ---------------------------------------------------------------------------------------------------- --workers flag


@pytest.mark.parametrize("value", ["0", "11", "-3"])
def test_out_of_range_workers_exit_2_before_the_key_or_any_call(value):
    err = io.StringIO()
    with mock.patch.object(holder_analysis, "load_keys", side_effect=AssertionError("the key must not be read")), \
         mock.patch.object(holder_analysis, "HeliusClient", side_effect=AssertionError("no client")), \
         mock.patch.object(holder_analysis, "JupiterClient", side_effect=AssertionError("no client")), \
         mock.patch.object(analysis, "run", side_effect=AssertionError("must not run")), contextlib.redirect_stderr(err):
        code = holder_analysis.main([MINT, "--workers", value])
    assert code == 2
    assert err.getvalue() == "error: --workers must be between 1 and 10\n"


def test_non_integer_workers_is_a_usage_error():
    with contextlib.redirect_stderr(io.StringIO()), pytest.raises(SystemExit) as exc:
        holder_analysis.main([MINT, "--workers", "four"])
    assert exc.value.code == 2


@pytest.mark.parametrize("argv,expect", [([], 4), (["--workers", "1"], 1), (["--workers", "10"], 10)])
def test_default_is_four_and_the_bounds_are_accepted(argv, expect):
    seen, real = [], analysis.run

    def spy(*a, **k):
        seen.append(k.get("workers"))
        return real(*a, **k)

    with mock.patch.object(analysis, "run", side_effect=spy), contextlib.redirect_stdout(io.StringIO()):
        code = holder_analysis.main([MINT, "--no-helius", "--no-jupiter", *argv])
    assert code == 0 and seen == [expect]


# ---------------------------------------------------------------------------------------------------- key safety


def test_key_only_in_the_header_and_never_in_any_output(tmp_path):
    answers, tx = funded_by_answers(), first_tx_answers()
    answers[CHECKED[2]] = Seq([429, 503, answers[CHECKED[2]]])
    answers[CHECKED[15]] = ValueError(f"Invalid header value b'{SECRET}' for https://api.helius.xyz/?api-key={SECRET}")
    tx[CHECKED[11]] = 500
    for workers in ("1", "4"):
        opener = RoutingOpener(clock=FakeClock(), latency=0.002, funded_by={k: Seq(v) if isinstance(v, Seq) else v for k, v in answers.items()}, first_tx=dict(tx))
        out_json = tmp_path / f"k{workers}.json"
        code, out, err = run_cli(["--workers", workers, "--json", str(out_json)], opener, opener.clock)
        assert code == 0
        blob = out_json.read_text() + out + err
        assert SECRET not in blob
        for r in opener.requests:
            assert SECRET not in r["url"] and SECRET.encode() not in r["body"]
            assert {k.lower(): v for k, v in r["headers"].items()}.get("x-api-key") == SECRET
        stage = json.loads(out_json.read_text())["providers"]["helius.wallet_forensics"]
        assert stage["status"] == "partial"


# ---------------------------------------------------------------------------------------------------- K1: key format, no traceback

PIECES = ("DUMMYk1PIECEone", "DUMMYk1PIECEtwo")
BAD_KEYS = [PIECES[0] + sep + PIECES[1] for sep in ("\n", " ", "\x07", "\t", "\r", "\x00", "/")] + ["short", "x" * 129]
ENV_KEYS = [k for k in BAD_KEYS if "\x00" not in k]  # an environment variable cannot hold a NUL byte
FORMAT_LINE = "error: HELIUS_API_KEY has an unexpected format\n"


def no_key_piece(text):
    return not any(piece in text for piece in PIECES)


@pytest.mark.parametrize("key", ENV_KEYS)
def test_malformed_key_in_the_environment_exits_2_before_any_call_without_echoing_it(key):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.dict(os.environ, {"HELIUS_API_KEY": key, "HOLDER_ANALYSIS_ENV": "/nonexistent/.env"}), \
         mock.patch.object(holder_analysis, "HeliusClient", side_effect=AssertionError("no client")), \
         mock.patch.object(holder_analysis, "JupiterClient", side_effect=AssertionError("no client")), \
         mock.patch.object(analysis, "run", side_effect=AssertionError("must not run")), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = holder_analysis.main([MINT])
    assert (code, err.getvalue(), out.getvalue()) == (2, FORMAT_LINE, "")
    assert no_key_piece(out.getvalue() + err.getvalue())


@pytest.mark.parametrize("value", ['"DUMMYk1PIECEone DUMMYk1PIECEtwo"', "DUMMYk1PIECEone\x07DUMMYk1PIECEtwo", "'DUMMYk1PIECEone\tDUMMYk1PIECEtwo'"])
def test_malformed_key_in_the_env_file_exits_2_without_echoing_it(value, tmp_path, monkeypatch):
    env_file = tmp_path / "dummy.env"
    env_file.write_text(f"HELIUS_API_KEY={value}\n", encoding="utf-8")
    monkeypatch.delenv("HELIUS_API_KEY", raising=False)
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(holder_analysis, "HeliusClient", side_effect=AssertionError("no client")), \
         mock.patch.object(holder_analysis, "JupiterClient", side_effect=AssertionError("no client")), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = holder_analysis.main([MINT, "--env-file", str(env_file)])
    assert (code, err.getvalue()) == (2, FORMAT_LINE)
    assert no_key_piece(out.getvalue() + err.getvalue())


@pytest.mark.parametrize("key", BAD_KEYS)
def test_helius_client_refuses_a_malformed_key_with_a_fixed_reason(key):
    with pytest.raises(transport.TransportError) as exc:
        HeliusClient(key)
    assert exc.value.reason == "helius_key_unexpected_format"
    assert no_key_piece(str(exc.value) + repr(exc.value))


@pytest.mark.parametrize("label", ["getTokenSupply", "getMultipleAccounts", "identity"])
def test_an_exception_carrying_the_key_prints_its_type_name_only(label, tmp_path):
    def boom(n, got, wallet):
        if got == label:  # the fixed-call path: _guard catches only budget and transport errors
            raise ValueError(f"Invalid header value b'{SECRET}' for https://mainnet.helius-rpc.com/?api-key={SECRET}")

    opener = RoutingOpener(clock=FakeClock(), on_request=boom)
    code, out, err = run_cli(["--json", str(tmp_path / "x.json")], opener, opener.clock)
    assert (code, err, out) == (3, "error: unexpected ValueError\n", "")
    assert SECRET not in out + err and "Traceback" not in out + err
    assert not (tmp_path / "x.json").exists()


@pytest.mark.skipif(os.name != "posix", reason="needs a child process")
def test_real_cli_process_with_a_newline_key_prints_nothing_of_it():
    """The Verifier's reproduction: the key reaches stderr (the collector's .err file) only through a traceback."""
    driver = textwrap.dedent(
        """
        import socket, sys
        socket.socket.connect = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("network disabled"))
        sys.path.insert(0, sys.argv[1])
        import holder_analysis
        sys.exit(holder_analysis.main(["Hg5Ja55T5wESq4vyFoiVCMeHXtGyVA69X2UHq8hgpump", "--no-jupiter"]))
        """
    )
    scripts = Path(holder_analysis.__file__).resolve().parent
    env = {k: v for k, v in os.environ.items() if k not in ("HELIUS_API_KEY", "HOLDER_ANALYSIS_ENV")}
    env |= {"HELIUS_API_KEY": PIECES[0] + "\n" + PIECES[1], "HOLDER_ANALYSIS_ENV": "/nonexistent/.env"}
    proc = subprocess.run([sys.executable, "-I", "-c", driver, str(scripts)], capture_output=True, text=True, env=env, timeout=60)
    assert (proc.returncode, proc.stderr, proc.stdout) == (2, FORMAT_LINE, "")
    assert no_key_piece(proc.stdout + proc.stderr) and "Traceback" not in proc.stderr


# ---------------------------------------------------------------------------------------------------- Ctrl-C


@pytest.mark.parametrize("workers", ["4", "1"])
def test_ctrl_c_in_the_wallet_stage_exits_130_with_one_line(workers, tmp_path):
    def interrupt(n, label, wallet):
        if n == len(FIXED) + 6:
            _thread.interrupt_main()

    opener = RoutingOpener(clock=FakeClock(), latency=0.01, on_request=interrupt)
    code, out, err = run_cli(["--workers", workers, "--json", str(tmp_path / "x.json")], opener, opener.clock)
    time.sleep(0.05)  # let in-flight daemon checks finish before counting
    assert code == 130
    assert err == INTERRUPT_LINE + "\n"
    assert "Traceback" not in out + err and SECRET not in out + err
    assert len(opener.requests) < len(FIXED) + 6 + 2 * int(workers) + 1  # no new wallets after the interrupt
    assert not (tmp_path / "x.json").exists()


@pytest.mark.skipif(os.name != "posix", reason="needs POSIX signals")
def test_real_sigint_exits_promptly_without_traceback(tmp_path):
    driver = textwrap.dedent(
        """
        import json, sys, time
        sys.path.insert(0, sys.argv[1])
        import holder_analysis
        from ha import analysis
        from unittest import mock
        marker, workers, owners = sys.argv[2], sys.argv[3], json.loads(sys.argv[4])

        class Slow:
            max_calls = 10**6
            def __init__(self):
                self.calls = {}
            @property
            def total_calls(self):
                return sum(self.calls.values())
            def token_supply(self, mint): return {"raw": 10**9, "decimals": 0}
            def mint_info(self, mint): return {"token_program": "T", "mint_authority": None, "freeze_authority": None, "extensions": []}
            def largest_accounts(self, mint): return [{"token_account": f"t{i}", "amount_raw": 10**6 - i} for i in range(len(owners))]
            def token_account_owners(self, accounts): return {f"t{i}": o for i, o in enumerate(owners)}
            def all_holders(self, mint, *, max_pages): return {"owners": {o: {"amount_raw": 10**6 - i, "accounts": 1} for i, o in enumerate(owners)}, "complete": True, "pages": 1}
            def owner_kinds(self, owners_): return {o: "wallet" for o in owners_}
            def identities(self, owners_): return {}
            def funded_by(self, wallet):
                with open(marker, "a") as fh:
                    fh.write(wallet + "\\n")
                time.sleep(0.5)
                return None
            def first_activity(self, wallet):
                time.sleep(0.5)
                return None

        with mock.patch.object(holder_analysis, "HeliusClient", return_value=Slow()), mock.patch.object(holder_analysis, "JupiterClient", return_value=None):
            code = holder_analysis.main(["Hg5Ja55T5wESq4vyFoiVCMeHXtGyVA69X2UHq8hgpump", "--workers", workers, "--funding-top", "20", "--no-jupiter"])
        sys.exit(code)
        """
    )
    scripts = Path(holder_analysis.__file__).resolve().parent
    for workers in ("4", "1"):
        marker = tmp_path / f"calls-{workers}.txt"
        env = {k: v for k, v in os.environ.items() if k not in ("HELIUS_API_KEY", "HOLDER_ANALYSIS_ENV")} | {"HELIUS_API_KEY": SECRET}
        proc = subprocess.Popen([sys.executable, "-I", "-c", driver, str(scripts), str(marker), workers, json.dumps(WALLETS[:20])],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True)
        deadline = time.monotonic() + 20
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        time.sleep(0.3)
        sent = time.monotonic()
        proc.send_signal(signal.SIGINT)
        out, err = proc.communicate(timeout=30)
        elapsed = time.monotonic() - sent
        calls = marker.read_text().split()
        assert proc.returncode == 130, (workers, err)
        assert err.strip() == INTERRUPT_LINE
        assert "Traceback" not in out + err and SECRET not in out + err
        assert elapsed < 5.0
        assert len(calls) < 20


# ---------------------------------------------------------------------------------------------------- criterion 7

REFUSED = {
    "Solana Tracker": ["Solana Tracker", "solana_tracker", "SOLANA-TRACKER (bundlers)", "SolanaTracker", "Sol Tracker", "Sоlana Tracker",
                       "Ｓｏｌａｎａ Ｔｒａｃｋｅｒ", "S0lana Tracker", "ST", "Solanna Tracker", "Solana​Tracker"],
    "MadeOnSol": ["MadeOnSol", "made-on-sol", "Made On Sol", "МadeОnSol", "MOS", "Maddeonsol", "MadeOnSol (launch bundle)", "Mádé Ón Söl"],
    "Fomo API": ["Fomo API", "fomo", "FOMO API (tracked traders)", "F0M0 API", "Fommo", "fomo.family", "Fоmo API"],
}
ACCEPTED = ["okx", "insightx", "cabalspy", "gmgn", "bubblemaps", "arkham", "Step Finance", "Mosaic", "Cosmos", "Moss", "Tracker Bot", "Solscan", "Jupiter datapi", "Helius"]
# Findings copied by hand from the presentation-only collectors' files (solanatracker.json, madeonsol.json, fomoapi.json)
HAND_COPIED = [
    {"provider": "Solana Tracker", "status": "ok", "largest_cluster_pct": 0.25, "bundle_pct": 0.008, "unit": "percent", "data_age_min": 4, "detail": "copied from solanatracker.json"},
    {"provider": "MadeOnSol", "status": "ok", "bundle_pct": 80.68, "unit": "percent", "data_age_min": 6, "detail": "launch bundle, copied from madeonsol.json"},
    {"provider": "Fomo API", "status": "ok", "largest_cluster_pct": 0.0, "unit": "percent", "data_age_min": 2, "detail": "2 tracked traders, copied from fomoapi.json"},
]
OKX = {"provider": "okx", "status": "ok", "largest_cluster_pct": 3.0, "unit": "percent", "data_age_min": 5}


def refusal_line(label: str) -> str:
    return f"error: --external-artifact cannot supply {label}: it is a presentation-only provider, shown by the synthesis next to the FLAGs and never an engine input\n"


def main_without_any_call(argv):
    err = io.StringIO()
    with mock.patch.object(holder_analysis, "load_keys", side_effect=AssertionError("the key must not be read")), \
         mock.patch.object(holder_analysis, "HeliusClient", side_effect=AssertionError("no client")), \
         mock.patch.object(holder_analysis, "JupiterClient", side_effect=AssertionError("no client")), \
         mock.patch.object(analysis, "run", side_effect=AssertionError("must not run")), contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        code = holder_analysis.main([MINT, *argv])
    return code, err.getvalue()


def test_hand_copied_presentation_only_findings_exit_2_before_the_key_or_any_call(tmp_path):
    for finding, label in zip(HAND_COPIED, ("Solana Tracker", "MadeOnSol", "Fomo API")):
        for findings in ([finding], [OKX, finding]):  # alone, or hidden after a legitimate finding
            path = tmp_path / "evidence.json"
            path.write_text(json.dumps({"provider_findings": findings, "providers": {"bubblemaps": {"status": "ok", "clusters": {"largest_cluster_share": 0.02}}}}))
            code, err = main_without_any_call(["--external-artifact", str(path)])
            assert (code, err) == (2, refusal_line(label))


def test_every_spelling_the_forensics_matcher_refuses_is_refused_here(tmp_path):
    for label, names in REFUSED.items():
        for name in names:
            assert hf.presentation_only_provider(name) == label, name
            path = tmp_path / "evidence.json"
            path.write_text(json.dumps({"provider_findings": [dict(HAND_COPIED[0], provider=name)]}))
            code, err = main_without_any_call(["--external-artifact", str(path)])
            assert (code, err) == (2, refusal_line(label)), name  # only the fixed label is printed, never the raw provider text


def test_real_provider_names_stay_accepted(tmp_path):
    from test_analysis import FakeHelius, FakeJupiter as SmallJupiter

    for name in ACCEPTED:
        assert hf.presentation_only_provider(name) is None, name
        path = tmp_path / "evidence.json"
        path.write_text(json.dumps({"provider_findings": [dict(OKX, provider=name)]}))
        art = analysis.run(MINT, helius=FakeHelius(), jupiter=SmallJupiter(), external_artifact=path, now=NOW)
        assert [f["provider"] for f in art["coverage"]["findings"]] == [name]


def test_run_refuses_before_any_provider_call(tmp_path):
    from test_analysis import FakeHelius, FakeJupiter as SmallJupiter

    path = tmp_path / "evidence.json"
    path.write_text(json.dumps({"provider_findings": [OKX, HAND_COPIED[1]]}))
    fake_helius, fake_jupiter = FakeHelius(), SmallJupiter()
    with pytest.raises(analysis.ArtifactRefused, match="cannot supply MadeOnSol"):
        analysis.run(MINT, helius=fake_helius, jupiter=fake_jupiter, external_artifact=path, now=NOW)
    assert fake_helius.calls == {} and fake_jupiter.calls == 0


def test_a_file_changed_after_the_cli_check_is_still_refused_before_any_call(tmp_path):
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps({"provider_findings": [OKX]}))

    def swap_then_key(names, env_file=None):  # runs after the CLI check and before run(): the file is swapped in between
        path.write_text(json.dumps({"provider_findings": [OKX, HAND_COPIED[2]]}))
        return {"HELIUS_API_KEY": SECRET}

    opener, err = RoutingOpener(), io.StringIO()
    jupiter = FakeJupiter()
    with mock.patch.object(holder_analysis, "load_keys", side_effect=swap_then_key), \
         mock.patch.object(holder_analysis, "HeliusClient", side_effect=lambda key, max_calls: HeliusClient(key, max_calls=max_calls, opener=opener)), \
         mock.patch.object(holder_analysis, "JupiterClient", return_value=jupiter), contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
        code = holder_analysis.main([MINT, "--external-artifact", str(path)])
    assert (code, err.getvalue()) == (2, refusal_line("Fomo API"))
    assert opener.requests == [] and jupiter.calls == 0


def test_the_artifact_is_read_once_so_a_later_change_cannot_slip_in(tmp_path):
    from test_analysis import FakeHelius, FakeJupiter as SmallJupiter

    path = tmp_path / "evidence.json"
    path.write_text(json.dumps({"provider_findings": [OKX]}))

    class Swapping(FakeHelius):
        def token_supply(self, mint):  # the first provider call: the file changes mid-run
            path.write_text(json.dumps({"provider_findings": [OKX, HAND_COPIED[0]]}))
            return super().token_supply(mint)

    art = analysis.run(MINT, helius=Swapping(), jupiter=SmallJupiter(), external_artifact=path, now=NOW)
    assert [f["provider"] for f in art["coverage"]["findings"]] == ["okx"]


def test_unreadable_artifact_is_still_recorded_unavailable(tmp_path):
    from test_analysis import FakeHelius, FakeJupiter as SmallJupiter

    path = tmp_path / "evidence.json"
    path.write_bytes(b"\xff\xfe not json")
    assert analysis.read_external_artifact(path) is analysis._UNREADABLE  # the check passes it on; the run records it
    art = analysis.run(MINT, helius=FakeHelius(), jupiter=SmallJupiter(), external_artifact=path, now=NOW)
    assert art["providers"]["external_artifact"] == {"status": "unavailable", "reason": "unreadable"}
