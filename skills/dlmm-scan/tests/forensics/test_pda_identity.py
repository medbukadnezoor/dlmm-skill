"""HS-PDA-T1: the `pda_identity_reads` follow-up collector (scripts/pda_identity.py) and its offline `--present` block.
Offline: a fake JSON-RPC transport answering from public account data read live on 2026-10-19 (MAKERS and Aloooong,
fixtures/pda_identity_live_20261019.json) and from synthetic accounts built on those bytes. No key exists for this lane.

Covers: request construction (one host, POST JSON-RPC, only getMultipleAccounts and getProgramAccounts, base64 with a
data slice, no key, no env proxy, no redirects, size and time bounds); the one retry after a 429 and never more; the
hard wall-clock deadline; the fixed reason codes and the ok / empty / unavailable statuses; the Streamflow decode (the
MAKERS lock: sender = recipient = dev, single cliff 2027-04-16 04:00 UTC, not cancellable, not transferable, withdrawn
0) through the escrow lookup and directly, a vesting stream, every layout-mismatch check and the wrong mint; the
PumpSwap decode (quote side = infrastructure with the --exclude hint, base side = pool); everything else unidentified
with its owner program, never "wallet"; the lookups sent at the same time and capped; offsets equal to the cited
layouts (and to the provider-docs cache when it is on this machine); --present (exact owner lines, no verdict words,
never a crash); and the presentation-only rule (assess gives the same files with or without the follow-up file)."""

from __future__ import annotations

import ast
import base64
import contextlib
import copy
import email.message
import io
import json
import os
import random
import re
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
import pda_identity as pi  # noqa: E402
from ha.solana import b58decode  # noqa: E402
from test_assess import _map, _run, case_negative_space_inu, run_assess  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
LIVE = json.loads((FIX / "pda_identity_live_20261019.json").read_text())
LOOKUP = json.loads((FIX / "pda_identity_lookup_live_20261019.json").read_text())
ACCOUNTS = LIVE["accounts"]
MAKERS = "3XEqNHe3jHTRWAZCTHbb1UwpSfNbJL9oU1ErsM86pump"
ALOOOONG = "1htv5Nzfdy44FJWAdTXZoACJW4BWbB2XwZC6SVopurp"
ESCROW = "6mLfJYRqKBS7b1NurtVazjWJesusUL61MYxmw7dnv3MW"
STREAM = "5sp9K5s2rB21Pd4FVeoNXwxPUxr3ya6hWq7UTAd3Z3R6"
DEV = "41ht2ZJoYSYnhbYP5SPs6Zz65L7yB8ieJ64wpETAzK82"
QUOTE_POOL = "J4KJkjaLB3wbpMV6RUyhPpAPqakPHfYsoxyAjkdaZqqR"
ALO_POOL = "6CWeZYjCrn2ZQEDjD7NKE38NiDN99H9wy48zBHyqbvPw"
MAKERS_POOL = "D6G4BRfHuGYsTkPCBkmuEqesND7gJuGzdCzeNicATtmy"
NOW = 1_792_420_000  # 2026-10-19 14:26:40 UTC, the day the fixtures were read
CLIFF = 1_807_848_000  # 2027-04-16 04:00:00 UTC
REASSURING = re.compile(r"\b(clean|safe|low)\b", re.IGNORECASE)
FLAG_WORDS = re.compile(r"DANGER FLAG|CAUTION|NO FLAG RAISED")


def raw_of(value) -> bytes:
    return base64.b64decode(value["data"][0])


def with_raw(value, raw: bytes, owner: str | None = None):
    out = copy.deepcopy(value)
    out["data"] = [base64.b64encode(raw).decode(), "base64"]
    out["space"] = len(raw)
    if owner:
        out["owner"] = owner
    return out


def put_u64(raw: bytearray, offset: int, value: int) -> None:
    struct.pack_into("<Q", raw, offset, value)


def address_of(seed: int) -> str:
    return pi.b58encode(bytes(random.Random(seed).getrandbits(8) for _ in range(32)))


def synthetic_stream(stream_address: str, mutate=None):
    """The live MAKERS stream bytes at another stream address, with the escrow field set to that address's own derived
    escrow (so every check passes unless `mutate` breaks one). Returns (stream value, escrow address, escrow value)."""
    raw = bytearray(raw_of(ACCOUNTS[STREAM]))
    escrow, _ = pi.find_program_address([b"strm", b58decode(stream_address)], pi.STREAMFLOW_PROGRAM)
    raw[209:241] = b58decode(escrow)
    if mutate:
        mutate(raw)
    token = bytearray(raw_of(ACCOUNTS[ESCROW]))
    token[32:64] = b58decode(escrow)
    return with_raw(ACCOUNTS[STREAM], bytes(raw)), escrow, with_raw(ACCOUNTS[ESCROW], bytes(token))


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200, chunk: int | None = None):
        self._buf, self.status, self._chunk = io.BytesIO(body), status, chunk

    def read(self, n=-1):
        return self._buf.read(n if self._chunk is None else min(n, self._chunk))

    def close(self):
        pass


def http_error(code, headers=None):
    msg = email.message.Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError(pi.RPC_ENDPOINT, code, "error", msg, io.BytesIO(b""))


def rpc_body(result) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()


def sliced(value, config):
    if value is None:
        return None
    out = copy.deepcopy(value)
    window = config.get("dataSlice")
    if window:
        try:
            raw = raw_of(value)[window["offset"]:window["offset"] + window["length"]]
        except ValueError:  # deliberately broken data reaches the script as it is
            return out
        out["data"] = [base64.b64encode(raw).decode(), "base64"]
    return out


class FakeRpc:
    """A JSON-RPC server double: getMultipleAccounts from `accounts`, getProgramAccounts by owner program and memcmp
    filters over `programs`; `answers` (exceptions, responses or callables) are used first, in order."""

    def __init__(self, accounts=None, programs=None, answers=None, gate=None):
        self.accounts = dict(ACCOUNTS if accounts is None else accounts)
        self.programs = dict({STREAM: ACCOUNTS[STREAM]} if programs is None else programs)
        self.answers = list(answers or [])
        self.gate = gate
        self.requests = []
        self.lock = threading.Lock()

    def methods(self):
        return [p["method"] for _, _, p in self.requests]

    def open(self, request, timeout=None):
        payload = json.loads(request.data.decode())
        with self.lock:
            self.requests.append((request, timeout, payload))
            answer = self.answers.pop(0) if self.answers else None
        if isinstance(answer, BaseException):
            raise answer
        if callable(answer):
            return answer()
        if answer is not None:
            return answer
        keys, config = payload["params"]
        if payload["method"] == "getMultipleAccounts":
            return FakeResponse(rpc_body({"context": {"slot": 458862735}, "value": [sliced(self.accounts.get(k), config) for k in keys]}))
        if self.gate is not None:
            self.gate.wait(timeout=5)
        rows = []
        for pubkey, value in self.programs.items():
            raw = raw_of(value)
            if value["owner"] == keys and all(raw[f["memcmp"]["offset"]:f["memcmp"]["offset"] + 32] == b58decode(f["memcmp"]["bytes"]) for f in config["filters"]):
                rows.append({"pubkey": pubkey, "account": sliced(value, config)})
        return FakeResponse(rpc_body(rows))


def target(address, source="holder-analysis.json program_account"):
    return {"address": address, "from": [source], "row_share_pct": None}


def collect(mint, addresses, rpc=None, sleeps=None, now=NOW):
    sleeps = [] if sleeps is None else sleeps
    return pi.collect_pda_identity(mint, [target(a) for a in addresses], opener=rpc or FakeRpc(), now=lambda: now, monotonic=time.monotonic, sleep=sleeps.append)


def row(result, address):
    return next(r for r in result["targets"] if r["address"] == address)


def write_result(folder: Path, result) -> None:
    (folder / pi.OUT_DIR).mkdir(parents=True, exist_ok=True)
    (folder / pi.OUT_DIR / pi.OUT_FILE).write_text(json.dumps(result, indent=1))


class RequestConstructionTests(unittest.TestCase):
    def test_one_batch_post_with_no_key_then_one_filtered_lookup(self):
        rpc = FakeRpc()
        res = collect(MAKERS, [ESCROW], rpc)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(rpc.methods(), ["getMultipleAccounts", "getProgramAccounts"])
        for request, timeout, _ in rpc.requests:
            url = urllib.parse.urlparse(request.full_url)
            self.assertEqual((url.scheme, url.hostname, url.port, url.path, url.query), ("https", "api.mainnet-beta.solana.com", None, "", ""))
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(dict(request.header_items()), {"Content-type": "application/json", "Accept": "application/json", "User-agent": pi.USER_AGENT})
            self.assertEqual(timeout, pi.TIMEOUT_S)
        batch, lookup = rpc.requests[0][2], rpc.requests[1][2]
        self.assertEqual(batch["params"], [[MAKERS, ESCROW], {"encoding": "base64", "commitment": "confirmed", "dataSlice": {"offset": 0, "length": 1104}}])
        self.assertEqual(lookup["params"], [pi.STREAMFLOW_PROGRAM, {"encoding": "base64", "commitment": "confirmed", "dataSlice": {"offset": 0, "length": 1104},
                                                                   "filters": [{"memcmp": {"offset": 177, "bytes": MAKERS}}, {"memcmp": {"offset": 209, "bytes": ESCROW}}]}])
        self.assertEqual(res["request"], {"host": "api.mainnet-beta.solana.com", "path": "/", "methods": ["getMultipleAccounts", "getProgramAccounts"], "keys": "none",
                                          "batch_calls": 1, "stream_lookups": 1, "requests_sent": 2, "max_requests": 8, "max_targets": 99, "max_stream_lookups": 3,
                                          "data_slice_bytes": 1104})

    def test_default_opener_ignores_env_proxies_and_refuses_redirects(self):
        with mock.patch.dict(os.environ, {"https_proxy": "http://proxy.invalid:3128", "HTTPS_PROXY": "http://proxy.invalid:3128"}):
            opener = pi.default_opener()
        self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in opener.handlers))
        self.assertTrue(any(isinstance(h, pi.NoRedirect) for h in opener.handlers))

    def test_only_the_allowlisted_host_path_and_methods(self):
        for url in ("http://api.mainnet-beta.solana.com", "https://api.mainnet-beta.solana.com.evil.example", "https://api.mainnet-beta.solana.com:8899",
                    "https://u:p@api.mainnet-beta.solana.com", "https://api.mainnet-beta.solana.com/rpc", "https://api.mainnet-beta.solana.com/?x=1",
                    "https://mainnet.helius-rpc.com", "https://api.devnet.solana.com"):
            with self.subTest(url), self.assertRaises(pi.Failure):
                pi.check_url(url)
        for method in ("sendTransaction", "getSignaturesForAddress", "getTransaction", "requestAirdrop", "getAccountInfo"):
            with self.subTest(method), self.assertRaises(pi.Failure):
                pi.build_request({"jsonrpc": "2.0", "id": 1, "method": method, "params": []})
        rpc = FakeRpc()
        with self.assertRaises(pi.Failure):
            pi.send_once(urllib.request.Request("https://example.com/"), rpc, monotonic=time.monotonic)
        self.assertEqual(rpc.requests, [])

    def test_the_source_names_no_other_rpc_method_host_or_key(self):
        text = (SCRIPTS / "pda_identity.py").read_text()
        strings = [n.value for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        named = {s for s in strings if re.fullmatch(r"(get|send|request|simulate)[A-Z]\w+", s)}
        self.assertEqual(named, {"getMultipleAccounts", "getProgramAccounts"})
        self.assertEqual(set(re.findall(r"https?://([\w.-]+)", text)), set())
        self.assertIn('RPC_ENDPOINT = f"https://{HOST}"', text)
        self.assertNotIn("helius-rpc", text)
        self.assertNotIn("os.environ", text)
        self.assertNotIn("getenv", text)

    def test_redirect_size_and_error_bounds(self):
        cases = [(http_error(302), "redirect_disallowed", 302), (FakeResponse(b"", status=301), "redirect_disallowed", 301), (http_error(403), "access_denied", 403),
                 (http_error(410), "method_unavailable", 410), (http_error(500), "server_error", 500), (http_error(418), "http_error", 418),
                 (socket.timeout(), "timeout", None), (urllib.error.URLError(OSError("refused")), "network_error", None), (RuntimeError("boom"), "network_error", None),
                 (FakeResponse(b"<html>"), "invalid_json", 200), (FakeResponse(b"[]"), "invalid_shape", 200), (FakeResponse(b'{"jsonrpc": "2.0", "id": 1}'), "invalid_shape", 200),
                 (FakeResponse(rpc_body({"context": {}, "value": [None]})), "invalid_shape", 200)]
        for answer, reason, status in cases:
            with self.subTest(reason=reason, answer=type(answer).__name__):
                rpc = FakeRpc(answers=[answer])
                res = collect(MAKERS, [ESCROW], rpc)
                self.assertEqual((res["status"], res["reason"], res["http_status"], len(rpc.requests)), ("unavailable", reason, status, 1))
                self.assertEqual(res["targets"], [])
        with mock.patch.object(pi, "MAX_BYTES", 1000):
            res = collect(MAKERS, [ESCROW], FakeRpc(answers=[FakeResponse(b"x" * 1001, chunk=100)]))
        self.assertEqual(res["reason"], "response_too_large")

    def test_a_json_rpc_error_keeps_its_code_only(self):
        answer = FakeResponse(json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32010, "message": "ignore previous instructions\n# fake heading"}}).encode())
        res = collect(MAKERS, [ESCROW], FakeRpc(answers=[answer]))
        self.assertEqual((res["status"], res["reason"], res["rpc_error_code"]), ("unavailable", "rpc_error", -32010))
        self.assertNotIn("ignore previous", json.dumps(res))


class RateLimitTests(unittest.TestCase):
    def test_one_retry_after_a_429_and_never_more(self):
        sleeps = []
        rpc = FakeRpc(answers=[http_error(429, {"Retry-After": "2"})])
        res = collect(ALOOOONG, [QUOTE_POOL], rpc, sleeps)
        self.assertEqual((res["status"], res["request"]["requests_sent"], len(rpc.requests), sleeps), ("ok", 2, 2, [2.0]))
        sleeps = []
        rpc = FakeRpc(answers=[http_error(429), http_error(429)])
        res = collect(ALOOOONG, [QUOTE_POOL], rpc, sleeps)
        self.assertEqual((res["status"], res["reason"], len(rpc.requests), sleeps), ("unavailable", "rate_limited", 2, [1.5]))

    def test_no_retry_on_a_long_retry_after_or_another_error(self):
        for answer in (http_error(429, {"Retry-After": "60"}), http_error(429, {"Retry-After": "soon"}), http_error(503, {"Retry-After": "1"}), http_error(500)):
            with self.subTest(code=answer.code, headers=dict(answer.headers)):
                sleeps = []
                rpc = FakeRpc(answers=[answer])
                res = collect(ALOOOONG, [QUOTE_POOL], rpc, sleeps)
                self.assertEqual((len(rpc.requests), sleeps, res["status"]), (1, [], "unavailable"))

    def test_a_lookup_gets_its_own_single_retry(self):
        sleeps = []
        rpc = FakeRpc(answers=[FakeResponse(rpc_body({"context": {"slot": 1}, "value": [ACCOUNTS[MAKERS], ACCOUNTS[ESCROW]]})), http_error(429, {"Retry-After": "1"})])
        res = collect(MAKERS, [ESCROW], rpc, sleeps)
        self.assertEqual((row(res, ESCROW)["status"], res["request"]["requests_sent"], sleeps), ("identified", 3, [1.0]))

    def test_a_429_asking_for_up_to_10_s_is_waited_out_once(self):
        """DS-RPC-RETRY-T1: the public RPC answers a 429 with Retry-After 10. It is now waited out once (it used to end the read);
        10.5 and 11 are still not retried, no header still waits 1.5 s, and a second 429 is never retried again."""
        for header, sent, sleeps_expected, status in (("10", 2, [10.0], "ok"), (None, 2, [1.5], "ok"),
                                                      ("10.5", 1, [], "unavailable"), ("11", 1, [], "unavailable")):
            with self.subTest(retry_after=header):
                sleeps = []
                rpc = FakeRpc(answers=[http_error(429, {"Retry-After": header} if header else None)])
                res = collect(ALOOOONG, [QUOTE_POOL], rpc, sleeps)
                self.assertEqual((res["status"], len(rpc.requests), res["request"]["requests_sent"], sleeps), (status, sent, sent, sleeps_expected))
                if status != "ok":
                    self.assertEqual(res["reason"], "rate_limited")
        sleeps = []
        rpc = FakeRpc(answers=[http_error(429, {"Retry-After": "10"}), http_error(429, {"Retry-After": "10"})])
        res = collect(ALOOOONG, [QUOTE_POOL], rpc, sleeps)
        self.assertEqual((res["status"], res["reason"], len(rpc.requests), sleeps), ("unavailable", "rate_limited", 2, [10.0]), "never more than one retry")
        sleeps = []
        rpc = FakeRpc(answers=[FakeResponse(rpc_body({"context": {"slot": 1}, "value": [ACCOUNTS[MAKERS], ACCOUNTS[ESCROW]]})), http_error(429, {"Retry-After": "10"})])
        res = collect(MAKERS, [ESCROW], rpc, sleeps)
        self.assertEqual((row(res, ESCROW)["status"], res["request"]["requests_sent"], sleeps), ("identified", 3, [10.0]), "a lookup gets its own one retry")
        self.assertEqual(pi.RETRY_MAX_WAIT_S, 10.0)

    def test_the_10_s_wait_stays_inside_the_hard_limits_on_a_fake_clock(self):
        """DS-RPC-RETRY-T1: no overrun. The wait is between attempts and every attempt keeps its own TIMEOUT_S deadline, so one
        call takes at most 2 x 30 s + 10 s; a retry that runs past its deadline ends as a timeout, never a third request; and
        the lookup join waits longer than one call can take, so a retried lookup is never cut off."""
        clock = [5_000.0]

        def tick(seconds):
            clock[0] += seconds

        class Slow:
            """Each attempt uses `spend` seconds of the fake clock, then gives the next answer."""

            def __init__(self, answers, spend):
                self.answers, self.spend, self.requests = list(answers), list(spend), 0

            def open(self, request, timeout=None):
                self.requests += 1
                tick(self.spend.pop(0))
                answer = self.answers.pop(0)
                if isinstance(answer, BaseException):
                    raise answer
                return answer

        payload = pi.lookup_payload(MAKERS, ESCROW)
        for spend, reason in (([pi.TIMEOUT_S - 1, pi.TIMEOUT_S - 1], None), ([pi.TIMEOUT_S - 1, pi.TIMEOUT_S + 1], "timeout")):
            with self.subTest(reason=reason):
                start = clock[0]
                opener = Slow([http_error(429, {"Retry-After": "10"}), FakeResponse(rpc_body([]))], spend)
                got = pi.rpc_call(payload, opener, monotonic=lambda: clock[0], sleep=tick)
                self.assertEqual((got["reason"], got["attempts"], opener.requests), (reason, 2, 2))
                self.assertEqual(clock[0] - start, sum(spend) + 10.0)
                self.assertLessEqual(clock[0] - start, 2 * pi.TIMEOUT_S + pi.RETRY_MAX_WAIT_S + 1)
        joins = []
        real_thread = threading.Thread

        class Recording(real_thread):
            def join(self, timeout=None):
                if self.name == "pda-identity-lookup":
                    joins.append(timeout)
                return super().join(timeout)

        with mock.patch.object(threading, "Thread", Recording):
            res = collect(MAKERS, [ESCROW])
        self.assertEqual((row(res, ESCROW)["status"], len(joins)), ("identified", 1))
        self.assertTrue(all(j > 2 * pi.TIMEOUT_S + pi.RETRY_MAX_WAIT_S for j in joins), joins)


class HardDeadlineTests(unittest.TestCase):
    DEADLINE = 0.5
    MARGIN = 0.5

    def setUp(self):
        self.stop = threading.Event()
        patcher = mock.patch.object(pi, "TIMEOUT_S", self.DEADLINE)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.stop.set)

    def test_a_drip_feed_and_a_stalled_open_end_at_the_deadline(self):
        stop = self.stop

        class Drip:
            status = 200

            def __init__(self):
                self.start = time.monotonic()

            def read(self, n=-1):
                got = b""
                while not stop.is_set() and time.monotonic() - self.start < 3.0 and len(got) < n:
                    time.sleep(0.01)
                    got += b"x"
                return got

            def close(self):
                pass

        def stall():
            stop.wait(3.0)
            raise OSError("released")

        for answer in (Drip, stall):
            with self.subTest(answer=answer.__name__):
                started = time.monotonic()
                res = collect(ALOOOONG, [QUOTE_POOL], FakeRpc(answers=[answer]))
                self.assertEqual((res["status"], res["reason"]), ("unavailable", "timeout"))
                self.assertLess(time.monotonic() - started, self.DEADLINE + self.MARGIN)

    def test_a_stalled_lookup_ends_at_the_deadline_and_keeps_the_rest(self):
        stop = self.stop

        def stall():
            stop.wait(3.0)
            raise OSError("released")

        rpc = FakeRpc(answers=[FakeResponse(rpc_body({"context": {"slot": 1}, "value": [ACCOUNTS[MAKERS], ACCOUNTS[ESCROW], None]})), stall])
        started = time.monotonic()
        res = collect(MAKERS, [ESCROW, QUOTE_POOL], rpc)
        self.assertLess(time.monotonic() - started, self.DEADLINE + self.MARGIN)
        self.assertEqual(res["status"], "ok")
        self.assertEqual((row(res, ESCROW)["status"], row(res, ESCROW)["reason"], row(res, ESCROW)["lookup_reason"]), ("unavailable", "stream_lookup_failed", "timeout"))
        self.assertEqual(row(res, QUOTE_POOL)["detail"], "no_account")


class StreamflowTests(unittest.TestCase):
    def test_the_makers_lock_through_the_escrow_lookup(self):
        res = collect(MAKERS, [ESCROW])
        r = row(res, ESCROW)
        self.assertEqual((res["status"], r["status"], r["kind"], r["found_by"], r["stream_type"]), ("ok", "identified", "streamflow", "program_account_lookup", "lock"))
        self.assertEqual((r["stream"], r["escrow"], r["sender"], r["recipient"], r["mint"], r["program"]), (STREAM, ESCROW, DEV, DEV, MAKERS, pi.STREAMFLOW_PROGRAM))
        self.assertEqual((r["created_at"], r["start"], r["cliff"], r["end"], r["period_s"]), (1_792_206_592, CLIFF, CLIFF, CLIFF, 1))
        self.assertEqual((r["deposited_raw"], r["cliff_amount_raw"], r["withdrawn_raw"], r["held_raw"], r["held_basis"]),
                         (105_483_264_472_548, 105_483_264_472_548, 0, 105_483_264_472_548, "escrow balance"))
        self.assertEqual({k: r[k] for k in ("cancelable_by_sender", "cancelable_by_recipient", "transferable_by_sender", "transferable_by_recipient", "can_topup", "closed")},
                         dict.fromkeys(("cancelable_by_sender", "cancelable_by_recipient", "transferable_by_sender", "transferable_by_recipient", "can_topup", "closed"), False))
        self.assertEqual((r["unlocked_at_read_raw"], r["next_unlock"]), (0, {"at": CLIFF, "amount_raw": 105_483_264_472_548}))
        self.assertEqual(r["owner_program"], "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "the holder row itself is the Token-2022 escrow")
        self.assertEqual(res["mint_info"], {"program": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", "supply_raw": 955_867_521_146_311, "decimals": 6})
        self.assertEqual(pi.status_line(res), "ok (1 target: 1 Streamflow; 2 calls to the public Solana RPC)")

    def test_a_target_that_is_the_stream_account_is_decoded_without_a_lookup(self):
        rpc = FakeRpc()
        res = collect(MAKERS, [STREAM], rpc)
        r = row(res, STREAM)
        self.assertEqual((r["status"], r["found_by"], r["held_basis"], rpc.methods()), ("identified", "direct", "deposited minus withdrawn", ["getMultipleAccounts"]))

    def test_after_the_cliff_the_lock_is_fully_unlocked(self):
        r = row(collect(MAKERS, [ESCROW], now=CLIFF + 2), ESCROW)
        self.assertEqual((r["unlocked_at_read_raw"], r["next_unlock"]), (105_483_264_472_548, None))

    def test_a_vesting_stream_follows_streamflows_formula(self):
        deposited = 105_483_264_472_548
        start, cliff, day = 1_800_000_000, 1_800_086_400, 86_400

        def vest(raw):
            put_u64(raw, 409, start)
            put_u64(raw, 441, cliff)
            put_u64(raw, 449, deposited // 10)
            put_u64(raw, 425, day)
            put_u64(raw, 433, (deposited - deposited // 10) // 90)
            put_u64(raw, 33, cliff + 90 * day)
            raw[457] = 1  # cancellable by the sender

        stream_address = address_of(1)
        stream, escrow, token = synthetic_stream(stream_address, vest)
        accounts = dict(ACCOUNTS, **{escrow: token})
        rpc = FakeRpc(accounts=accounts, programs={stream_address: stream})
        r = row(collect(MAKERS, [escrow], rpc, now=cliff + 10 * day + 3600), escrow)
        per = (deposited - deposited // 10) // 90
        self.assertEqual((r["status"], r["stream_type"], r["cancelable_by_sender"]), ("identified", "vesting", True))
        self.assertEqual(r["unlocked_at_read_raw"], deposited // 10 + 10 * per)
        self.assertEqual(r["next_unlock"], {"at": cliff + 11 * day, "amount_raw": per})
        self.assertEqual(pi.unlocked_at(r, cliff - 1), 0)
        self.assertEqual(pi.unlocked_at(r, cliff), deposited // 10)
        self.assertEqual(pi.unlocked_at(r, cliff + 90 * day + 1), deposited)
        self.assertEqual(pi.next_unlock(r, start), (cliff, deposited // 10))

    def test_a_full_cliff_stream_the_sender_can_transfer_is_vesting(self):
        """Streamflow's isTokenLock (contractUtils.ts): top-up, automatic withdrawal, cancellable by either side or
        transferable by the sender make it vesting, even with the whole deposit at one cliff; transferable by the
        recipient alone does not."""
        def transferable(raw):
            raw[460] = 1

        stream_address = address_of(11)
        stream, escrow, token = synthetic_stream(stream_address, transferable)
        r = row(collect(MAKERS, [escrow], FakeRpc(accounts=dict(ACCOUNTS, **{escrow: token}), programs={stream_address: stream})), escrow)
        self.assertEqual((r["status"], r["cliff_amount_raw"] == r["deposited_raw"], r["end"] - r["cliff"], r["transferable_by_sender"], r["stream_type"]),
                         ("identified", True, 0, True, "vesting"))
        self.assertEqual(pi.stream_type(dict(r, transferable_by_sender=False)), "lock")
        self.assertEqual(pi.stream_type(dict(r, transferable_by_sender=False, transferable_by_recipient=True)), "lock")

    def test_at_exactly_the_end_time_the_period_formula_still_applies(self):
        """calculateUnlockedAmount returns the whole deposit only when `currentTimestamp > end`; at t == end the period
        formula still applies, so a remainder unlocks one second later."""
        deposited, day, periods = 105_483_264_472_548, 86_400, 91
        per = deposited // periods
        self.assertNotEqual(deposited % periods, 0, "precondition: the periods leave a remainder")

        def vest(raw):
            put_u64(raw, 449, 0)
            put_u64(raw, 425, day)
            put_u64(raw, 433, per)
            put_u64(raw, 33, CLIFF + periods * day)

        stream_address = address_of(12)
        stream, _, _ = synthetic_stream(stream_address, vest)
        r = pi.classify(stream_address, stream, MAKERS, NOW)
        end = CLIFF + periods * day
        self.assertEqual((r["status"], r["stream_type"], r["end"]), ("identified", "vesting", end))
        self.assertEqual(pi.unlocked_at(r, end), periods * per)
        self.assertLess(pi.unlocked_at(r, end), deposited)
        self.assertEqual(pi.unlocked_at(r, end + 1), deposited)
        self.assertEqual(pi.next_unlock(r, end), (end + 1, deposited - periods * per))

    def test_every_layout_check_refuses_instead_of_guessing(self):
        def put(offset, value):
            return lambda raw: put_u64(raw, offset, value)

        def setbyte(offset, value):
            def change(raw):
                raw[offset] = value
            return change

        def other_escrow(raw):
            raw[209:241] = b58decode(ESCROW)

        cases = {
            "flags": setbyte(458, 2), "closed flag": setbyte(671, 7),
            "timestamps": put(9, 1_500_000_000), "start after cliff": put(409, CLIFF + 10), "end before cliff": put(33, CLIFF - 10),
            "future creation": put(9, NOW + 10 * 86_400), "end year 2300": put(33, 10_413_792_000),
            "withdrawn over deposit": put(17, 2 * 105_483_264_472_548), "zero deposit": put(417, 0), "zero period": put(425, 0),
            "escrow derivation": other_escrow,
        }
        expected_check = {"flags": "flags", "closed flag": "flags", "escrow derivation": "escrow_derivation", "withdrawn over deposit": "amounts",
                          "zero deposit": "amounts", "zero period": "amounts"}
        for number, (name, mutate) in enumerate(cases.items()):
            with self.subTest(name):
                stream_address = address_of(1000 + number)
                stream, escrow, token = synthetic_stream(stream_address, mutate)
                direct = pi.classify(stream_address, stream, MAKERS, NOW)
                self.assertEqual((direct["status"], direct["reason"]), ("unavailable", "layout_mismatch"))
                self.assertEqual(direct["check"], expected_check.get(name, "timestamps"))
                self.assertNotIn("stream_type", direct, "never a guessed lock")
        short = with_raw(ACCOUNTS[STREAM], raw_of(ACCOUNTS[STREAM])[:700])
        self.assertEqual(pi.classify(STREAM, short, MAKERS, NOW)["check"], "length")
        moved = pi.classify(address_of(77), ACCOUNTS[STREAM], MAKERS, NOW)
        self.assertEqual((moved["status"], moved["check"]), ("unavailable", "escrow_derivation"), "the real bytes at another address fail the derivation")

    def test_a_stream_of_another_mint_is_refused(self):
        r = pi.classify(STREAM, ACCOUNTS[STREAM], ALOOOONG, NOW)
        self.assertEqual((r["status"], r["reason"], r["check"]), ("unavailable", "mint_mismatch", "mint"))
        self.assertNotIn("stream_type", r)

    def test_lookup_outcomes(self):
        empty = row(collect(MAKERS, [ESCROW], FakeRpc(programs={})), ESCROW)
        self.assertEqual((empty["status"], empty["detail"]), ("unidentified", "self_owned_token_account_no_stream"))
        twin = synthetic_stream(address_of(5))[0]
        twin_raw = bytearray(raw_of(twin))
        twin_raw[209:241] = b58decode(ESCROW)
        both = row(collect(MAKERS, [ESCROW], FakeRpc(programs={STREAM: ACCOUNTS[STREAM], address_of(5): with_raw(twin, bytes(twin_raw))})), ESCROW)
        self.assertEqual((both["status"], both["reason"]), ("unavailable", "stream_lookup_ambiguous"))
        rpc = FakeRpc(answers=[FakeResponse(rpc_body({"context": {"slot": 1}, "value": [ACCOUNTS[MAKERS], ACCOUNTS[ESCROW]]})), FakeResponse(rpc_body({"not": "a list"}))])
        bad = row(collect(MAKERS, [ESCROW], rpc), ESCROW)
        self.assertEqual((bad["status"], bad["reason"], bad["lookup_reason"]), ("unavailable", "stream_lookup_failed", "invalid_shape"))
        rpc = FakeRpc(answers=[FakeResponse(rpc_body({"context": {"slot": 1}, "value": [ACCOUNTS[MAKERS], ACCOUNTS[ESCROW]]})),
                               FakeResponse(json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32010, "message": "excluded"}}).encode())])
        failed = row(collect(MAKERS, [ESCROW], rpc), ESCROW)
        self.assertEqual((failed["status"], failed["lookup_reason"], failed["rpc_error_code"]), ("unavailable", "rpc_error", -32010))

    def test_the_live_lookup_answer_of_2026_10_19(self):
        """The script's own request, sent live once to the public RPC (coordinator smoke), and its exact answer."""
        self.assertEqual(LOOKUP["request_body"], pi.lookup_payload(MAKERS, ESCROW), "the live request was exactly the script's")
        rows = LOOKUP["answer_body"]["result"]
        self.assertEqual([(r["pubkey"], r["account"]["owner"], r["account"]["space"]) for r in rows], [(STREAM, pi.STREAMFLOW_PROGRAM, 1104)])
        batch = FakeResponse(rpc_body({"context": {"slot": 1}, "value": [ACCOUNTS[MAKERS], ACCOUNTS[ESCROW]]}))
        live = row(collect(MAKERS, [ESCROW], FakeRpc(answers=[batch, FakeResponse(json.dumps(LOOKUP["answer_body"]).encode())])), ESCROW)
        offline = row(collect(MAKERS, [ESCROW]), ESCROW)
        self.assertEqual(live, offline)
        self.assertEqual((live["status"], live["stream_type"], live["next_unlock"]), ("identified", "lock", {"at": CLIFF, "amount_raw": 105_483_264_472_548}))

    def test_a_failed_lookup_is_never_a_lock_and_never_unidentified(self):
        """No free per-account read links the escrow to its stream, so a failed lookup leaves an escrow-style token
        account: not called Streamflow, not called unidentified, no lock details."""
        batch = lambda: FakeResponse(rpc_body({"context": {"slot": 1}, "value": [ACCOUNTS[MAKERS], ACCOUNTS[ESCROW]]}))  # noqa: E731
        excluded = FakeResponse(json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -32010, "message": "excluded from account secondary indexes"}}).encode())
        cases = {"rpc_error": [batch(), excluded], "rate_limited": [batch(), http_error(429), http_error(429)], "access_denied": [batch(), http_error(403)],
                 "timeout": [batch(), socket.timeout()]}
        tmp = Path(tempfile.mkdtemp())
        try:
            for code, answers in cases.items():
                with self.subTest(code):
                    res = collect(MAKERS, [ESCROW], FakeRpc(answers=answers))
                    r = row(res, ESCROW)
                    self.assertEqual((r["status"], r["reason"], r["lookup_reason"], r["kind"]), ("unavailable", "stream_lookup_failed", code, "escrow_candidate"))
                    self.assertNotIn("stream_type", r)
                    write_result(tmp / code, res)
                    line = next(x for x in pi.present(tmp / code) if x.startswith(f"  {ESCROW}"))
                    self.assertEqual(line, f"  {ESCROW}: escrow-style token account (its own authority): unavailable (stream_lookup_failed, {code}); {pi.ESCROW_NOT_CONFIRMED}")
                    self.assertNotIn("unidentified", line)
                    self.assertNotIn("Streamflow lock", line)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_lookups_go_out_at_the_same_time_and_are_capped(self):
        accounts, programs, escrows = dict(ACCOUNTS), {}, []
        for seed in range(4):
            stream_address = address_of(100 + seed)
            stream, escrow, token = synthetic_stream(stream_address)
            accounts[escrow], programs[stream_address] = token, stream
            escrows.append(escrow)
        gate = threading.Barrier(3)
        rpc = FakeRpc(accounts=accounts, programs=programs, gate=gate)
        res = collect(MAKERS, escrows, rpc)
        self.assertFalse(gate.broken, "the three lookups were in flight together (a one-by-one loop would break the barrier)")
        self.assertEqual([row(res, e)["status"] for e in escrows], ["identified", "identified", "identified", "unavailable"])
        self.assertEqual(row(res, escrows[3])["reason"], "stream_lookup_cap")
        self.assertEqual((rpc.methods().count("getProgramAccounts"), res["request"]["stream_lookups"]), (3, 3))


class PumpSwapTests(unittest.TestCase):
    def test_the_aloooong_quote_side_pool_is_infrastructure(self):
        res = collect(ALOOOONG, [QUOTE_POOL])
        r = row(res, QUOTE_POOL)
        self.assertEqual((r["status"], r["kind"], r["side"], r["infrastructure"], r["exclude_hint"]), ("identified", "pumpswap_pool", "quote", True, f"--exclude {QUOTE_POOL}"))
        self.assertEqual((r["base_mint"], r["quote_mint"], r["index"], r["creator"]), ("Hukxg44mFqJ8AeVbtSebpGuJD9cF3XHzCCyDp9rapump", ALOOOONG, 0, "8Lqi5iXKxRPpu4KxSMbKC3i1byNcAhrNHXLJVCHmourp"))
        self.assertEqual(pi.status_line(res), "ok (1 target: 1 PumpSwap pool; 1 call to the public Solana RPC)")

    def test_base_side_pools_are_pools(self):
        for mint, pool, quote in ((ALOOOONG, ALO_POOL, "pumpCmXqMfrsAkQ5r49WcJnRayYRqmXz6ae8H7H9Dfn"), (MAKERS, MAKERS_POOL, "So11111111111111111111111111111111111111112")):
            with self.subTest(pool):
                r = row(collect(mint, [pool]), pool)
                self.assertEqual((r["side"], r["base_mint"], r["quote_mint"], r["infrastructure"], r["exclude_hint"]), ("base", mint, quote, False, None))
        neither = pi.classify(QUOTE_POOL, ACCOUNTS[QUOTE_POOL], MAKERS, NOW)
        self.assertEqual(neither["side"], "neither")

    def test_pool_checks_refuse_instead_of_guessing(self):
        raw = bytearray(raw_of(ACCOUNTS[QUOTE_POOL]))
        raw[11] ^= 1  # another creator: the address no longer derives
        self.assertEqual(pi.classify(QUOTE_POOL, with_raw(ACCOUNTS[QUOTE_POOL], bytes(raw)), ALOOOONG, NOW)["check"], "pool_derivation")
        raw = bytearray(raw_of(ACCOUNTS[QUOTE_POOL]))
        raw[8] = 1  # a stored bump the derivation does not give
        self.assertEqual(pi.classify(QUOTE_POOL, with_raw(ACCOUNTS[QUOTE_POOL], bytes(raw)), ALOOOONG, NOW)["check"], "pool_derivation")
        short = pi.classify(QUOTE_POOL, with_raw(ACCOUNTS[QUOTE_POOL], raw_of(ACCOUNTS[QUOTE_POOL])[:150]), ALOOOONG, NOW)
        self.assertEqual((short["status"], short["reason"], short["check"]), ("unavailable", "layout_mismatch", "length"))
        other = bytearray(raw_of(ACCOUNTS[QUOTE_POOL]))
        other[:8] = bytes(8)
        r = pi.classify(QUOTE_POOL, with_raw(ACCOUNTS[QUOTE_POOL], bytes(other)), ALOOOONG, NOW)
        self.assertEqual((r["status"], r["detail"], r["owner_program"]), ("unidentified", "not_a_pool_account", pi.PUMP_AMM_PROGRAM))


class UnidentifiedAndStatusTests(unittest.TestCase):
    def test_everything_else_stays_unidentified_with_its_owner_program(self):
        off_curve_system = address_of(9001)
        while not pi.off_curve(off_curve_system):
            off_curve_system = pi.b58encode(bytes(random.Random(off_curve_system).getrandbits(8) for _ in range(32)))
        other_program = with_raw(ACCOUNTS[QUOTE_POOL], b"\x01" * 64, owner="SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf")
        system = with_raw(ACCOUNTS[QUOTE_POOL], b"", owner=pi.SYSTEM_PROGRAM)
        token = bytearray(raw_of(ACCOUNTS[ESCROW]))
        token[32:64] = b58decode(DEV)
        accounts = dict(ACCOUNTS, **{"Hukxg44mFqJ8AeVbtSebpGuJD9cF3XHzCCyDp9rapump": other_program, off_curve_system: system,
                                    "So11111111111111111111111111111111111111112": with_raw(ACCOUNTS[ESCROW], bytes(token))})
        addresses = ["Hukxg44mFqJ8AeVbtSebpGuJD9cF3XHzCCyDp9rapump", off_curve_system, "So11111111111111111111111111111111111111112", address_of(31337)]
        res = collect(MAKERS, addresses, FakeRpc(accounts=accounts))
        rows = [row(res, a) for a in addresses]
        self.assertEqual([r["status"] for r in rows], ["unidentified"] * 4)
        self.assertEqual([r.get("detail") for r in rows], [None, "system_owned_off_curve", "token_account", "no_account"])
        self.assertEqual([r.get("owner_program") for r in rows], ["SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf", pi.SYSTEM_PROGRAM, "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb", None])
        tmp = Path(tempfile.mkdtemp())
        try:
            write_result(tmp, res)
            text = "\n".join(pi.present(tmp))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        self.assertIn("unidentified program account (owner program SQDS4ep65T869zMMBKyuUq6aD6EgTu8psMjkvj52pCf)", text)
        self.assertIn(f"{addresses[3]}: unidentified program account (owner program unknown); no account at this address", text)
        self.assertNotRegex(text, r"(?i)\bwallet\b")

    def test_statuses(self):
        rpc = FakeRpc()
        empty = pi.collect_pda_identity(MAKERS, [], opener=rpc, now=lambda: NOW)
        self.assertEqual((empty["status"], empty["reason"], empty["request"]["requests_sent"], rpc.requests), ("empty", "no_targets", 0, []))
        self.assertEqual(pi.status_line(empty), "empty (no program-account rows to identify; no RPC call sent)")
        gone = collect(address_of(4), [QUOTE_POOL])
        self.assertEqual((gone["status"], gone["reason"]), ("unavailable", "mint_not_found"))
        not_a_mint = collect(QUOTE_POOL, [ESCROW], FakeRpc(accounts=dict(ACCOUNTS)))
        self.assertEqual((not_a_mint["status"], not_a_mint["reason"]), ("unavailable", "mint_unreadable"))
        self.assertEqual(pi.status_line(not_a_mint), "unavailable (mint_unreadable; 1 call to the public Solana RPC)")
        many = [address_of(5000 + i) for i in range(120)]
        res = collect(MAKERS, many)
        self.assertEqual((len(res["targets"]), res["targets_not_read"]), (99, 21))

    def test_an_unreadable_account_is_a_fixed_code(self):
        broken = copy.deepcopy(ACCOUNTS[ESCROW])
        broken["data"] = ["%%%not base64", "base64"]
        r = row(collect(MAKERS, [ESCROW], FakeRpc(accounts=dict(ACCOUNTS, **{ESCROW: broken}))), ESCROW)
        self.assertEqual((r["status"], r["reason"]), ("unavailable", "account_unreadable"))


class TargetSelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_targets_come_from_the_saved_rows_with_full_addresses(self):
        on_curve = DEV
        off = ESCROW
        (self.tmp / "holder-analysis.json").write_text(json.dumps({"mint": MAKERS, "top_holders": [
            {"owner": ESCROW, "kind": "program_account", "share": 0.11021}, {"owner": MAKERS_POOL, "kind": "liquidity_pool", "share": 0.0569},
            {"owner": QUOTE_POOL, "kind": "controlled_vault", "share": 0.01}, {"owner": on_curve, "kind": "wallet", "share": 0.02},
            {"owner": "6mLfJ…nv3MW", "kind": "program_account", "share": 0.5}]}))
        (self.tmp / "holders.json").write_text(json.dumps({"mint": MAKERS, "top_holders": [
            {"rank": 1, "wallet": off, "share_pct": 11.02, "infrastructure": False}, {"rank": 2, "wallet": MAKERS_POOL, "share_pct": 5.69, "infrastructure": False},
            {"rank": 3, "wallet": STREAM, "share_pct": 1.0, "infrastructure": False}, {"rank": 4, "wallet": on_curve, "share_pct": 2.0, "infrastructure": False},
            {"rank": 5, "wallet": ALO_POOL, "share_pct": 3.0, "infrastructure": True}]}))
        targets, read = pi.collect_targets(self.tmp, MAKERS, [ALO_POOL])
        self.assertEqual(read, {"holder-analysis.json": "read", "holders.json": "read"})
        self.assertEqual([t["address"] for t in targets], [ALO_POOL, ESCROW, QUOTE_POOL] + ([STREAM] if pi.off_curve(STREAM) else []))
        self.assertEqual(targets[1]["from"], ["holder-analysis.json program_account", "holders.json off-curve"])
        self.assertEqual(targets[1]["row_share_pct"], 11.021)

    def test_files_of_another_mint_or_unreadable_are_skipped(self):
        (self.tmp / "holder-analysis.json").write_text(json.dumps({"mint": ALOOOONG, "top_holders": [{"owner": QUOTE_POOL, "kind": "program_account"}]}))
        (self.tmp / "holders.json").write_text("{not json")
        targets, read = pi.collect_targets(self.tmp, MAKERS, [])
        self.assertEqual((targets, read), ([], {"holder-analysis.json": "other_mint", "holders.json": "unreadable"}))
        targets, read = pi.collect_targets(self.tmp / "missing", MAKERS, [])
        self.assertEqual(read, {"holder-analysis.json": "missing", "holders.json": "missing"})


class CitedLayoutTests(unittest.TestCase):
    """The offsets are the cited layouts' summed field sizes, never typed in by hand."""

    STREAM_LAYOUT = [("magic", 8), ("version", 1), ("created_at", 8), ("withdrawn_amount", 8), ("canceled_at", 8), ("end_time", 8), ("last_withdrawn_at", 8),
                     ("sender", 32), ("sender_tokens", 32), ("recipient", 32), ("recipient_tokens", 32), ("mint", 32), ("escrow_tokens", 32),
                     ("streamflow_treasury", 32), ("streamflow_treasury_tokens", 32), ("streamflow_fee_total", 8), ("streamflow_fee_withdrawn", 8),
                     ("streamflow_fee_percent", 4), ("partner", 32), ("partner_tokens", 32), ("partner_fee_total", 8), ("partner_fee_withdrawn", 8),
                     ("partner_fee_percent", 4), ("start_time", 8), ("net_amount_deposited", 8), ("period", 8), ("amount_per_period", 8), ("cliff", 8),
                     ("cliff_amount", 8), ("cancelable_by_sender", 1), ("cancelable_by_recipient", 1), ("automatic_withdrawal", 1),
                     ("transferable_by_sender", 1), ("transferable_by_recipient", 1), ("can_topup", 1), ("stream_name", 64), ("withdraw_frequency", 8),
                     ("ghost", 4), ("pausable", 1), ("can_update_rate", 1), ("ghost2", 4), ("is_pda", 1), ("nonce", 4), ("create_params_padding", 121),
                     ("closed", 1), ("current_pause_start", 8), ("pause_cumulative", 8), ("last_rate_change_time", 8), ("funds_unlocked_at_last_rate_change", 8),
                     ("creation_fee", 4), ("creation_fee_claimed", 1), ("auto_claim_fee", 4), ("auto_claim_fee_claimed", 1), ("old_metadata", 32), ("payer", 32),
                     ("bump", 1), ("fee_partner", 32), ("cancel_request_time", 8)]
    POOL_LAYOUT = [("discriminator", 8), ("pool_bump", 1), ("index", 2), ("creator", 32), ("base_mint", 32), ("quote_mint", 32), ("lp_mint", 32),
                   ("pool_base_token_account", 32), ("pool_quote_token_account", 32), ("lp_supply", 8)]

    @staticmethod
    def offsets(layout):
        out, at = {}, 0
        for name, size in layout:
            out[name] = at
            at += size
        return out, at

    def test_streamflow_offsets_and_the_sdk_named_offsets(self):
        offsets, end = self.offsets(self.STREAM_LAYOUT)
        for table in (pi.STREAM_FIELDS_U64, pi.STREAM_FIELDS_ADDRESS, pi.STREAM_FIELDS_FLAG):
            for name, offset in table.items():
                self.assertEqual(offset, offsets[name], name)
        self.assertEqual(end, pi.STREAM_LAYOUT_END)
        for name, offset in pi.STREAM_CROSS_CHECK.items():  # constants.ts STREAM_STRUCT_OFFSET_*
            self.assertEqual(offsets[name], offset, name)
        self.assertEqual((offsets["mint"], offsets["start_time"], offsets["cancelable_by_sender"]), (177, 409, 457), "the handoff's offsets, re-verified")

    def test_pool_and_token_offsets(self):
        offsets, end = self.offsets(self.POOL_LAYOUT)
        self.assertEqual((pi.POOL_BUMP, pi.POOL_INDEX, pi.POOL_CREATOR, pi.POOL_BASE_MINT, pi.POOL_QUOTE_MINT, pi.POOL_LP_MINT, pi.POOL_BASE_TA, pi.POOL_QUOTE_TA, pi.POOL_MIN_LEN),
                         (offsets["pool_bump"], offsets["index"], offsets["creator"], offsets["base_mint"], offsets["quote_mint"], offsets["lp_mint"],
                          offsets["pool_base_token_account"], offsets["pool_quote_token_account"], offsets["lp_supply"]))
        mint, _ = self.offsets([("mint_authority", 36), ("supply", 8), ("decimals", 1), ("is_initialized", 1), ("freeze_authority", 36)])
        self.assertEqual((pi.MINT_SUPPLY, pi.MINT_DECIMALS, pi.MINT_IS_INITIALIZED), (mint["supply"], mint["decimals"], mint["is_initialized"]))
        account, size = self.offsets([("mint", 32), ("owner", 32), ("amount", 8), ("delegate", 36), ("state", 1), ("is_native", 12), ("delegated_amount", 8), ("close_authority", 36)])
        self.assertEqual((pi.TOKEN_ACCOUNT_MINT, pi.TOKEN_ACCOUNT_OWNER, pi.TOKEN_ACCOUNT_AMOUNT, pi.TOKEN_ACCOUNT_STATE, pi.TOKEN_ACCOUNT_LEN),
                         (account["mint"], account["owner"], account["amount"], account["state"], size))

    def test_the_layouts_match_the_provider_docs_cache_when_present(self):
        """Parity with the cached sources on this machine (skipped cleanly elsewhere, like the GMGN sibling parity)."""
        cache = Path(os.environ.get("PROVIDER_DOCS_CACHE") or "provider-docs-cache-not-set")
        streamflow, pump, spl = cache / "streamflow" / "protocol.md", cache / "pumpfun" / "idls.md", cache / "spltoken" / "layouts.md"
        if not (streamflow.is_file() and pump.is_file() and spl.is_file()):
            self.skipTest("provider-docs cache not on this machine")
        text = streamflow.read_text(encoding="utf-8")
        block = text.split("export const streamLayout", 1)[1].split("]);", 1)[0]
        cached = []
        for m in re.finditer(r'BufferLayout\.(?:blob\((\d+),\s*|seq\(BufferLayout\.u8\(\),\s*CREATE_PARAMS_PADDING,\s*|(u8|u32|f32)\()"(\w+)"', block):
            size, typed, name = m.group(1), m.group(2), m.group(3)
            cached.append((name, int(size) if size else {"u8": 1, "u32": 4, "f32": 4}[typed] if typed else 121))
        self.assertIn("export const CREATE_PARAMS_PADDING = 121;", text)
        self.assertEqual(cached, self.STREAM_LAYOUT)
        for name, value in (("SENDER", 49), ("RECIPIENT", 113), ("MINT", 177), ("CLOSED", 671), ("OLD_METADATA_KEY", 714)):
            self.assertIn(f"export const STREAM_STRUCT_OFFSET_{name} = {value};", text)
        self.assertIn('[ICluster.Mainnet]: "strmRqUCoQUgGUan5YhzUZa6KqdzwX5L6FpUxfmKg5m"', text)
        self.assertIn('export const ESCROW_SEED = Buffer.from("strm", "utf-8");', text)
        idl_text = pump.read_text(encoding="utf-8").split("idl/pump_amm.json ---", 1)[1].split("--- PAGE", 1)[0]
        idl = json.JSONDecoder().raw_decode(idl_text[idl_text.index("{"):])[0]
        self.assertEqual(idl["address"], pi.PUMP_AMM_PROGRAM)
        self.assertEqual(bytes(next(a for a in idl["accounts"] if a["name"] == "Pool")["discriminator"]), pi.PUMP_AMM_POOL_DISCRIMINATOR)
        fields = next(t for t in idl["types"] if t["name"] == "Pool")["type"]["fields"]
        sizes = {"u8": 1, "u16": 2, "pubkey": 32, "u64": 8}
        self.assertEqual([(f["name"], sizes[f["type"]]) for f in fields[:9]], self.POOL_LAYOUT[1:])
        seeds = next(a for a in next(i for i in idl["instructions"] if i["name"] == "create_pool")["accounts"] if a["name"] == "pool")["pda"]["seeds"]
        self.assertEqual([s.get("value") or s.get("path") for s in seeds], [list(b"pool"), "index", "creator", "base_mint", "quote_mint"])
        spl_text = spl.read_text(encoding="utf-8")
        self.assertIn("array_refs![src, 36, 8, 1, 1, 36];", spl_text)
        self.assertIn("array_refs![src, 32, 32, 8, 36, 1, 12, 8, 36];", spl_text)

    def test_the_program_address_rule_reproduces_the_live_addresses(self):
        self.assertEqual(pi.find_program_address([b"strm", b58decode(STREAM)], pi.STREAMFLOW_PROGRAM), (ESCROW, 253))
        raw = raw_of(ACCOUNTS[QUOTE_POOL])
        self.assertEqual(pi.find_program_address([b"pool", raw[9:11], raw[11:43], raw[43:75], raw[75:107]], pi.PUMP_AMM_PROGRAM), (QUOTE_POOL, raw[8]))


MAKERS_LINE = (f"  {ESCROW}: Streamflow lock of 11.03% of supply (105,483,264.47 tokens in the escrow): recipient {DEV} (also the sender), "
               f"unlocks 2027-04-16 04:00 UTC (cliff, all of it), not cancellable, not transferable, no top-up; withdrawn so far 0.00; "
               f"stream {STREAM} (created 2026-10-17 03:09 UTC)")
ALOOOONG_LINE = (f"  {QUOTE_POOL}: PumpSwap pool (this token is the quote side): infrastructure (quote side), consider --exclude {QUOTE_POOL}; "
                 "pair Hukxg44mFqJ8AeVbtSebpGuJD9cF3XHzCCyDp9rapump / this token")


class PresentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def lines(self, result, name="run"):
        run = self.tmp / name
        write_result(run, result)
        return pi.present(run)

    def test_the_owner_lines(self):
        makers = self.lines(collect(MAKERS, [ESCROW]), "makers")
        self.assertIn(MAKERS_LINE, makers)
        self.assertTrue(makers[0].startswith("PDA identity reads (follow-up lane pda_identity_reads; public Solana RPC, no key, free): read; data age "))
        self.assertTrue(makers[0].endswith("; 2 calls (1 Streamflow lookup)"))
        aloooong = self.lines(collect(ALOOOONG, [QUOTE_POOL]), "aloooong")
        self.assertIn(ALOOOONG_LINE, aloooong)
        base = self.lines(collect(ALOOOONG, [ALO_POOL]), "base")
        self.assertIn(f"  {ALO_POOL}: PumpSwap pool (this token is the base side): pool; pair this token / pumpCmXqMfrsAkQ5r49WcJnRayYRqmXz6ae8H7H9Dfn", base)
        for text in ("\n".join(makers), "\n".join(aloooong), "\n".join(base)):
            self.assertIsNone(REASSURING.search(text))
            self.assertIsNone(FLAG_WORDS.search(text))
            self.assertIn("presentation only", text)
            self.assertIn("cannot see:", text)

    def test_a_vesting_line_and_a_passed_cliff(self):
        r = collect(MAKERS, [ESCROW], now=CLIFF + 5)
        self.assertIn("unlocked since 2027-04-16 04:00 UTC (cliff passed, all of it)", "\n".join(self.lines(r, "passed")))
        day = 86_400

        def vest(raw):
            put_u64(raw, 449, 0)
            put_u64(raw, 425, day)
            put_u64(raw, 433, 105_483_264_472_548 // 100)
            put_u64(raw, 33, CLIFF + 100 * day)
            raw[460] = 1

        stream_address = address_of(2)
        stream, escrow, token = synthetic_stream(stream_address, vest)
        res = collect(MAKERS, [escrow], FakeRpc(accounts=dict(ACCOUNTS, **{escrow: token}), programs={stream_address: stream}))
        text = "\n".join(self.lines(res, "vest"))
        self.assertIn("Streamflow vesting stream of 11.03% of supply", text)
        self.assertIn("starts 2027-04-16 04:00 UTC, cliff 2027-04-16 04:00 UTC (0.00 tokens), then 1,054,832.64 every 1 day until 2027-07-25 04:00 UTC", text)
        self.assertIn("next unlock 2027-04-17 04:00 UTC (1,054,832.64 tokens)", text)
        self.assertIn("transferable by the sender", text)

    def test_a_rate_the_sender_can_change_is_named(self):
        """can_update_rate is decoded and printed: 'rate can be changed by the sender' (C1)."""
        def updatable(raw):
            raw[540] = 1

        stream_address = address_of(13)
        stream, escrow, token = synthetic_stream(stream_address, updatable)
        res = collect(MAKERS, [escrow], FakeRpc(accounts=dict(ACCOUNTS, **{escrow: token}), programs={stream_address: stream}))
        self.assertTrue(row(res, escrow)["can_update_rate"])
        line = next(x for x in self.lines(res, "rate") if x.startswith(f"  {escrow}"))
        self.assertIn(", no top-up, rate can be changed by the sender; withdrawn so far", line)
        self.assertNotIn("rate can be changed", "\n".join(self.lines(collect(MAKERS, [ESCROW]), "fixed")))

    def test_empty_unavailable_and_missing(self):
        empty = self.lines(pi.collect_pda_identity(MAKERS, [], now=lambda: NOW), "empty")
        self.assertIn("empty (no_targets)", empty[0])
        failed = self.lines(collect(MAKERS, [ESCROW], FakeRpc(answers=[http_error(403)])), "failed")
        self.assertIn("unavailable (access_denied)", failed[0])
        nothing = self.tmp / "nothing"
        nothing.mkdir()
        self.assertEqual(pi.present(nothing), ["PDA identity reads (follow-up lane pda_identity_reads; public Solana RPC, no key, free): not read (followup/pda_identity_reads.json missing)"])

    def test_random_damage_never_crashes(self):
        rng = random.Random(20261019)
        junk = [None, True, 0, -1, 2**70, 1e308, float("nan"), "x\n# y", [], [1, "a"], {}, {"at": "soon"}, "J4KJk…aZqqR"]
        base = collect(MAKERS, [ESCROW, QUOTE_POOL, STREAM, address_of(3)], FakeRpc(accounts=dict(ACCOUNTS)))
        for i in range(300):
            res = copy.deepcopy(base)
            for _ in range(rng.randint(1, 5)):
                rows = res.get("targets") if isinstance(res.get("targets"), list) else []
                holder = rng.choice([res, *[r for r in rows if isinstance(r, dict)], *([res["mint_info"]] if isinstance(res.get("mint_info"), dict) else [])])
                key = rng.choice(list(holder) or ["x"])
                if rng.random() < 0.3:
                    holder.pop(key, None)
                else:
                    holder[key] = copy.deepcopy(rng.choice(junk))
            run = self.tmp / f"fuzz{i}"
            (run / pi.OUT_DIR).mkdir(parents=True)
            (run / pi.OUT_DIR / pi.OUT_FILE).write_text(json.dumps(res, allow_nan=True))
            lines = pi.present(run)
            self.assertTrue(lines and all(isinstance(line, str) and "\n" not in line for line in lines))
            self.assertIsNone(REASSURING.search("\n".join(lines)))
        for whole in ([], "text", 7, None):
            run = self.tmp / f"whole{abs(hash(str(whole)))}"
            (run / pi.OUT_DIR).mkdir(parents=True)
            (run / pi.OUT_DIR / pi.OUT_FILE).write_text(json.dumps(whole))
            self.assertTrue(pi.present(run)[0].endswith("not read (followup/pda_identity_reads.json unreadable)"))

    def test_saved_codes_print_only_from_the_fixed_list(self):
        """A tampered file cannot put text into the report: unknown reason or check codes print as 'unrecognized code'."""
        res = collect(MAKERS, [ESCROW, QUOTE_POOL], FakeRpc(answers=[FakeResponse(rpc_body({"context": {"slot": 1}, "value": [ACCOUNTS[MAKERS], ACCOUNTS[ESCROW], ACCOUNTS[QUOTE_POOL]]})),
                                                                     http_error(403)]))
        self.assertEqual(row(res, ESCROW)["lookup_reason"], "access_denied")
        known = "\n".join(self.lines(res, "known"))
        self.assertIn(f"  {ESCROW}: escrow-style token account (its own authority): unavailable (stream_lookup_failed, access_denied); {pi.ESCROW_NOT_CONFIRMED}", known)
        row(res, ESCROW).update(reason="safe to buy", lookup_reason="clean\n# Verdict: low", check="SAFU")
        res.update(status="unavailable", reason="no risk")
        text = "\n".join(self.lines(res, "tampered"))
        self.assertIn("unavailable (unrecognized code)", text)
        self.assertIsNone(REASSURING.search(text))
        self.assertNotIn("SAFU", text)
        self.assertNotIn("no risk", text)
        res.update(status="ok", reason=None)
        text = "\n".join(self.lines(res, "tampered-row"))
        self.assertIn(f"  {ESCROW}: escrow-style token account (its own authority): unavailable (unrecognized code, unrecognized code, check unrecognized code)", text)
        self.assertIsNone(REASSURING.search(text))

    def test_shares_and_amounts_are_cut_never_rounded_up(self):
        self.assertEqual(pi._share(29_999_999, 100_000_000), "29.99%")
        self.assertEqual(pi._share(1, 100_000_000), "under 0.01%")
        self.assertEqual(pi._share(0, 100), "0.00%")
        self.assertEqual(pi._tokens(1_999_999, 6), "1.99")
        self.assertEqual(pi._share(5, 0), "unknown share")


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_main(self, argv, rpc):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(pi, "default_opener", return_value=rpc), mock.patch.object(pi.time, "sleep"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = pi.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_bad_input_exits_2_without_a_call(self):
        rpc = FakeRpc()
        for argv in (["not-a-mint", "--out", str(self.tmp)], [MAKERS], [MAKERS, "--out", str(self.tmp), "--target", "6mLfJ…nv3MW"],
                     ["--present", str(self.tmp / "missing")], [MAKERS, "--present", str(self.tmp)]):
            with self.subTest(argv):
                code, _, err = self.run_main(argv, rpc)
                self.assertEqual(code, 2)
                self.assertTrue(err.startswith("error:"))
        self.assertEqual(rpc.requests, [])

    def test_the_collector_reads_its_targets_and_writes_into_followup(self):
        (self.tmp / "holder-analysis.json").write_text(json.dumps({"mint": MAKERS, "top_holders": [{"owner": ESCROW, "kind": "program_account", "share": 0.11021}]}))
        code, out, _ = self.run_main([MAKERS, "--out", str(self.tmp)], FakeRpc())
        self.assertEqual((code, out.strip()), (0, "ok (1 target: 1 Streamflow; 2 calls to the public Solana RPC)"))
        saved = json.loads((self.tmp / "followup" / "pda_identity_reads.json").read_text())
        self.assertEqual((saved["schema"], saved["lane"], saved["presentation_only"], saved["targets_from"]),
                         ("holder-scan-pda-identity/1", "pda_identity_reads", True, {"holder-analysis.json": "read", "holders.json": "missing"}))
        code, out, _ = self.run_main([ALOOOONG, "--out", str(self.tmp / "none")], FakeRpc())
        self.assertEqual((code, out.strip()), (0, "empty (no program-account rows to identify; no RPC call sent)"))

    def test_present_opens_no_connection(self):
        write_result(self.tmp, collect(MAKERS, [ESCROW]))

        def refuse(*_a, **_k):
            raise AssertionError("network access in --present")

        out = io.StringIO()
        with mock.patch.object(pi, "default_opener", side_effect=refuse), mock.patch.object(socket, "create_connection", refuse), \
             mock.patch.object(socket.socket, "connect", refuse), contextlib.redirect_stdout(out):
            code = pi.main(["--present", str(self.tmp)])
        self.assertEqual(code, 0)
        self.assertIn(MAKERS_LINE, out.getvalue().splitlines())


class PresentationOnlyRuleTests(unittest.TestCase):
    """assess never reads followup/pda_identity_reads.json: the same assessment.json and report.md with or without it."""

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

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def assess(self, extra, name):
        out = self.tmp / name
        code, _, err = run_assess(self.mint, self.run_dir, extra, out=out)
        return code, err, (json.loads((out / "assessment.json").read_text()) if code == 0 else None), ((out / "report.md").read_text() if code == 0 else None)

    def test_the_followup_file_changes_nothing(self):
        lock = collect(MAKERS, [ESCROW, QUOTE_POOL])
        lock["mint"] = self.mint
        for extra, tag in ((["--bubblemaps-json", str(self.space_map)], "map"), (["--bubblemaps-json", str(self.alarm_map)], "alarm"), ([], "no-map")):
            with self.subTest(tag):
                code, err, before, md_before = self.assess(extra, f"{tag}-without")
                self.assertEqual(code, 0, err)
                write_result(self.run_dir, lock)
                try:
                    code, err, after, md_after = self.assess(extra, f"{tag}-with")
                finally:
                    shutil.rmtree(self.run_dir / pi.OUT_DIR)
                self.assertEqual(code, 0, err)
                self.assertEqual((after, md_after), (before, md_before))
        _, _, alarm, _ = self.assess(["--bubblemaps-json", str(self.alarm_map)], "alarm-check")
        self.assertTrue(alarm["flag"]["label"].startswith(hf.FLAG_DANGER), "the map alarm stands; an identity never softens it")

    def test_refused_as_providers_json_and_unknown_to_both_engines(self):
        write_result(self.run_dir, collect(MAKERS, [ESCROW]))
        try:
            code, err, _, _ = self.assess(["--providers-json", str(self.run_dir / pi.OUT_DIR / pi.OUT_FILE)], "refused")
        finally:
            shutil.rmtree(self.run_dir / pi.OUT_DIR)
        self.assertEqual(code, 2)
        self.assertIn("--providers-json must hold a JSON list of findings", err)
        for path in [SCRIPTS / "helius_forensics.py", SCRIPTS / "holder_analysis.py", *sorted((SCRIPTS / "ha").glob("*.py"))]:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("pda_identity", text, path.name)
            self.assertNotIn("followup", text, path.name)


class SelfContainedTests(unittest.TestCase):
    def test_every_code_the_script_writes_is_in_its_printable_list(self):
        text = (SCRIPTS / "pda_identity.py").read_text()
        written = set(re.findall(r'Failure\("(\w+)"', text)) | set(re.findall(r'refuse\("(\w+)"', text)) | set(re.findall(r'refuse\("\w+", "(\w+)"\)', text))
        written |= set(re.findall(r'"(?:reason|lookup_reason|check)": "(\w+)"', text)) | set(re.findall(r'\breason="(\w+)"', text)) | set(pi.HTTP_REASONS.values())
        written |= {"server_error", "http_error", "timeout", "network_error", "request_failed", "invalid_json", "invalid_shape", "rpc_error"}
        self.assertGreater(len(written), 30)
        self.assertEqual(sorted(written - pi.KNOWN_CODES), [])

    def test_standard_library_and_the_local_solana_helpers_only(self):
        text = (SCRIPTS / "pda_identity.py").read_text()
        modules = set()
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Import):
                modules |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        self.assertEqual(sorted(modules - set(sys.stdlib_module_names) - {"__future__"}), ["ha"])
        self.assertIn("from ha.solana import b58decode, is_on_curve", text)
        self.assertEqual(re.findall(r"\b[A-Z][A-Z0-9_]*_(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|RPC_URL)\b", text), [])
        self.assertNotIn("/Users/", text)
        self.assertNotIn(".env", text)


if __name__ == "__main__":
    unittest.main()
