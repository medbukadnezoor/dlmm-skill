"""DS-DEV-BAGS-T1 ("Gap E"): the `wallet_rpc_reads` follow-up collector (scripts/wallet_rpc_reads.py), its offline `--present`
block, and the dev-sent bags that exit_overhang.py --present now counts at zero cost (owner decision of 2026-10-27, "Count at
zero cost (Recommended)").

Offline: a fake JSON-RPC transport answering from public data read live on 2026-10-27 for the saved BTC scan of 2026-10-25
(fixtures/wallet_rpc_reads/btc_rpc_live_20261027.json, recorded while quote_curves.py ran at the same moment, its three
first-try 429s included; the run's four saved files that the lane and exit_overhang.py read are byte-identical copies in
fixtures/wallet_rpc_reads/20261025T103617Z-BTC.../), synthetic token accounts, signature pages and transfers, and synthetic
run folders built with test_exit_overhang's helpers. No key exists for this lane.

Covers the ticket's acceptance criteria: the BTC replay (LoCKu4f3... found as sent by the dev 7Pyr5o... and counted at zero
cost: 3.9x before, 4.8x after; LoCKWZ... not counted unless a read transfer's sender is a dev wallet) (1); a wallet that got its
tokens from another wallet stays under no cost basis (2); zero-cost share = min(share, sent) (3); dev unknown, the lane missing,
unreadable or unavailable: nothing new counted and the reason printed (4); the caps (6 wallets, 5 calls per wallet, 30 calls,
60 requests), the pace (4 per method per 10 s), the one retry after a 429 with Retry-After up to 10 s, the host, path and
method allowlists and no key, under counting fake transports (5); a history not read to its start says so and never "only
transfer" (6); assess byte-identical with and without the lane's file on the frozen clock of test_assess.run_assess, engine
flags unchanged (7); no clean, low or safe, unknown never printed as 0 (8)."""

from __future__ import annotations

import ast
import base64
import contextlib
import copy
import email.message
import hashlib
import io
import json
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

import create_slot as cs  # noqa: E402
import exit_overhang as eo  # noqa: E402
import helius_forensics as hf  # noqa: E402
import quote_curves as qc  # noqa: E402
import wallet_rpc_reads as wr  # noqa: E402
from ha.solana import b58decode, is_on_curve  # noqa: E402
from test_assess import _map, _run, case_negative_space_inu, run_assess  # noqa: E402
from test_exit_overhang import MINT, PRICE, addr, cheap, dear, row, write_run  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "wallet_rpc_reads"
LIVE = json.loads((FIX / "btc_rpc_live_20261027.json").read_text(encoding="utf-8"))
BTC_RUN = FIX / "20261025T103617Z-BTCk1ZAAGrbSq7e4L7mg8oiRKRqafkUbeLQpXeGq9BTC"
REGISTRY = SCRIPTS.parent / "collectors.json"
BTC = "BTCk1ZAAGrbSq7e4L7mg8oiRKRqafkUbeLQpXeGq9BTC"
DEV = "7Pyr5ojjjVPmKwfg33DQVcJW1sbjgPC4gKB2fh3DD5kH"
LOCK = "LoCKu4f3nBiNj2mNaR9qHhQWXAwq2eJxtjr4ZPAgxEe"            # 7.81%, a plain system wallet with a vanity prefix
LOCK_TA = "7uZdstvKkJ449zD9bcW7Br78oBCF7cd7jcEVfcHejX1v"
LOCK_SIG = "4KMfr5dURmPHJvTMcCV412qkZKtG5foyDt8efr7ZvJxwXQi4JLBKAQcday7E1MMR1fD5ip9GE9qKhJsiwYB6egVU"
LOCKWZ = "LoCKWZpYd4BtN92xBRxtiFzNhdFxahsvsALqgGz8gLe"          # 0.16%: pump payouts in, then sent on to the dev (hand read 2026-10-25)
OWN_CURVE = "6jvwz2hgtKNJmQrAUYcXMk5eu1aUBycG1RYTkyj7d3n1"       # BTC's own bonding curve
POOL = "9nkE3B5zF3yCDh8YrQrhch4dGNyLYcNBqEB7feo3V9Av"            # BTC's canonical PumpSwap pool
TARGETS = [LOCK, "649ot18fccD6Mc9V4aHWTdoSVCuqAEtg9aWuxBA9cRoU", "FJhCMmUbYbBPTMgZaLVW4eSFSnRJ5JJZpWaCPCUKYp3E",
           "96g3wVsMZEiGSegQD5ep5B2ZpR7Gqr9B3TzcPmAob3G1", "BM9CcyErJcu2mjrFvUsRRrD3snGeHDDVirJLvL6EjvMN"]
NOW = LIVE["read_at_unix"] + 60
MARK = "[for the executive summary] "
BEFORE_FLAG = (f"{MARK}EXIT OVERHANG: DANGER (provisional) — 36.22% of supply sits in 52 wallets that bought at half today's price or less: "
               "3.9x the main pool's tokens.")
AFTER_FLAG = (f"{MARK}EXIT OVERHANG: DANGER (provisional) — 36.22% of supply sits in 52 wallets that bought at half today's price or less, "
              "plus 7.81% the dev sent to 1 wallet at no cost: 4.8x the main pool's tokens.")
REASSURING = re.compile(r"(?i)\b(?:clean|safe|safer|safest|low|legit|safu)\b|low[\s_-]*risk|nobody")
DEV_HEAD = eo.DEV_HEAD


# ----------------------------------------------------------------------------- a JSON-RPC server double


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200, headers=None):
        self._buf, self.status, self.headers = io.BytesIO(body), status, headers

    def read(self, n=-1):
        return self._buf.read(n)

    def close(self):
        pass


def headers_of(values):
    msg = email.message.Message()
    for k, v in (values or {}).items():
        msg[k] = v
    return msg


def http_error(code, headers=None):
    return urllib.error.HTTPError(wr.RPC_ENDPOINT, code, "error", headers_of(headers), io.BytesIO(b""))


def rpc_body(result) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": 1, "result": result}).encode()


def rpc_error(code) -> FakeResponse:
    return FakeResponse(json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": code, "message": "a provider message that is never kept"}}).encode())


def live_tables():
    """The recorded 200 answers as lookup tables: token accounts by (owner, mint), signature pages by address, transactions
    by signature."""
    owned, pages, txs = {}, {}, {}
    for a in LIVE["answers"]:
        if a["http_status"] != 200:
            continue
        method, params, result = a["method"], a["params"], a["result"]
        if method == "getTokenAccountsByOwner":
            owned[(params[0], params[1]["mint"])] = result
        elif method == "getSignaturesForAddress":
            pages[params[0]] = result
        elif method == "getTransaction":
            txs[params[0]] = result
    return owned, pages, txs


LIVE_429 = [a["params"][0] for a in LIVE["answers"] if a["http_status"] == 429]


class FakeRpc:
    """Answers getTokenAccountsByOwner from `owned`, getSignaturesForAddress from `pages` and getTransaction from `txs`;
    `hook(payload)` may answer first (an exception, a response, or None to fall through). Counts requests, the most in flight
    at once and, with `clock`, the clock time of each request."""

    def __init__(self, owned=None, pages=None, txs=None, hook=None, delay=0.0, clock=None):
        live = live_tables()
        self.owned = dict(live[0] if owned is None else owned)
        self.pages = dict(live[1] if pages is None else pages)
        self.txs = dict(live[2] if txs is None else txs)
        self.hook, self.delay, self.clock = hook, delay, clock
        self.requests, self.times = [], []
        self.lock = threading.Lock()
        self.inflight = self.max_inflight = 0

    def methods(self):
        return [p["method"] for _, _, p in self.requests]

    def open(self, request, timeout=None):
        payload = json.loads(request.data.decode())
        with self.lock:
            self.requests.append((request, timeout, payload))
            if self.clock is not None:
                self.times.append((self.clock[0], payload["method"]))
            self.inflight += 1
            self.max_inflight = max(self.max_inflight, self.inflight)
        try:
            if self.delay:
                time.sleep(self.delay)
            answer = self.hook(payload) if self.hook else None
            if isinstance(answer, BaseException):
                raise answer
            if answer is not None:
                return answer
            method, params = payload["method"], payload["params"]
            if method == "getTokenAccountsByOwner":
                return FakeResponse(rpc_body(self.owned.get((params[0], params[1]["mint"]), {"context": {"slot": 1}, "value": []})))
            if method == "getSignaturesForAddress":
                return FakeResponse(rpc_body(self.pages.get(params[0], [])))
            if method == "getTransaction":
                return FakeResponse(rpc_body(self.txs.get(params[0])))
            raise AssertionError(f"unexpected method {method}")
        finally:
            with self.lock:
                self.inflight -= 1


def first_try_429(signatures, retry_after="10"):
    """The live run's three rate-limited first tries: a 429 (Retry-After 10) on the first request for each signature."""
    seen = set()

    def hook(payload):
        key = payload["params"][0]
        if payload["method"] == "getTransaction" and key in signatures and key not in seen:
            seen.add(key)
            return http_error(429, {"Retry-After": retry_after})
        return None

    return hook


# ----------------------------------------------------------------------------- synthetic chain data


def address_of(seed: str) -> str:
    return cs.b58encode(hashlib.sha256(seed.encode()).digest())


def wallet_of(seed: str) -> str:
    for i in range(1000):
        candidate = address_of(f"{seed}/{i}")
        if is_on_curve(candidate):
            return candidate
    raise AssertionError("no on-curve address")


def signature_of(seed: str) -> str:
    return cs.b58encode(hashlib.sha512(seed.encode()).digest())


def token_row(mint: str, owner: str, ta: str, amount: int, program: str = cs.TOKEN_2022_PROGRAM):
    raw = b58decode(mint) + b58decode(owner) + struct.pack("<Q", amount)
    return {"pubkey": ta, "account": {"owner": program, "data": [base64.b64encode(raw).decode(), "base64"], "space": 182, "lamports": 1, "executable": False, "rentEpoch": 0}}


def transfer_tx(signature, slot, block_time, mint, wallet, wallet_ta, sender, sender_ta, amount, *, decimals=6, direction="in", inner=False):
    """A minimal successful jsonParsed transaction: `sender` moves `amount` base units of `mint` to `wallet` (or back, with
    direction 'out'), by a transferChecked at the top level or inside another program's instruction."""
    src, dst = (sender_ta, wallet_ta) if direction == "in" else (wallet_ta, sender_ta)
    signer = sender if direction == "in" else wallet
    keys = [{"pubkey": signer, "signer": True}, {"pubkey": sender_ta, "signer": False}, {"pubkey": wallet_ta, "signer": False}, {"pubkey": mint, "signer": False}]
    s_pre, w_pre = (amount * 2, 0) if direction == "in" else (0, amount * 2)
    s_post, w_post = (amount, amount) if direction == "in" else (amount, amount)
    bal = lambda i, owner, n: {"accountIndex": i, "mint": mint, "owner": owner, "uiTokenAmount": {"amount": str(n), "decimals": decimals}}  # noqa: E731
    ix = {"program": "spl-token", "programId": cs.TOKEN_2022_PROGRAM, "parsed": {"type": "transferChecked", "info": {"source": src, "destination": dst, "authority": signer}}}
    top = [{"programId": address_of("some program")}] if inner else [ix]
    return {"slot": slot, "blockTime": block_time,
            "meta": {"err": None, "preTokenBalances": [bal(1, sender, s_pre), bal(2, wallet, w_pre)], "postTokenBalances": [bal(1, sender, s_post), bal(2, wallet, w_post)],
                     "innerInstructions": [{"index": 0, "instructions": [ix]}] if inner else []},
            "transaction": {"signatures": [signature], "message": {"accountKeys": keys, "instructions": top}}}


class Chain:
    """Synthetic wallets of one mint, each with token accounts, a signature page and transfers in from `sender`."""

    def __init__(self, mint: str):
        self.mint, self.owned, self.pages, self.txs = mint, {}, {}, {}

    def wallet(self, wallet: str, sender: str, *, transfers: int = 1, accounts: int = 1, full_page: bool = False, amount: int = 1_000_000) -> list[str]:
        rows, sigs = [], []
        for a in range(accounts):
            ta = address_of(f"ta/{wallet}/{a}")
            rows.append(token_row(self.mint, wallet, ta, amount * transfers))
            entries = []
            for k in range(transfers):
                sig = signature_of(f"{wallet}/{a}/{k}")
                slot, t = 460_000_000 + k, NOW - 7200 + k
                self.txs[sig] = transfer_tx(sig, slot, t, self.mint, wallet, ta, sender, address_of(f"ta/{sender}"), amount)
                entries.append({"signature": sig, "slot": slot, "err": None, "blockTime": t})
                sigs.append(sig)
            if full_page:
                entries += [{"signature": signature_of(f"{wallet}/{a}/later/{k}"), "slot": 470_000_000, "err": None, "blockTime": NOW - 60}
                            for k in range(cs.SIGNATURE_PAGE - len(entries))]
            self.pages[ta] = list(reversed(entries))  # newest first
        self.owned[(wallet, self.mint)] = {"context": {"slot": 1}, "value": rows}
        return sigs

    def rpc(self, **kw):
        return FakeRpc(owned=self.owned, pages=self.pages, txs=self.txs, **kw)


def lane_folder(tmp: Path, mint: str, rows: list[tuple[str, float, float | None, bool]], *, top: list[tuple[str, float, bool]] | None = None) -> Path:
    """A run folder with gmgn_holder_pnl.json rows (address, share 0..1, avg_cost, transfer_in) and holders.json rows
    (wallet, share_pct, infrastructure)."""
    run = tmp / f"lane-{len(list(tmp.iterdir()))}"
    (run / "followup").mkdir(parents=True)
    (run / "gmgn_holder_pnl.json").write_text(json.dumps({"schema": wr.GMGN_SCHEMA, "mint": mint, "status": "ok", "rows": [
        {"address": a, "amount_percentage": s, "addr_type": 0, "avg_cost": c, "transfer_in": t} for a, s, c, t in rows]}))
    top = [(a, s * 100, False) for a, s, _, _ in rows] if top is None else top
    (run / "holders.json").write_text(json.dumps({"mint": mint, "pool_addresses": [a for a, _, i in top if i],
                                                  "top_holders": [{"rank": n, "wallet": a, "share_pct": s, "infrastructure": i} for n, (a, s, i) in enumerate(top, 1)]}))
    return run


def collect(run: Path, rpc=None, mint=BTC, sleeps=None, workers=wr.MAX_WORKERS, monotonic=time.monotonic):
    sleeps = [] if sleeps is None else sleeps
    return wr.collect_wallet_reads(mint, run, workers=workers, opener=rpc or FakeRpc(), now=lambda: NOW, monotonic=monotonic, sleep=sleeps.append)


def write_result(run: Path, result) -> None:
    (run / wr.OUT_DIR).mkdir(parents=True, exist_ok=True)
    (run / wr.OUT_DIR / wr.OUT_FILE).write_text(json.dumps(result, indent=1))


def btc_folder(tmp: Path) -> Path:
    run = tmp / BTC_RUN.name
    shutil.copytree(BTC_RUN, run)
    return run


def wallet(result, address):
    return next(w for w in result["wallets"] if w["address"] == address)


class TempDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


# ----------------------------------------------------------------------------- the BTC replay (AC1)


class BtcReplayTests(TempDirTest):
    def test_the_targets_and_lockus_one_transfer_from_the_dev(self):
        run = btc_folder(self.tmp)
        rpc = FakeRpc()
        res = collect(run, rpc)
        self.assertEqual((res["status"], res["reason"]), ("ok", None))
        self.assertEqual([w["address"] for w in res["wallets"]], TARGETS)
        self.assertEqual(wallet(res, LOCK)["why"], ["no GMGN cost basis", "GMGN transfer_in tag", "above 5% of supply"])
        self.assertIn(LOCKWZ, [w["address"] for w in res["not_read"]], "LoCKWZ is not among the 5 largest: not read (cap)")
        lock = wallet(res, LOCK)
        self.assertEqual((lock["status"], lock["complete"], lock["history_start_reached"], lock["signatures_seen"], lock["transactions_read"], lock["incoming"],
                          lock["outgoing_seen"], lock["calls"], lock["token_program"]),
                         ("read", True, True, 1, 1, 1, False, 3, cs.TOKEN_2022_PROGRAM))
        self.assertEqual(lock["token_accounts"][0]["token_account"], LOCK_TA)
        event = lock["events"][0]
        self.assertEqual((event["signature"], event["direction"], event["amount_raw"], event["decimals"], event["kind"], event["counterparty_owner"],
                          event["signers"], event["fee_payer"], qc._utc(event["block_time"])),
                         (LOCK_SIG, "in", 75_000_000_000_000, 6, "transfer", DEV, [DEV], DEV, "2026-10-25 06:52:17 UTC"))
        self.assertEqual(event["senders"], [{"owner": DEV, "token_account": None, "amount_raw": 75_375_000_000_000}], "the dev also sent 375,000 to another wallet")
        for address in TARGETS[1:]:  # the other four bought from BTC's own curve, its pool or another program account
            w = wallet(res, address)
            owners = {s["owner"] for e in w["events"] for s in e["senders"]}
            self.assertNotIn(DEV, owners, address)
            self.assertTrue(owners & {OWN_CURVE, POOL}, address)
        self.assertEqual(len(rpc.requests), 23)
        self.assertLessEqual(res["request"]["requests_sent"], wr.MAX_REQUESTS)

    def test_the_live_rate_limits_replayed_with_one_retry_each(self):
        self.assertEqual(len(LIVE_429), 3, "the live run met three 429s while quote_curves ran at the same moment")
        self.assertTrue(all(a.get("retry_after") == "10" for a in LIVE["answers"] if a["http_status"] == 429))
        sleeps = []
        rpc = FakeRpc(hook=first_try_429(set(LIVE_429)))
        res = collect(btc_folder(self.tmp), rpc, sleeps=sleeps)
        self.assertEqual(wr.status_line(res), "ok (5 wallets read: 5 read, 0 unavailable, 5 with an incoming transfer seen, 9 not read (caps); "
                                              "23 calls to the public Solana RPC, 26 requests with retries)")
        self.assertEqual((len(rpc.requests), res["request"]["rate_limit_pauses"]), (26, 3))
        retried = [c for c in res["request"]["calls"] if c["attempts"] == 2]
        self.assertEqual(len(retried), 3)
        self.assertTrue(all(c["reason"] is None and c["method"] == "getTransaction" for c in retried))
        self.assertEqual([m for _, _, p in rpc.requests for m in [p["method"]]].count("getTransaction"), 16)
        self.assertTrue(any(9.0 < s <= wr.RETRY_MAX_WAIT_S for s in sleeps), "the 10 s Retry-After is honoured")

    def test_exit_overhang_counts_lockus_bag_at_zero_cost(self):
        run = btc_folder(self.tmp)
        before = eo.present(run)
        self.assertEqual(before[0], BEFORE_FLAG)
        self.assertIn(f"{DEV_HEAD}: not read (followup/wallet_rpc_reads.json missing); nothing counted", before)
        write_result(run, collect(run))
        after = eo.present(run)
        self.assertEqual(after[0], AFTER_FLAG)
        m = eo.measure(run)
        self.assertEqual((f"{m['cheap_ratio']:.2f}", f"{m['ratio']:.2f}", f"{m['dev_pct']:.2f}", [b["row"]["address"] for b in m["dev_counted"]]),
                         ("3.91", "4.75", "7.81", [LOCK]))
        line = next(x for x in after if x.startswith(f"    {LOCK}: "))
        for needle in ("7.81% of supply (GMGN)", "no GMGN cost basis, GMGN transfer_in tag", "the dev sent it 75,000,000 tokens (7.81% of supply)",
                       f"from {DEV} at 2026-10-25 06:52 UTC = 2026-10-25 13:52 WIB", f"signature {LOCK_SIG}", "counted 7.81% at zero cost",
                       "its whole token-account history was read: the only transfer into it"):
            self.assertIn(needle, line, needle)
        head = next(x for x in after if x.startswith(DEV_HEAD))
        self.assertIn(f"7.81% of supply in 1 wallet that got tokens by transfer from this token's dev wallets ({DEV}), counted in the ratio; with the wallets "
                      "at or below 1/2: 44.03% of supply = 4.8x the main pool's tokens (5 wallets read, ", head)
        self.assertIn("  no cost basis here = no average buy from GMGN: 3 wallets, 1.13% of supply (", "\n".join(after))
        self.assertIn("  no cost basis here = no average buy from GMGN: 4 wallets, 8.93% of supply (", "\n".join(before))
        self.assertIn("and the wallets the dev sent its tokens to (1 wallet) sold into the main pool at once", "\n".join(after))
        # everything else as today: the entry lines keep GMGN's average buys only
        self.assertEqual(after[4:6], before[4:6])
        self.assertIn("52 wallets, 36.22% of supply = 3.9x the main pool's tokens", after[4])
        for line in after:
            self.assertIsNone(REASSURING.search(line), line)

    def test_lockwz_is_counted_only_when_a_read_transfer_came_from_a_dev_wallet(self):
        """AC1: LoCKWZ... got pump-program payouts (senders: curve accounts, signed by HckQ93...) and sent them on to the dev
        (the hand read of 2026-10-25). Read that way it is not dev-sent; only a read transfer whose sender is a dev wallet makes
        it one (then min(its 0.16% share, what was sent))."""
        run = btc_folder(self.tmp)
        res = collect(run)
        payout = signature_of("payout")
        res["wallets"].append({"address": LOCKWZ, "status": "read", "complete": True, "history_start_reached": True, "incoming": 1, "outgoing_seen": True,
                               "transactions_read": 2, "successful_signatures": 2, "events": [
                                   {"signature": payout, "direction": "in", "amount_raw": 1_844_679_558_119, "decimals": 6, "block_time": 1792914624,
                                    "senders": [{"owner": OWN_CURVE, "token_account": None, "amount_raw": 1_844_679_558_119}],
                                    "signers": ["HckQ93Xqjjo8mwt5pNPWvyCTZXQZ858rvzmm7ZRrZg9t"]},
                                   {"signature": signature_of("out to dev"), "direction": "out", "amount_raw": 1_844_679_558_119, "decimals": 6,
                                    "block_time": 1792914660, "senders": [], "receivers": [{"owner": DEV, "token_account": None, "amount_raw": 1_844_679_558_119}]}]})
        write_result(run, res)
        self.assertEqual(eo.present(run)[0], AFTER_FLAG)
        self.assertFalse(any(x.startswith(f"    {LOCKWZ}") for x in eo.present(run)))
        res["wallets"][-1]["events"][0]["senders"][0]["owner"] = DEV  # mutation: the sender is the dev
        write_result(run, res)
        lines = eo.present(run)
        self.assertIn("plus 7.97% the dev sent to 2 wallets at no cost", lines[0])
        line = next(x for x in lines if x.startswith(f"    {LOCKWZ}: "))
        self.assertIn("0.16% of supply (GMGN)", line)
        self.assertIn("the dev sent it 1,844,679 tokens (0.19% of supply)", line)
        self.assertIn("counted 0.16% at zero cost", line)
        self.assertNotIn("the only transfer", line, "an outgoing transfer was seen")


# ----------------------------------------------------------------------------- the join in exit_overhang.py (AC2, AC3, AC4)


SYN_DEV = wallet_of("synthetic dev")
OTHER = wallet_of("another wallet")


def trace(dev=(SYN_DEV,), status="ok", mint=MINT):
    return {"schema": eo.TRACE_SCHEMA, "mint": mint, "status": status, "reason": "no_create_tx_pointer" if status == "unavailable" else None,
            "presentation_only": True, "create_tx": {"dev_wallets": list(dev)}, "trace": {"wallets": []}}


def event(sender, tokens, seed, *, direction="in", decimals=6, block_time=1792911137):
    raw = int(tokens * 10 ** decimals)
    return {"signature": signature_of(seed), "direction": direction, "amount_raw": raw, "decimals": decimals, "block_time": block_time,
            "senders": [{"owner": sender, "token_account": None, "amount_raw": raw}] if direction == "in" else [], "receivers": []}


def entry(address, events, *, complete=True, start=True, status="read", outgoing=False, read=None, seen=None):
    return {"address": address, "status": status, "complete": complete, "history_start_reached": start, "events": events,
            "incoming": sum(1 for e in events if isinstance(e, dict) and e.get("direction") == "in"), "outgoing_seen": outgoing,
            "transactions_read": len(events) if read is None else read, "successful_signatures": len(events) if seen is None else seen}


def reads(entries, *, status="ok", mint=MINT, schema=wr.SCHEMA):
    return {"schema": schema, "lane": "wallet_rpc_reads", "mint": mint, "status": status, "reason": "rate_limited" if status == "unavailable" else None,
            "fetched_at": "2026-10-27T08:14:24Z", "presentation_only": True, "wallets": entries}


def join_run(tmp: Path, name: str, rows, lane=None, *, tr=None, pool_pct=10.0) -> Path:
    run = write_run(tmp / name, rows, pool_pct=pool_pct, trace=trace() if tr is None else tr)
    if lane is not None:
        (run / "followup").mkdir(exist_ok=True)
        (run / eo.READS_FILE).write_text(json.dumps(lane) if not isinstance(lane, str) else lane)
    return run


BASE_ROWS = [cheap(1, 0.10), row(addr(2), 0.10, None, transfer_in=True), dear(3, 0.05)]  # 10% cheap, 10% no-basis transfer_in wallet
BASE_FLAG = f"{MARK}EXIT OVERHANG: CAUTION (provisional) — 10.00% of supply sits in 1 wallet that bought at half today's price or less: 1.0x the main pool's tokens."


class ExitOverhangJoinTests(TempDirTest):
    def test_a_dev_sent_bag_joins_the_ratio_and_can_move_the_level(self):
        run = join_run(self.tmp, "dev", BASE_ROWS, reads([entry(addr(2), [event(SYN_DEV, 100_000_000, "a")])]))
        lines = eo.present(run)
        self.assertEqual(lines[0], f"{MARK}EXIT OVERHANG: DANGER (provisional) — 10.00% of supply sits in 1 wallet that bought at half today's price or less, "
                                   "plus 10.00% the dev sent to 1 wallet at no cost: 2.0x the main pool's tokens.")
        self.assertIn("  entry at or below 1/2 of today's price (bought at or below $500k market cap): 1 wallet, 10.00% of supply = 1.0x the main pool's tokens", lines)

    def test_dev_sent_bags_without_any_cheap_wallet(self):
        run = join_run(self.tmp, "no-cheap", [dear(1, 0.20), row(addr(2), 0.10, None, transfer_in=True)], reads([entry(addr(2), [event(SYN_DEV, 100_000_000, "n")])]))
        lines = eo.present(run)
        self.assertEqual(lines[0], f"{MARK}EXIT OVERHANG: CAUTION (provisional) — 0.00% of supply sits in 0 wallets that bought at half today's price or less, "
                                   "plus 10.00% the dev sent to 1 wallet at no cost: 1.0x the main pool's tokens.")
        self.assertIn("  pool math: if all the wallets the dev sent its tokens to (1 wallet) sold into the main pool at once, constant-product pool math puts "
                      "the price about 75% lower; real dumps are spread out, and other pools and buyers absorb some of it", lines)
        self.assertIn("  biggest bags: no wallet in GMGN's top 100 bought at or below 1/2 of today's price (by GMGN's average buy)", lines)
        self.assertFalse(any(x.startswith("  pool math and biggest bags") for x in lines))

    def test_ac2_a_wallet_that_got_its_tokens_from_another_wallet_stays_apart(self):
        run = join_run(self.tmp, "other", BASE_ROWS, reads([entry(addr(2), [event(OTHER, 100_000_000, "b")])]))
        lines = eo.present(run)
        self.assertEqual(lines[0], BASE_FLAG)
        m = eo.measure(run)
        self.assertEqual(([r["address"] for r in m["no_basis"]], m["dev_counted"], m["ratio"]), ([addr(2)], [], 1.0))
        self.assertTrue(any(x.startswith("  no cost basis here = no average buy from GMGN: 1 wallet, 10.00% of supply (") and "not in the ratio;" in x for x in lines))
        self.assertIn(f"{DEV_HEAD}: none seen: no transfer from this token's dev wallets ({SYN_DEV}) into the 1 wallet read, 2026-10-27 08:14 UTC = "
                      "2026-10-27 15:14 WIB; nothing counted (what was read, not an all-clear)", lines)

    def test_ac3_the_zero_cost_share_is_the_smaller_of_its_share_and_what_the_dev_sent(self):
        later_bought = join_run(self.tmp, "bought-more", BASE_ROWS, reads([entry(addr(2), [event(SYN_DEV, 60_000_000, "c"), event(OTHER, 40_000_000, "d")])]))
        m = eo.measure(later_bought)
        self.assertEqual((f"{m['dev_pct']:.2f}", f"{m['ratio']:.2f}"), ("6.00", "1.60"))
        line = next(x for x in eo.present(later_bought) if x.startswith(f"    {addr(2)}: "))
        self.assertIn("the dev sent it 60,000,000 tokens (6.00% of supply)", line)
        self.assertIn("counted 6.00% at zero cost; the rest of its share (4.00%) did not come from the dev in the transfers read: not counted", line)
        sold_some = join_run(self.tmp, "sold-some", [cheap(1, 0.10), row(addr(2), 0.05, None, transfer_in=True)],
                             reads([entry(addr(2), [event(SYN_DEV, 80_000_000, "e")], outgoing=True)]))
        m = eo.measure(sold_some)
        self.assertEqual((f"{m['dev_pct']:.2f}", f"{m['ratio']:.2f}"), ("5.00", "1.50"))
        self.assertIn("plus 5.00% the dev sent to 1 wallet at no cost: 1.5x", eo.present(sold_some)[0])

    def test_ac4_dev_unknown_or_the_lane_not_read_counts_nothing_and_says_why(self):
        lane = reads([entry(addr(2), [event(SYN_DEV, 100_000_000, "f")])])
        hand_written = {"lane": "wallet_rpc_reads", "status": "partial", "parts": [{"addresses": [{"address": addr(2), "events": [{"counterparty_owner": SYN_DEV}]}]}]}
        cases = {
            "lane missing": (None, None, "followup/wallet_rpc_reads.json missing"),
            "lane hand-written": (hand_written, None, "followup/wallet_rpc_reads.json unreadable"),
            "lane not json": ("{oops", None, "followup/wallet_rpc_reads.json unreadable"),
            "lane unavailable": (reads([], status="unavailable"), None, "wallet_rpc_reads unavailable: rate_limited"),
            "lane other mint": (reads(lane["wallets"], mint=addr(40)), None, "followup/wallet_rpc_reads.json is for another mint"),
            "trace missing": (lane, False, "this token's dev not known: followup/create_slot_trace.json missing"),
            "trace unavailable": (lane, trace(status="unavailable"), "this token's dev not known: create_slot_trace unavailable: no_create_tx_pointer"),
            "trace other mint": (lane, trace(mint=addr(41)), "this token's dev not known: followup/create_slot_trace.json is for another mint"),
            "trace names no creator": (lane, trace(dev=()), "this token's dev not known: the create-slot trace names no creator"),
            "trace foreign": (lane, {"schema": "x"}, "this token's dev not known: followup/create_slot_trace.json unreadable"),
        }
        for name, (lane_data, tr, why) in cases.items():
            with self.subTest(name):
                run = write_run(self.tmp / name.replace(" ", "-"), BASE_ROWS, pool_pct=10.0, trace=None if tr is False else (trace() if tr is None else tr))
                if lane_data is not None:
                    (run / "followup").mkdir(exist_ok=True)
                    (run / eo.READS_FILE).write_text(lane_data if isinstance(lane_data, str) else json.dumps(lane_data))
                lines = eo.present(run)
                self.assertEqual(lines[0], BASE_FLAG)
                self.assertIn(f"{DEV_HEAD}: not read ({why}); nothing counted", lines)
                self.assertEqual(eo.measure(run)["ratio"], 1.0)

    def test_a_wallet_already_cheap_by_its_average_buy_adds_nothing(self):
        run = join_run(self.tmp, "cheap-too", [cheap(1, 0.10, transfer_in=True), dear(3, 0.05)], reads([entry(addr(1), [event(SYN_DEV, 100_000_000, "g")])]))
        lines = eo.present(run)
        self.assertEqual(lines[0], BASE_FLAG)
        self.assertIn(f"    {addr(1)}: the dev also sent it 100,000,000 tokens (100,000,000 tokens from {SYN_DEV} at 2026-10-25 06:52 UTC = 2026-10-25 13:52 WIB, "
                      f"signature {signature_of('g')}); already counted above at GMGN's average buy, nothing added", lines)

    def test_a_wallet_with_a_cost_basis_and_no_transfer_in_tag_is_never_a_dev_bag(self):
        run = join_run(self.tmp, "costed", [cheap(1, 0.10), dear(2, 0.10), dear(3, 0.05)], reads([entry(addr(2), [event(SYN_DEV, 100_000_000, "h")])]))
        self.assertEqual(eo.present(run)[0], BASE_FLAG)
        tagged = join_run(self.tmp, "costed-tagged", [cheap(1, 0.10), row(addr(2), 0.10, PRICE, transfer_in=True), dear(3, 0.05)],
                          reads([entry(addr(2), [event(SYN_DEV, 100_000_000, "i")])]))
        self.assertIn("plus 10.00% the dev sent to 1 wallet at no cost: 2.0x", eo.present(tagged)[0], "a transfer_in wallet above 1/2 by its average buy counts")

    def test_unknown_or_damaged_values_never_count_and_never_print_as_zero(self):
        good = event(SYN_DEV, 100_000_000, "j")
        damaged = [{**good, "amount_raw": "100"}, {**good, "amount_raw": -5}, {**good, "amount_raw": True}, {**good, "decimals": 40}, {**good, "decimals": None},
                   {**good, "signature": "not a signature"}, {**good, "senders": "x"}, {**good, "senders": [{"owner": SYN_DEV, "amount_raw": "1"}]},
                   "not an event", {**good, "amount_raw": 0}, {**good, "senders": [{"owner": "not an address", "amount_raw": 1}]}]
        for n, bad in enumerate(damaged):  # Repair R1: next to a good dev transfer, a damaged one makes the whole file's values unreadable
            with self.subTest(bad=str(bad)[:60]):
                lines = eo.present(join_run(self.tmp, f"damaged-{n}", BASE_ROWS, reads([entry(addr(2), [good, bad])])))
                self.assertEqual(lines[0], BASE_FLAG)
                self.assertIn(f"{DEV_HEAD}: not read (wallet_rpc_reads values unreadable); nothing counted", lines)
        lines = eo.present(join_run(self.tmp, "outgoing", BASE_ROWS, reads([entry(addr(2), [{**good, "direction": "out"}])])))
        self.assertEqual(lines[0], BASE_FLAG, "an outgoing transfer is never a dev-sent bag")
        self.assertTrue(any(x.startswith(f"{DEV_HEAD}: none seen: ") for x in lines))
        unknown_share = join_run(self.tmp, "share-unknown", [cheap(1, 0.10), {**row(addr(2), 0.10, None, transfer_in=True), "amount_percentage": "x"}],
                                 reads([entry(addr(2), [good])]))
        lines = eo.present(unknown_share)
        self.assertEqual(lines[0], BASE_FLAG)
        line = next(x for x in lines if x.startswith(f"    {addr(2)}: "))
        self.assertIn("share of supply not read (GMGN)", line)
        self.assertIn("its share is not read: not counted", line)
        self.assertNotIn(" 0.00%", line)
        for bad in ({"wallets": "x"}, {"status": "partial"}, {"presentation_only": False}):
            with self.subTest(bad):
                run = join_run(self.tmp, f"bad-{len(list(self.tmp.iterdir()))}", BASE_ROWS, {**reads([entry(addr(2), [good])]), **bad})
                self.assertEqual(eo.present(run)[0], BASE_FLAG)

    def test_ac6_a_history_not_read_to_its_start_never_says_only_transfer(self):
        cases = {"start not reached": ({"complete": False, "start": False}, "its history was not read to its start (more than one page of signatures): earlier transfers are not seen"),
                 "read in part": ({"complete": False, "start": True, "seen": 7}, "its history was read in part (1 of 7 transactions, the oldest): later transfers are not seen"),
                 "whole history, more than one": ({"complete": True, "read": 2, "seen": 2}, "its whole token-account history was read (2 transactions)"),
                 "whole history, one": ({"complete": True}, "its whole token-account history was read: the only transfer into it")}
        for name, (kw, want) in cases.items():
            with self.subTest(name):
                events = [event(SYN_DEV, 100_000_000, name)] + ([event(OTHER, 1, name + "2")] if kw.get("read") == 2 else [])
                run = join_run(self.tmp, name.replace(" ", "-").replace(",", ""), BASE_ROWS, reads([entry(addr(2), events, **kw)]))
                line = next(x for x in eo.present(run) if x.startswith(f"    {addr(2)}: "))
                self.assertTrue(line.endswith(want), line)
                if name != "whole history, one":
                    self.assertNotIn("only transfer", line)

    def test_wording_has_no_verdict_words_and_the_not_raised_rule_holds(self):
        lines = []
        for name, lane in (("w1", reads([entry(addr(2), [event(SYN_DEV, 100_000_000, "k")])])), ("w2", reads([entry(addr(2), [event(OTHER, 1, "l")])])), ("w3", None)):
            lines += eo.present(join_run(self.tmp, name, BASE_ROWS, lane))
        lines += eo.present(join_run(self.tmp, "w4", [cheap(1, 0.01), row(addr(2), 0.02, None, transfer_in=True)], reads([entry(addr(2), [event(SYN_DEV, 20_000_000, "m")])])))
        for line in lines:
            self.assertIsNone(REASSURING.search(line), line)
            self.assertIsNone(re.search(r"not raised(?! \(not a safety signal\))", line), line)
        self.assertTrue(any("not raised (not a safety signal)" in x for x in lines))


# ----------------------------------------------------------------------------- Repair R1 (Verifier caveats on cf62b53)


class RepairR1Tests(TempDirTest):
    NOT_READ = f"{DEV_HEAD}: not read (wallet_rpc_reads values unreadable); nothing counted"

    def btc_lane(self, entries):
        run = btc_folder(self.tmp / f"r{len(list(self.tmp.iterdir()))}")
        write_result(run, {**reads(entries, mint=BTC)})
        return run

    def test_c1_a_damaged_value_marks_only_the_dev_sent_line_not_read(self):
        """C1: an unhashable owner, an amount that overflows a float and a non-dict entry used to raise out of measure() and
        blank the whole reading ("not read (saved values unreadable)"). Now the flag line and every other line are those of
        the run without the lane's file; only the dev-sent line reads not read."""
        (self.tmp / "plain").mkdir()
        plain = eo.present(btc_folder(self.tmp / "plain"))
        self.assertEqual(plain[0], BEFORE_FLAG)
        good = {"signature": LOCK_SIG, "direction": "in", "amount_raw": 75_000_000_000_000, "decimals": 6, "block_time": 1792911137}
        cases = {"unhashable owner": [entry(LOCK, [{**good, "senders": [{"owner": [DEV], "amount_raw": 1}]}])],
                 "dict owner": [entry(LOCK, [{**good, "senders": [{"owner": {"a": DEV}, "amount_raw": 1}]}])],
                 "overflowing amount": [entry(LOCK, [{**good, "amount_raw": 10 ** 400, "senders": [{"owner": DEV, "amount_raw": 10 ** 400}]}])],
                 "amount above u64": [entry(LOCK, [{**good, "amount_raw": 2 ** 64, "senders": [{"owner": DEV, "amount_raw": 2 ** 64}]}])],
                 "non-dict entry": ["x", 5],
                 "events not a list": [{**entry(LOCK, []), "events": "x"}]}
        for name, entries in cases.items():
            with self.subTest(name):
                lines = eo.present(self.btc_lane(entries))
                self.assertEqual(lines[0], BEFORE_FLAG)
                diff = [i for i, (a, b) in enumerate(zip(plain, lines)) if a != b]
                self.assertEqual((len(lines), diff), (len(plain), [plain.index(f"{DEV_HEAD}: not read (followup/wallet_rpc_reads.json missing); nothing counted")]))
                self.assertIn(self.NOT_READ, lines)
                self.assertFalse(any("saved values unreadable" in x for x in lines))

    def test_a_a_mixed_sender_transaction_counts_only_the_dev_part(self):
        """Gap (a): the dev and another wallet both send in one transaction; only the dev's part counts, then the smaller of
        that, what was received and the wallet's share."""
        mixed = {**event(SYN_DEV, 100_000_000, "mixed"), "senders": [{"owner": SYN_DEV, "token_account": None, "amount_raw": 60_000_000_000_000},
                                                                   {"owner": OTHER, "token_account": None, "amount_raw": 40_000_000_000_000}]}
        m = eo.measure(join_run(self.tmp, "mixed", BASE_ROWS, reads([entry(addr(2), [mixed])])))
        self.assertEqual((f"{m['dev_pct']:.2f}", f"{m['ratio']:.2f}"), ("6.00", "1.60"))
        self.assertEqual(m["dev_counted"][0]["sent"][0]["sender"], SYN_DEV)
        two_dev = {**mixed, "senders": [{"owner": SYN_DEV, "amount_raw": 30_000_000_000_000}, {"owner": OTHER, "amount_raw": 40_000_000_000_000},
                                        {"owner": SYN_DEV, "amount_raw": 20_000_000_000_000}]}
        m = eo.measure(join_run(self.tmp, "two-dev", BASE_ROWS, reads([entry(addr(2), [two_dev])])))
        self.assertEqual(f"{m['dev_pct']:.2f}", "5.00", "every dev sender's part, never the other sender's")

    def test_b_a_sender_with_no_recorded_owner_is_never_the_dev(self):
        for name, sender in (("owner None", {"owner": None, "token_account": address_of("ta n"), "amount_raw": 100_000_000_000_000}),
                             ("owner missing", {"token_account": address_of("ta m"), "amount_raw": 100_000_000_000_000})):
            with self.subTest(name):
                ev = {**event(SYN_DEV, 100_000_000, name), "senders": [sender]}
                lines = eo.present(join_run(self.tmp, name.replace(" ", "-"), BASE_ROWS, reads([entry(addr(2), [ev])])))
                self.assertEqual(lines[0], BASE_FLAG)
                self.assertTrue(any(x.startswith(f"{DEV_HEAD}: none seen: ") for x in lines))

    def test_c_an_unavailable_wallet_counts_nothing_even_with_events(self):
        lines = eo.present(join_run(self.tmp, "unavailable", BASE_ROWS, reads([entry(addr(2), [event(SYN_DEV, 100_000_000, "u")], status="unavailable")])))
        self.assertEqual(lines[0], BASE_FLAG)
        self.assertIn(f"{DEV_HEAD}: none seen: no transfer from this token's dev wallets ({SYN_DEV}) into the 0 wallets read, 2026-10-27 08:14 UTC = "
                      "2026-10-27 15:14 WIB; nothing counted (what was read, not an all-clear)", lines)

    def test_c3_cannot_see_names_the_dev_transfers_only_when_they_were_read(self):
        claim = "except transfers from this token's dev wallets"
        lane = reads([entry(addr(2), [event(OTHER, 1, "cs")])])
        for name, run in (("lane missing", join_run(self.tmp, "cs-missing", BASE_ROWS)), ("lane unreadable", join_run(self.tmp, "cs-bad", BASE_ROWS, "{oops")),
                          ("values unreadable", join_run(self.tmp, "cs-damaged", BASE_ROWS, reads(["x"]))),
                          ("dev not known", join_run(self.tmp, "cs-nodev", BASE_ROWS, lane, tr=trace(dev=())))):
            with self.subTest(name):
                line = next(x for x in eo.present(run) if x.startswith("  cannot see: "))
                self.assertNotIn(claim, line)
                self.assertIn("tokens received by transfer; sellers' intent", line)
        line = next(x for x in eo.present(join_run(self.tmp, "cs-read", BASE_ROWS, lane)) if x.startswith("  cannot see: "))
        self.assertIn(f"tokens received by transfer, {claim} into the wallets the follow-up lane wallet_rpc_reads read (at most 6; a dev that sends "
                      "from a second wallet is missed); sellers' intent", line)

    def test_c3_the_status_line_names_calls_and_requests_apart(self):
        base = {"status": "ok", "wallets": [], "not_read": [], "request": {"calls": [{"attempts": 1}] * 23, "requests_sent": 23}}
        self.assertTrue(wr.status_line(base).endswith("; 23 calls to the public Solana RPC)"))
        retried = {**base, "request": {"calls": [{"attempts": 2}] * 3 + [{"attempts": 1}] * 20, "requests_sent": 26}}
        self.assertTrue(wr.status_line(retried).endswith("; 23 calls to the public Solana RPC, 26 requests with retries)"))
        self.assertEqual(wr.status_line({**base, "status": "unavailable", "reason": "rate_limited", "request": {"calls": [{"attempts": 2}], "requests_sent": 2}}),
                         "unavailable (rate_limited; 1 call to the public Solana RPC, 2 requests with retries)")


# ----------------------------------------------------------------------------- targets


class TargetTests(TempDirTest):
    def test_five_without_a_cost_basis_then_the_wallets_above_5_percent_at_most_6(self):
        mint = address_of("target mint")
        nb = [wallet_of(f"nb{i}") for i in range(7)]
        costed = [wallet_of(f"c{i}") for i in range(2)]
        rows = [(nb[i], s, None if i % 2 else 0.0, i % 2 == 1) for i, s in enumerate((0.09, 0.085, 0.08, 0.07, 0.065, 0.04, 0.03))]
        rows += [(costed[0], 0.082, 1e-5, False), (costed[1], 0.06, 1e-5, False)]
        run = lane_folder(self.tmp, mint, rows)
        targets, rest, read = wr.collect_targets(run, mint)
        self.assertEqual(read, {"holders.json": "read", "gmgn_holder_pnl.json": "read"})
        self.assertEqual([t["address"] for t in targets], nb[:5] + [costed[0]])
        self.assertEqual([t["address"] for t in rest], [costed[1], nb[5], nb[6]])
        self.assertTrue(all(t["status"] == "not_read" and t["reason"] == "wallet_cap" for t in rest))
        self.assertEqual(targets[-1]["why"], ["above 5% of supply"])
        self.assertEqual(targets[1]["why"], ["no GMGN cost basis", "GMGN transfer_in tag", "above 5% of supply"])
        res = collect(run, Chain(mint).rpc(), mint=mint)
        self.assertEqual(len(res["wallets"]), wr.MAX_WALLETS)
        self.assertEqual(len(res["not_read"]), 3)

    def test_pools_infrastructure_rows_pool_addresses_and_the_mint_are_never_targets(self):
        mint = address_of("pool mint")
        pool, infra, listed, plain = (wallet_of(s) for s in ("pool", "infra", "listed", "plain"))
        rows = [(pool, 0.2, None, False), (infra, 0.2, None, True), (listed, 0.2, None, True), (plain, 0.01, None, False), (mint, 0.1, None, False)]
        run = lane_folder(self.tmp, mint, rows, top=[(infra, 20.0, True), (listed, 20.0, False), (plain, 1.0, False), (mint, 10.0, False)])
        data = json.loads((run / "gmgn_holder_pnl.json").read_text())
        data["rows"][0]["addr_type"] = 2
        (run / "gmgn_holder_pnl.json").write_text(json.dumps(data))
        holders = json.loads((run / "holders.json").read_text())
        holders["pool_addresses"] = [listed]
        (run / "holders.json").write_text(json.dumps(holders))
        targets, _, _ = wr.collect_targets(run, mint)
        self.assertEqual([t["address"] for t in targets], [plain])

    def test_statuses_without_targets_send_no_call(self):
        mint = address_of("empty mint")
        rpc = FakeRpc()
        costed = lane_folder(self.tmp, mint, [(wallet_of("x"), 0.01, 1e-5, False)])
        res = collect(costed, rpc, mint=mint)
        self.assertEqual((res["status"], res["reason"], len(rpc.requests)), ("empty", "no_targets", 0))
        self.assertEqual(wr.status_line(res), "empty (no target wallet among this scan's saved rows; no RPC call sent)")
        (costed / "holders.json").unlink()
        res = collect(costed, rpc, mint=mint)
        self.assertEqual((res["status"], res["reason"], len(rpc.requests)), ("unavailable", "holders_not_read", 0))

    def test_without_gmgn_only_the_wallets_above_5_percent(self):
        mint = address_of("no gmgn")
        big, small = wallet_of("big"), wallet_of("small")
        run = lane_folder(self.tmp, mint, [(big, 0.06, None, True), (small, 0.01, None, True)])
        (run / "gmgn_holder_pnl.json").unlink()
        targets, _, read = wr.collect_targets(run, mint)
        self.assertEqual(([t["address"] for t in targets], targets[0]["share_source"], read["gmgn_holder_pnl.json"]), ([big], "holders.json", "missing"))


# ----------------------------------------------------------------------------- caps, pace, pool (AC5)


class BudgetTests(TempDirTest):
    def chain(self, n: int, **kw):
        mint = address_of(f"budget mint {n}")
        chain = Chain(mint)
        wallets = [wallet_of(f"bw{i}") for i in range(n)]
        for w in wallets:
            chain.wallet(w, SYN_DEV, **kw)
        run = lane_folder(self.tmp, mint, [(w, 0.08 - i * 0.001, None, True) for i, w in enumerate(wallets)])
        return mint, chain, run

    def test_the_worst_case_stays_inside_the_registered_maximum(self):
        entry_ = next(e for e in json.loads(REGISTRY.read_text())["entries"] if e["id"] == "wallet_rpc_reads")
        self.assertEqual((entry_["credits"]["max_calls_per_scan"], entry_["credits"]["max_requests_per_scan"], entry_["credits"]["max_wallets_per_scan"],
                          entry_["credits"]["max_calls_per_wallet"]), (wr.MAX_CALLS, wr.MAX_REQUESTS, wr.MAX_WALLETS, wr.CALLS_PER_WALLET))
        self.assertEqual((wr.MAX_WALLETS, wr.CALLS_PER_WALLET, wr.MAX_CALLS, wr.MAX_REQUESTS), (6, 5, 30, 60))
        mint, chain, run = self.chain(8, transfers=5)
        rpc = chain.rpc()
        res = collect(run, rpc, mint=mint)
        self.assertEqual(len(rpc.requests), wr.MAX_CALLS)
        self.assertEqual((rpc.methods().count("getTokenAccountsByOwner"), rpc.methods().count("getSignaturesForAddress"), rpc.methods().count("getTransaction")), (6, 6, 18))
        self.assertTrue(all(w["calls"] == wr.CALLS_PER_WALLET and w["transactions_read"] == 3 and w["complete"] is False for w in res["wallets"]))
        seen: set = set()

        def every_first_try_429(payload):
            key = json.dumps(payload, sort_keys=True)
            if key not in seen:
                seen.add(key)
                return http_error(429)
            return None

        rpc = chain.rpc(hook=every_first_try_429)
        res = collect(run, rpc, mint=mint)
        self.assertEqual((len(rpc.requests), res["request"]["requests_sent"], len(res["request"]["calls"])), (wr.MAX_REQUESTS, wr.MAX_REQUESTS, wr.MAX_CALLS))
        self.assertTrue(all(w["status"] == "read" for w in res["wallets"]))

    def test_two_token_accounts_still_five_calls_and_a_third_is_not_read(self):
        mint = address_of("two accounts")
        chain = Chain(mint)
        w = wallet_of("two")
        chain.wallet(w, SYN_DEV, transfers=3, accounts=3)
        res = collect(lane_folder(self.tmp, mint, [(w, 0.08, None, True)]), chain.rpc(), mint=mint)
        entry_ = res["wallets"][0]
        self.assertEqual((entry_["calls"], len(entry_["token_accounts"]), entry_["token_accounts_not_read"], entry_["transactions_read"], entry_["complete"]), (5, 2, 1, 2, False))

    def test_the_pace_keeps_four_per_method_per_ten_seconds(self):
        clock = [1000.0]

        def sleep(seconds):
            clock[0] += seconds

        mint, chain, run = self.chain(6, transfers=5)
        rpc = chain.rpc(clock=clock)
        res = wr.collect_wallet_reads(mint, run, workers=1, opener=rpc, now=lambda: NOW, monotonic=lambda: clock[0], sleep=sleep)
        self.assertEqual(len(rpc.requests), 30)
        for t, method in rpc.times:  # in every 10 s window ending at a send, at most 4 sends of that method
            self.assertLessEqual(sum(1 for u, m in rpc.times if m == method and t - wr.METHOD_WINDOW_S < u <= t), wr.METHOD_PACE, (t, method))
        self.assertGreater(res["request"]["pace_waits"], 0)
        self.assertGreaterEqual(clock[0] - 1000.0, 40.0, "18 transactions at 4 per 10 s need more than 40 s")

    def test_the_method_pace_first_come_first_served(self):
        clock, sleeps = [1000.0], []

        def sleep(seconds):
            sleeps.append(seconds)
            clock[0] += seconds

        pace = wr.MethodPace(lambda: clock[0], sleep)
        sent = []
        for _ in range(9):
            pace.take("getTransaction")
            sent.append(clock[0])
            clock[0] += 0.1
        self.assertEqual(sent, sorted(sent))
        self.assertTrue(all(abs(sent[i + 1] - sent[i] - 0.1) < 1e-9 for i in range(3)), "the first 4 go out at once")
        self.assertAlmostEqual(sent[4], 1010.0)
        self.assertAlmostEqual(sent[8], 1020.0)
        waits = pace.waits
        pace.take("getSignaturesForAddress")  # another method has its own window
        self.assertEqual(pace.waits, waits)
        self.assertEqual((wr.METHOD_PACE, wr.METHOD_WINDOW_S, qc.METHOD_PACE), (4, 10.0, 8))

    def test_wallets_are_read_at_the_same_time_at_most_three(self):
        mint, chain, run = self.chain(6, transfers=1)
        rpc = chain.rpc(delay=0.05)
        res = collect(run, rpc, mint=mint)
        self.assertEqual([w["status"] for w in res["wallets"]], ["read"] * 6)
        self.assertEqual(rpc.max_inflight, 3, "a bounded pool of 3: never one by one, never more than 3 at once")
        rpc = chain.rpc(delay=0.02)
        collect(run, rpc, mint=mint, workers=1)
        self.assertEqual(rpc.max_inflight, 1)


# ----------------------------------------------------------------------------- retry, allowlists, no key (AC5)


class RequestTests(TempDirTest):
    PAYLOAD = wr.token_accounts_payload(LOCK, BTC)

    def call(self, hook):
        sleeps = []
        rpc = FakeRpc(hook=hook)
        got = wr.rpc_call(self.PAYLOAD, rpc, monotonic=time.monotonic, sleep=sleeps.append)
        return got, len(rpc.requests), sleeps

    def test_one_retry_after_a_429_honouring_retry_after_up_to_10_s(self):
        for headers, attempts, sleeps in (({}, 2, [1.5]), ({"Retry-After": "10"}, 2, [10.0]), ({"Retry-After": "4"}, 2, [4.0]), ({"Retry-After": "0"}, 2, [0.5]),
                                          ({"Retry-After": "10.5"}, 1, []), ({"Retry-After": "60"}, 1, []), ({"Retry-After": "soon"}, 1, [])):
            with self.subTest(headers):
                got, sent, slept = self.call(lambda p, h=headers: http_error(429, h))
                self.assertEqual((got["reason"], got["attempts"], sent, slept), ("rate_limited", attempts, attempts, sleeps))
        got, sent, slept = self.call(lambda p: FakeResponse(b"", status=429, headers=headers_of({"Retry-After": "10"})))
        self.assertEqual((got["reason"], got["attempts"], slept), ("rate_limited", 2, [10.0]), "a 429 answer object is read the same way")
        self.assertEqual((cs.RETRY_MAX_WAIT_S, wr.RETRY_MAX_WAIT_S), (10.0, 10.0), "create_slot waits up to 10 s too since DS-RPC-RETRY-T1; this lane keeps its own rule")

    def test_a_retry_that_succeeds_and_other_failures_that_are_never_retried(self):
        answers = iter([http_error(429, {"Retry-After": "10"}), None])
        got, sent, slept = self.call(lambda p: next(answers))
        self.assertEqual((got["reason"], got["attempts"], sent, slept), (None, 2, 2, [10.0]))
        for hook, reason in ((lambda p: rpc_error(-32005), "rpc_error"), (lambda p: http_error(503), "service_unavailable"),
                             (lambda p: socket.timeout(), "timeout"), (lambda p: FakeResponse(b"{not json"), "invalid_json"),
                             (lambda p: FakeResponse(b"x" * (wr.MAX_BYTES + 1)), "response_too_large")):
            with self.subTest(reason):
                got, sent, slept = self.call(hook)
                self.assertEqual((got["reason"], got["attempts"], sent, slept), (reason, 1, 1, []))
        got, _, _ = self.call(lambda p: rpc_error(-32005))
        self.assertEqual(got["rpc_error_code"], -32005)
        self.assertNotIn("provider message", json.dumps(got))

    def test_one_shared_429_pause_for_every_worker(self):
        mint = address_of("pause mint")
        chain = Chain(mint)
        wallets = [wallet_of(f"pw{i}") for i in range(3)]
        for w in wallets:
            chain.wallet(w, SYN_DEV)
        hits = []

        def hook(payload):
            if payload["method"] == "getSignaturesForAddress" and not hits:
                hits.append(1)
                return http_error(429, {"Retry-After": "10"})
            return None

        res = collect(lane_folder(self.tmp, mint, [(w, 0.08, None, True) for w in wallets]), chain.rpc(hook=hook), mint=mint)
        self.assertEqual((res["request"]["rate_limit_pauses"], [w["status"] for w in res["wallets"]]), (1, ["read"] * 3))

    def test_requests_one_host_post_three_methods_no_key_and_only_the_content_type(self):
        rpc = FakeRpc()
        collect(btc_folder(self.tmp), rpc)
        self.assertEqual(set(rpc.methods()), set(wr.ALLOWED_METHODS))
        for request, timeout, payload in rpc.requests:
            url = urllib.parse.urlparse(request.full_url)
            self.assertEqual((url.scheme, url.hostname, url.port, url.path, url.query), ("https", "api.mainnet-beta.solana.com", None, "", ""))
            self.assertEqual((request.get_method(), timeout, dict(request.header_items())), ("POST", wr.TIMEOUT_S, {"Content-type": "application/json"}))
            self.assertFalse(re.search(r"(?i)api[-_]?key|authorization|bearer|token=", json.dumps(dict(request.header_items())) + request.full_url))
        token = next(p for _, _, p in rpc.requests if p["method"] == "getTokenAccountsByOwner")
        self.assertEqual(token["params"][1:], [{"mint": BTC}, {"encoding": "base64", "commitment": "confirmed", "dataSlice": {"offset": 0, "length": 72}}])
        page = next(p for _, _, p in rpc.requests if p["method"] == "getSignaturesForAddress")
        self.assertEqual(page["params"][1], {"limit": 1000, "commitment": "confirmed"})
        tx = next(p for _, _, p in rpc.requests if p["method"] == "getTransaction")
        self.assertEqual(tx["params"][1], {"encoding": "jsonParsed", "commitment": "confirmed", "maxSupportedTransactionVersion": 1})

    def test_only_the_allowlisted_host_path_and_methods(self):
        for url in ("http://api.mainnet-beta.solana.com", "https://api.mainnet-beta.solana.com.evil.example", "https://api.mainnet-beta.solana.com:8899",
                    "https://u:p@api.mainnet-beta.solana.com", "https://api.mainnet-beta.solana.com/rpc", "https://mainnet.helius-rpc.com"):
            with self.subTest(url), self.assertRaises(cs.Failure):
                cs.check_url(url)
        for method in ("sendTransaction", "getBlock", "getMultipleAccounts", "getProgramAccounts", "getAccountInfo", "requestAirdrop"):
            with self.subTest(method), self.assertRaises(cs.Failure):
                wr.build_request({"jsonrpc": "2.0", "id": 1, "method": method, "params": []})
        rpc = FakeRpc()
        got = wr.rpc_call({"jsonrpc": "2.0", "id": 1, "method": "getBlock", "params": []}, rpc, monotonic=time.monotonic, sleep=lambda s: None)
        self.assertEqual((got["reason"], got["attempts"], rpc.requests), ("method_not_allowlisted", 1, []))
        with mock.patch.object(wr, "RPC_ENDPOINT", "https://mainnet.helius-rpc.com"), self.assertRaises(cs.Failure):
            wr.build_request(self.PAYLOAD)

    def test_the_default_opener_ignores_env_proxies_and_refuses_redirects(self):
        opener = wr.default_opener()
        self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in opener.handlers))
        self.assertTrue(any(isinstance(h, cs.NoRedirect) for h in opener.handlers))


# ----------------------------------------------------------------------------- per-wallet reads and failures


class WalletReadTests(TempDirTest):
    def one(self, *, hook=None, **kw):
        mint = address_of("one mint")
        chain = Chain(mint)
        w = wallet_of("one wallet")
        sigs = chain.wallet(w, SYN_DEV, **kw)
        res = collect(lane_folder(self.tmp, mint, [(w, 0.08, None, True)]), chain.rpc(hook=hook), mint=mint)
        return res, res["wallets"][0], sigs, chain

    def test_history_not_read_to_its_start(self):
        res, w, _, _ = self.one(transfers=2, full_page=True)
        self.assertEqual((w["signatures_seen"], w["history_start_reached"], w["complete"], w["transactions_read"], w["transactions_not_read"], w["not_read_reasons"]),
                         (1000, False, False, 2, 1, ["not_found"]), "the 3 oldest on the page; the fake has no third transaction")
        self.assertEqual((w["status"], [e["direction"] for e in w["events"]]), ("partial", ["in", "in"]))

    def test_a_failed_transaction_read_leaves_the_wallet_partial(self):
        bad = []

        def hook(payload):
            if payload["method"] == "getTransaction" and not bad:
                bad.append(payload["params"][0])
                return rpc_error(-32005)
            return None

        res, w, sigs, _ = self.one(transfers=3, hook=hook)
        self.assertEqual((w["status"], w["reason"], w["transactions_read"], w["transactions_not_read"], w["not_read_reasons"], w["complete"]),
                         ("partial", "transaction_read_failed", 2, 1, ["rpc_error"], False))
        self.assertEqual(res["status"], "ok")

    def test_failures_are_fixed_codes_per_wallet(self):
        cases = {
            "token accounts 429 with a long wait": (lambda p: http_error(429, {"Retry-After": "60"}) if p["method"] == "getTokenAccountsByOwner" else None,
                                                   ("unavailable", "token_accounts_read_failed", None, "rate_limited")),
            "token accounts rpc error": (lambda p: rpc_error(-32602) if p["method"] == "getTokenAccountsByOwner" else None, ("unavailable", "token_accounts_read_failed", None, "rpc_error")),
            "signatures timeout": (lambda p: socket.timeout() if p["method"] == "getSignaturesForAddress" else None, ("unavailable", "signatures_read_failed", None, "timeout")),
            "signatures not a list": (lambda p: FakeResponse(rpc_body({"x": 1})) if p["method"] == "getSignaturesForAddress" else None,
                                      ("unavailable", "signatures_read_failed", "signatures_shape", None)),
            "every transaction fails": (lambda p: FakeResponse(rpc_body({"slot": 1})) if p["method"] == "getTransaction" else None,
                                        ("unavailable", "transaction_read_failed", "transaction_shape", None)),
        }
        for name, (hook, want) in cases.items():
            with self.subTest(name):
                res, w, _, _ = self.one(hook=hook)
                self.assertEqual((w["status"], w["reason"], w["check"], w["read_reason"]), want)
                self.assertEqual(res["status"], "unavailable")
                self.assertTrue(res["reason"] in wr.KNOWN_CODES, res["reason"])

    def test_token_accounts_of_another_mint_or_owner_are_refused(self):
        mint = address_of("refuse mint")
        w = wallet_of("refuse wallet")
        for name, rows, check in (("another mint", [token_row(address_of("x mint"), w, address_of("ta x"), 5)], "token_account_mint"),
                                  ("another owner", [token_row(mint, wallet_of("someone"), address_of("ta y"), 5)], "token_account_owner"),
                                  ("not a token program", [{**token_row(mint, w, address_of("ta z"), 5), "account": {**token_row(mint, w, address_of("ta z"), 5)["account"], "owner": cs.PUMP_PROGRAM}}], "token_accounts_shape")):
            with self.subTest(name):
                rpc = FakeRpc(owned={(w, mint): {"value": rows}}, pages={}, txs={})
                res = collect(lane_folder(self.tmp, mint, [(w, 0.08, None, True)]), rpc, mint=mint)
                self.assertEqual((res["wallets"][0]["reason"], res["wallets"][0]["check"]), ("layout_mismatch", check))
                self.assertEqual(rpc.methods(), ["getTokenAccountsByOwner"])

    def test_no_token_account_is_read_and_says_so(self):
        mint = address_of("closed mint")
        w = wallet_of("closed")
        rpc = FakeRpc(owned={}, pages={}, txs={})
        run = lane_folder(self.tmp, mint, [(w, 0.08, None, True)])
        res = collect(run, rpc, mint=mint)
        self.assertEqual((res["wallets"][0]["status"], res["wallets"][0]["reason"], rpc.methods()), ("read", "no_token_account", ["getTokenAccountsByOwner"]))
        write_result(run, res)
        self.assertTrue(any("no token account of this mint at read time" in x for x in wr.present(run)))

    def test_a_transfer_inside_a_program_and_an_outgoing_transfer(self):
        mint = address_of("kind mint")
        chain = Chain(mint)
        w = wallet_of("kind wallet")
        ta, other_ta = address_of(f"ta/{w}/0"), address_of("ta other")
        sig_in, sig_out = signature_of("kind in"), signature_of("kind out")
        chain.txs[sig_in] = transfer_tx(sig_in, 1, NOW - 100, mint, w, ta, OTHER, other_ta, 50, inner=True)
        chain.txs[sig_out] = transfer_tx(sig_out, 2, NOW - 50, mint, w, ta, OTHER, other_ta, 20, direction="out")
        chain.owned[(w, mint)] = {"value": [token_row(mint, w, ta, 30)]}
        chain.pages[ta] = [{"signature": sig_out, "slot": 2, "err": None}, {"signature": signature_of("failed"), "slot": 2, "err": {"x": 1}},
                           {"signature": sig_in, "slot": 1, "err": None}]
        res = collect(lane_folder(self.tmp, mint, [(w, 0.08, None, True)]), chain.rpc(), mint=mint)
        e = res["wallets"][0]
        self.assertEqual([(x["direction"], x["kind"], x["amount_raw"]) for x in e["events"]], [("in", "program_transfer", 50), ("out", "transfer", 20)])
        self.assertEqual((e["outgoing_seen"], e["incoming"], e["signatures_seen"], e["successful_signatures"], e["complete"]), (True, 1, 3, 2, True))
        self.assertEqual(e["events"][1]["receivers"], [{"owner": OTHER, "token_account": None, "amount_raw": 20}])


# ----------------------------------------------------------------------------- --present (the lane's block)


class PresentTests(TempDirTest):
    def test_the_btc_block(self):
        run = btc_folder(self.tmp)
        write_result(run, collect(run))
        lines = wr.present(run)
        self.assertTrue(lines[0].startswith("Single wallets read on-chain (follow-up lane wallet_rpc_reads; public Solana RPC, no key, free): read; data age "))
        self.assertIn("23 calls (5 getTokenAccountsByOwner, 5 getSignaturesForAddress, 13 getTransaction)", lines[0])
        self.assertIn(f"  This token's dev (create-slot trace): {DEV}", lines)
        lock = next(x for x in lines if x.startswith(f"  {LOCK} "))
        for needle in ("(7.81% of supply; no GMGN cost basis, GMGN transfer_in tag, above 5% of supply)", "its whole token-account history was read (1 transaction)",
                       f"in: 75,000,000.00 tokens from {DEV} (this token's dev) at 2026-10-25 06:52:17 UTC, a plain transfer, signed by {DEV}, fee payer {DEV}, tx {LOCK_SIG}",
                       "no outgoing transfer seen in the transactions read"):
            self.assertIn(needle, lock, needle)
        other = next(x for x in lines if x.startswith(f"  {TARGETS[1]} "))
        self.assertIn(f"{OWN_CURVE} (a program account)", other)
        self.assertIn("history read in part: the 3 oldest of 39 successful transactions", other)
        self.assertTrue(any(x.startswith("  Not read (caps: 5 without a cost basis, 6 in all): 9 more wallets: ") for x in lines))
        self.assertEqual(lines[-2:], [f"  cannot see: {wr.CANNOT_SEE}", f"  {wr.PRESENTATION_NOTE}"])
        for line in lines:
            self.assertIsNone(REASSURING.search(line), line)
        self.assertNotIn("only transfer", "\n".join(lines))

    def test_a_history_not_read_to_its_start_says_so(self):
        mint = address_of("present mint")
        chain = Chain(mint)
        w = wallet_of("present wallet")
        chain.wallet(w, SYN_DEV, transfers=1, full_page=True)
        run = lane_folder(self.tmp, mint, [(w, 0.08, None, True)])
        write_result(run, collect(run, chain.rpc(), mint=mint))
        line = next(x for x in wr.present(run) if x.startswith(f"  {w} "))
        self.assertIn("history not read to its start (the one page read holds 1000 signatures, the newest; older ones are not seen)", line)
        self.assertIn("This token's dev not known (create_slot_trace.json missing)", "\n".join(wr.present(run)))

    def test_unknown_shares_and_damaged_files_never_crash_and_never_print_zero(self):
        run = btc_folder(self.tmp)
        res = collect(run)
        res["wallets"][0]["share_pct"] = "x"
        res["wallets"][1].update(status="unavailable", reason="Some Provider Text", check=None, read_reason=None)
        res["wallets"][2]["events"] = ["x", {"direction": "in", "amount_raw": "1", "senders": "x"}]
        write_result(run, res)
        lines = wr.present(run)
        self.assertIn(f"  {LOCK} (share of supply not read; no GMGN cost basis, GMGN transfer_in tag, above 5% of supply)", "\n".join(lines))
        self.assertIn("unavailable (unrecognized code); nothing read", "\n".join(lines))
        self.assertIn("in: unknown tokens from no sender whose balance fell", "\n".join(lines))
        for damage in ("{oops", json.dumps({"schema": "x"}), json.dumps({**res, "wallets": "x"}), json.dumps({**res, "request": "x"})):
            with self.subTest(damage[:20]):
                (run / wr.OUT_DIR / wr.OUT_FILE).write_text(damage)
                lines = wr.present(run)
                self.assertTrue(lines and lines[0].startswith("Single wallets read on-chain"))
        (run / wr.OUT_DIR / wr.OUT_FILE).unlink()
        self.assertEqual(wr.present(run), ["Single wallets read on-chain (follow-up lane wallet_rpc_reads; public Solana RPC, no key, free): not read "
                                           "(followup/wallet_rpc_reads.json missing)"])

    def test_present_opens_no_connection(self):
        run = btc_folder(self.tmp)
        write_result(run, collect(run))

        def refuse(*_a, **_k):
            raise AssertionError("network access in --present")

        out = io.StringIO()
        with mock.patch.object(wr, "default_opener", side_effect=refuse), mock.patch.object(cs, "default_opener", side_effect=refuse), \
                mock.patch.object(socket, "create_connection", refuse), mock.patch.object(socket.socket, "connect", refuse), contextlib.redirect_stdout(out):
            self.assertEqual(wr.main(["--present", str(run)]), 0)
            self.assertEqual(eo.main(["--present", str(run)]), 0)
        self.assertIn(AFTER_FLAG, out.getvalue().splitlines())


class CliTests(TempDirTest):
    def run_main(self, argv, rpc):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(wr, "default_opener", return_value=rpc), mock.patch.object(wr.time, "sleep"), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = wr.main(argv)
        return code, out.getvalue(), err.getvalue()

    def test_bad_input_exits_2_without_a_call(self):
        rpc = FakeRpc()
        for argv in (["not-a-mint", "--out", str(self.tmp)], [BTC], [BTC, "--out", str(self.tmp), "--workers", "4"], [BTC, "--out", str(self.tmp), "--workers", "0"],
                     ["--present", str(self.tmp / "missing")], [BTC, "--present", str(self.tmp)]):
            with self.subTest(argv):
                code, _, err = self.run_main(argv, rpc)
                self.assertEqual(code, 2)
                self.assertTrue(err.startswith("error:"))
        self.assertEqual(rpc.requests, [])

    def test_the_collector_writes_into_followup_and_prints_one_line(self):
        run = btc_folder(self.tmp)
        code, out, _ = self.run_main([BTC, "--out", str(run)], FakeRpc())
        self.assertEqual((code, out.strip()), (0, "ok (5 wallets read: 5 read, 0 unavailable, 5 with an incoming transfer seen, 9 not read (caps); "
                                                   "23 calls to the public Solana RPC)"))
        saved = json.loads((run / "followup" / "wallet_rpc_reads.json").read_text())
        self.assertEqual((saved["schema"], saved["lane"], saved["presentation_only"], saved["request"]["keys"]), ("holder-scan-wallet-rpc-reads/1", "wallet_rpc_reads", True, "none"))


# ----------------------------------------------------------------------------- presentation only (AC7)


class PresentationOnlyRuleTests(unittest.TestCase):
    """assess never reads followup/wallet_rpc_reads.json: the same assessment.json and report.md with or without it, on the
    frozen clock of test_assess.run_assess; the map alarm still raises the same FLAG."""

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
        btc = cls.tmp / "btc"
        btc.mkdir()
        cls.saved = collect(btc_folder(btc))
        cls.saved["mint"] = cls.mint

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def assess(self, extra, name):
        out = self.tmp / name
        code, _, err = run_assess(self.mint, self.run_dir, extra, out=out)
        return code, err, (json.loads((out / "assessment.json").read_text()) if code == 0 else None), ((out / "report.md").read_text() if code == 0 else None)

    def test_the_followup_file_changes_nothing(self):
        for extra, tag in ((["--bubblemaps-json", str(self.space_map)], "map"), (["--bubblemaps-json", str(self.alarm_map)], "alarm"), ([], "no-map")):
            with self.subTest(tag):
                code, err, before, md_before = self.assess(extra, f"{tag}-without")
                self.assertEqual(code, 0, err)
                write_result(self.run_dir, self.saved)
                try:
                    code, err, after, md_after = self.assess(extra, f"{tag}-with")
                finally:
                    shutil.rmtree(self.run_dir / wr.OUT_DIR)
                self.assertEqual(code, 0, err)
                self.assertEqual((json.dumps(after, sort_keys=True), md_after), (json.dumps(before, sort_keys=True), md_before))
        _, _, alarm, _ = self.assess(["--bubblemaps-json", str(self.alarm_map)], "alarm-check")
        self.assertTrue(alarm["flag"]["label"].startswith(hf.FLAG_DANGER), "the map alarm stands; a dev-sent bag never softens it")

    def test_refused_as_providers_json_and_unknown_to_both_engines(self):
        write_result(self.run_dir, self.saved)
        try:
            code, err, _, _ = self.assess(["--providers-json", str(self.run_dir / wr.OUT_DIR / wr.OUT_FILE)], "refused")
        finally:
            shutil.rmtree(self.run_dir / wr.OUT_DIR)
        self.assertEqual(code, 2)
        self.assertIn("--providers-json must hold a JSON list of findings", err)
        for path in [SCRIPTS / "helius_forensics.py", SCRIPTS / "holder_analysis.py", *sorted((SCRIPTS / "ha").glob("*.py"))]:
            text = path.read_text(encoding="utf-8")
            for needle in ("wallet_rpc_reads", "dev-sent", "DEV_DECISION"):
                self.assertNotIn(needle, text, path.name)


# ----------------------------------------------------------------------------- the registry and SKILL.md


class RegistryAndSkillTests(unittest.TestCase):
    COMMAND = "mkdir -p <RUN>/followup && python3 -I skills/dlmm-scan/scripts/wallet_rpc_reads.py <MINT> --out <RUN> 2> <RUN>/followup/wallet_rpc_reads.err"
    PRESENT = "python3 -I skills/dlmm-scan/scripts/wallet_rpc_reads.py --present <RUN>"
    OVERHANG = "python3 -I skills/dlmm-scan/scripts/exit_overhang.py --present <RUN>"
    HEADING = ("## Follow-up collector `wallet_rpc_reads`: where the biggest wallets without a buy price got their tokens "
               "(public Solana RPC, presentation only)")

    @classmethod
    def setUpClass(cls):
        cls.reg = json.loads(REGISTRY.read_text(encoding="utf-8"))
        cls.by = {e["id"]: e for e in cls.reg["entries"]}
        cls.text = (SCRIPTS.parent / "SKILL.md").read_text(encoding="utf-8")

    def test_registered_as_a_free_keyless_default_on_follow_up_bounded_pool_script(self):
        e = self.by["wallet_rpc_reads"]
        self.assertEqual((e["role"], e["wave"], e["script_status"], e["lane"], e["tier"], e["cost"], e["default_on"], e["keys"], e["internal"], e["depends_on"], e["exception"]),
                         ("collector", "follow_up", "script", "parallel", "fast", "free", True, [], "bounded_pool", [], None))
        self.assertEqual((e["command"], e["entry_script"], e["covers"], e["hosts"], e["output"]),
                         (self.COMMAND, "scripts/wallet_rpc_reads.py", ["scripts/wallet_rpc_reads.py"], ["api.mainnet-beta.solana.com"],
                          ["followup/wallet_rpc_reads.json", "followup/wallet_rpc_reads.err"]))
        self.assertNotIn("owner_default_on_approval", e, "free and keyless: no owner record needed")
        self.assertEqual((e["credits"]["workers"], e["credits"]["max_calls_per_wallet"]), (wr.MAX_WORKERS, wr.CALLS_PER_WALLET))
        self.assertIn("at most 4 requests of one method per 10 s", e["credits"]["method_pace"])
        self.assertIn("Retry-After up to 10 s", e["credits"]["plan_note"])
        for needle in ("gmgn_holder_pnl.json", "holders.json", "transfer_in", "5%", "at most 6"):
            self.assertIn(needle, e["targets"], needle)
        self.assertEqual([x["id"] for x in self.reg["entries"] if "scripts/create_slot.py" in x.get("covers", [])], ["create_slot_trace"])
        self.assertEqual([x["id"] for x in self.reg["entries"] if "scripts/quote_curves.py" in x.get("covers", [])], ["quote_curves"])
        synth = self.by["synthesis"]
        self.assertTrue(synth["present_commands"][self.PRESENT].startswith("after the follow-up wave"))
        for needle in ("never passed to assess, not even as --providers-json", "never counted toward NO_ALARM", "no verdict, flag or threshold changes"):
            self.assertIn(needle, synth["present_commands"][self.PRESENT], needle)
        for needle in ("followup/wallet_rpc_reads.json", "the dev sent to <m> wallets at no cost", "Count at zero cost (Recommended)"):
            self.assertIn(needle, synth["present_commands"][self.OVERHANG], needle)
        self.assertFalse([k for k, v in synth["input_flags"].items() if "wallet_rpc_reads" in k + v])
        self.assertNotIn("wallet_rpc_reads", synth["command"])

    def test_skill_file_documents_the_lane_the_rule_and_the_synthesis_steps(self):
        self.assertIn(self.HEADING, self.text)
        body = self.text.split(self.HEADING, 1)[1].split("\n## ", 1)[0]
        for needle in (self.COMMAND, self.PRESENT, "Free and keyless", "at most 6", "at most 5 calls", "at most 30 calls, at most 60 requests",
                       "at most 4 requests of one method per 10 s", "Retry-After up to 10 s", "maxSupportedTransactionVersion 1", "What it cannot see",
                       "a dev that sends from a second wallet", "never passed to `assess`", "Nothing seen here is an all-clear", "Live check 2026-10-27",
                       "tests/forensics/test_wallet_rpc_reads.py", "never 0", "not read to its start"):
            self.assertIn(needle, body, needle)
        self.assertIsNone(REASSURING.search(body))
        self.assertIn("| `wallet_rpc_reads` (follow-up wave) | `scripts/wallet_rpc_reads.py`", self.text)
        self.assertNotIn("follow-up agent reads by hand (no script yet): any single wallet above 5%", self.text)
        follow = self.text.split("## Follow-up wave (fast tier)", 1)[1].split("\n## ", 1)[0]
        self.assertIn("`wallet_rpc_reads` runs its own", follow)
        self.assertIn("| `wallet_rpc_reads` | the token mint, on every scan", follow)
        rule = self.text.split("**EXIT OVERHANG, the third flag line", 1)[1].split("\n\n", 1)[0]
        for needle in ("DS-DEV-BAGS-T1", "\"Count at zero cost (Recommended)\"", "the smaller of", "followup/wallet_rpc_reads.json", "`create_tx.dev_wallets`",
                       "nothing new is counted"):
            self.assertIn(needle, rule, needle)
        synth = self.text.split("## Synthesis (top tier): `SUMMARY.md`", 1)[1].split("\n## ", 1)[0]
        step5 = synth.split("\n5. ", 1)[1].split("\n6. ", 1)[0]
        self.assertIn("Never call an address a lock from its name; only a lock `pda_identity_reads` confirms (Streamflow) is a lock", step5)
        self.assertIn(self.PRESENT, step5)
        tests = self.text.split("## Maintenance and tests", 1)[1]
        self.assertIn("`tests/forensics/test_wallet_rpc_reads.py` covers the `wallet_rpc_reads` lane offline (DS-DEV-BAGS-T1)", tests)


# ----------------------------------------------------------------------------- self-contained


class SelfContainedTests(unittest.TestCase):
    def test_every_code_the_script_writes_is_in_its_printable_list(self):
        text = (SCRIPTS / "wallet_rpc_reads.py").read_text()
        written = set(re.findall(r'fail\("(\w+)"', text)) | set(re.findall(r'Mismatch\("(\w+)"', text)) | set(re.findall(r'reason="(\w+)"', text))
        written |= set(re.findall(r'Failure\("(\w+)"', text)) | {"holders_not_read", "no_targets", "wallet_cap"}
        self.assertGreater(len(written), 10)
        self.assertEqual(sorted(written - wr.KNOWN_CODES), [])

    def test_standard_library_create_slot_and_quote_curves_only(self):
        text = (SCRIPTS / "wallet_rpc_reads.py").read_text()
        modules = set()
        for node in ast.walk(ast.parse(text)):
            if isinstance(node, ast.Import):
                modules |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        self.assertEqual(sorted(modules - set(sys.stdlib_module_names) - {"__future__"}), ["create_slot", "quote_curves"])
        self.assertEqual(re.findall(r"\b[A-Z][A-Z0-9_]*_(?:KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|RPC_URL)\b", text), [])
        for word in ("/Users/", ".env", "os.environ", "getenv", "helius-rpc", "helius.xyz"):
            self.assertNotIn(word, text)

    def test_the_helpers_are_imported_never_copied(self):
        text = (SCRIPTS / "wallet_rpc_reads.py").read_text()
        for used in ("cs.send_once(", "cs.check_url(", "cs.token_deltas(", "cs.transaction_payload(", "cs.signatures_payload(", "cs._keys(", "qc.token_accounts(",
                     "qc.SharedPause(", "qc.PausedOpener(", "qc.this_token_dev("):
            self.assertIn(used, text)
        for copied in ("def send_once", "def token_deltas", "def _bounded_call", "def check_url", "def transaction_payload", "def signatures_payload",
                       "class SharedPause", "class PausedOpener", "def this_token_dev", "build_opener", "ProxyHandler", "def _keys"):
            self.assertNotIn(copied, text)
        strings = [n.value for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        self.assertEqual({s for s in strings if re.fullmatch(r"(get|send|request|simulate)[A-Z]\w+", s)}, set(wr.ALLOWED_METHODS))

    def test_exit_overhang_still_imports_nothing_from_the_skill(self):
        tree = ast.parse((SCRIPTS / "exit_overhang.py").read_text(encoding="utf-8"))
        imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        imported |= {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
        self.assertNotIn("wallet_rpc_reads", imported)
        self.assertEqual((eo.READS_SCHEMA, eo.READS_FILE), (wr.SCHEMA, f"{wr.OUT_DIR}/{wr.OUT_FILE}"))


if __name__ == "__main__":
    unittest.main()
