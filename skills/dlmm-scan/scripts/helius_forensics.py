#!/usr/bin/env python3
"""Helius holder forensics for Solana tokens: full holder list + funder-batch ("wallet factory") detection.

Why this exists: GMGN, Bubblemaps and SolScanner each see a capped top-N window and define
"bundle" / "fresh" differently. On 2026-10-13 a 230-wallet, 64.6%-of-supply scripted operation on VEIL
was invisible to GMGN, Bubblemaps and InsightX but obvious once Helius `funded-by` ran on the top 250
holders. This tool automates that check.

Read-only. Secrets: only HELIUS_API_KEY is read (environment first, then the repository .env). It is never
printed, logged, written to output, or placed in an exception message. EVERY exception is reduced to
its type name before it reaches the terminal, because request URLs embed the key.

Subcommands:
  holders MINT   full holder list via Helius DAS getTokenAccounts, distribution summary
  funders MINT   holders + Helius funded-by on the top-N holders, batch/cadence detection, upstream trace
  report  MINT   same as funders, plus a short markdown verdict (default workflow)
  assess  MINT --from RUN_DIR
                 OFFLINE: rebuild assessment.json and report.md from a saved run folder (holders.json, funders.json)
                 plus saved input files. No network call, no key, 0 credits. The dlmm-scan synthesis runs it after
                 every collector has finished, so no collector has to wait for another one.

Exit codes: 0 ok, 2 usage/config error, 3 provider/internal error, 4 credit budget stopped the run, 130 interrupted
(Ctrl-C). Partial results are written when a run stops early. Requires Python >= 3.10.
"""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import hashlib
import itertools
import json
import math
import os
import queue
import re
import statistics
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterable

if sys.version_info < (3, 10):  # pragma: no cover
    raise SystemExit("error: Python >= 3.10 required")

SKILL_DIR = Path(__file__).resolve().parents[1]
_SCRIPTS_DIR = Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:  # python -I does not add the script directory; solscanner_scan.py lives beside this file
    sys.path.insert(0, str(_SCRIPTS_DIR))

import provider_words as pw  # noqa: E402  (HS-LABELS-T1: verdict words in provider text; standard library only, no network)
from provider_words import PROVIDER_LOOKALIKE_SIGNS, PROVIDER_LOOKALIKES  # noqa: E402  (the matcher's folding tables, defined there)
from ha.solana import b58decode, is_on_curve  # noqa: E402  (DS-AMM-VAULTS-T1: the shared vault authorities below; standard library only)

REPORTS_DIR = SKILL_DIR / "reports"

KEY_NAME = "HELIUS_API_KEY"
ALLOWED_KEYS = frozenset({KEY_NAME})
KEY_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
HELIUS_RPC_HOST = "mainnet.helius-rpc.com"
HELIUS_API_HOST = "api.helius.xyz"
DEXSCREENER_HOST = "api.dexscreener.com"
ALLOWED_HOSTS = frozenset({HELIUS_RPC_HOST, HELIUS_API_HOST, DEXSCREENER_HOST})

# Documented Helius credit costs (Helius billing docs, checked 2026-10-14). Plan-dependent; guard only.
COST_DAS_PAGE = 10
COST_FUNDED_BY = 100
COST_RPC_CALL = 1
MAX_DAS_PAGES = 60
UPSTREAM_TRACE_LIMIT = 15
DEFAULT_FUNDERS_TOP = 100  # owner 2026-10-28 ("Top 100"): funded-by lookups (100 credits each); the holder list stays --top 250
MAX_CONSECUTIVE_FAILURES = 5
# Parallel funded-by lookups (`--workers`). Every worker thread shares ONE pace: at most REQUEST_RATE_CAP_PER_S request
# starts in any 1 s window (retries included) and one shared pause after any HTTP 429. Reason for 6/s: the
# HELIUS_API_KEY is the same key, and the same credit pool, as the stop-loss bots, and on the Developer plan the Wallet
# API (funded-by) shares the 10 requests/s DAS & Enhanced limit (provider-docs cache current/helius.md, "Rate Limits"), so
# 6/s leaves 4/s for everyone else on the key. Each worker also keeps the old 0.25 s gap after its own last request, so
# one worker is never faster than the old one-at-a-time loop.
REQUEST_RATE_CAP_PER_S = 6
# The gate spaces each 7th start at least 1 s + this margin after the 1st: the request leaves a moment after the gate lets
# it pass (offline benchmark: up to about 2 ms of thread wake-up jitter), and without a margin that jitter put a 7th
# request inside one second by a few microseconds. Costs about 2 s on a 250-holder run.
RATE_WINDOW_MARGIN_S = 0.05
DEFAULT_WORKERS = 6
MAX_WORKERS = 10

MINT_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")
LABEL_RE = re.compile(r"[^\w .\-]")

# Detection thresholds. UNVALIDATED heuristics from one observed case (VEIL, 2026-10-13); they flag,
# they do not prove common control, and they must be re-calibrated before any automated gate uses them.
MIN_BATCH_WALLETS = 3          # a funder is a "batch" at 3+ examined holders
CLASSIFY_MIN_WALLETS = 5       # only batches of 5+ wallets count toward the verdict
TIGHT_WINDOW_S = 300
STRONG_SHARE_PCT = 20.0
STRONG_MIN_BATCH_FUNDERS = 4
WEAK_SHARE_PCT = 8.0
WEAK_MIN_BATCH_FUNDERS = 2     # one funder feeding a few big wallets is not a factory

# ---- PROVISIONAL verdict-gating thresholds (the one place for them) ----------------------------------
# Every value in this block rests on TWO positive cases (VEIL 2026-10-13, CAPE 2026-10-14) and no validated
# negative controls. They exist so that a report cannot read as an all-clear on thin evidence; they are
# not calibrated and must be revisited once negatives from live tokens exist.
VERDICT_HIGH = "HIGH"
VERDICT_UNRESOLVED = "UNRESOLVED"
VERDICT_LIMITED = "LIMITED"        # aka "unverified": the checks that ran found nothing, but too little ran
VERDICT_NO_ALARM = "NO_ALARM"      # never the words "clean" or "low"; it is not proof of safety
COVERAGE_MIN_SUPPLY_PCT = 60.0     # share of NON-infrastructure supply the funding detectors must have seen
MIN_CLUSTER_SOURCES = 2            # independent cluster-capable sources needed for NO_ALARM (own cohort detector counts as one)
YOUNG_TOKEN_MAX_AGE_H = 24.0       # below this age (or unknown age) a provider's all-clear must be fresh to count
CLUSTER_ALARM_PCT = 15.0           # a provider reporting a cluster this large (% of supply) alarms (the CAPE handoff's example bar)
BUNDLE_ALARM_PCT = 30.0            # a provider reporting bundles this large (% of supply) alarms (same source)
STALE_ALL_CLEAR_MIN = 15.0         # on a young token a provider all-clear older than this does not count toward NO_ALARM (owner's 15-minute map rule)
RESERVED_PROVIDERS = ("bubblemaps_map", "solscanner")  # only the --bubblemaps-json path may supply it, so the required step cannot be self-declared
# Presentation-only providers (HS-PROV-T1): the synthesis shows their numbers next to the FLAGs (late-source rule); they
# never enter the engine, because through --providers-json a low number would count toward NO_ALARM. Refused there,
# matched with case, spaces and punctuation ignored. Input acceptance only: no threshold, verdict or flag rule changes.
PRESENTATION_ONLY_PROVIDERS = {"solanatracker": "Solana Tracker", "madeonsol": "MadeOnSol", "fomo": "Fomo API"}
# HS-PROV-T2 (criterion 7): spellings that slip past a plain letters-and-digits match. The name is folded first (Unicode
# compatibility folding as in NFKC, done through NFKD so accents split off; accents and invisible format characters
# dropped; common Cyrillic / Greek / small-capital / Latin look-alikes mapped to Latin; a second pass also reads digits
# and signs used as letters, a capital I used as l and "rn" used as m; a third collapses repeated letters, so "Fommo" or
# "Solanna Tracker" still match), then searched for the tokens above and these unambiguous aliases, anywhere in the name.
# The bare abbreviations ST and MOS are refused as a separate word of the name (or the whole name), never inside a longer
# word, where they would clash with real names (Step, Stats, Mosaic, Cosmos, Moss). Input acceptance only: no threshold,
# verdict or flag rule changes. The look-alike tables (PROVIDER_LOOKALIKES, PROVIDER_LOOKALIKE_SIGNS) live in
# provider_words.py since HS-LABELS-T1, unchanged, so the verdict-word rule for provider text folds exactly as this matcher.
PRESENTATION_ONLY_ALIASES = {"soltrack": "Solana Tracker", "solanatrack": "Solana Tracker"}
PRESENTATION_ONLY_ABBREVIATIONS = {"st": "Solana Tracker", "mos": "MadeOnSol"}
PROVIDER_NAME_WORD_SPLIT = re.compile(r"[\s\-_/|()\[\]{},;:+&]+")  # word separators for the ST / MOS check (a dot stays inside: "S.T.")
REQUIRED_PROVIDERS = ("bubblemaps_map",)  # report cannot exceed LIMITED unless these returned readable data
PROVIDER_STATUSES = ("ok", "empty", "unavailable", "skipped")
# Report layout caps (presentation only, no effect on any verdict): the report shows evidence and the owner decides.
SUMMARY_MAX_LINES = 12             # executive summary length ceiling, in lines
LIST_CAP = 8                       # clusters / groups / batches listed per source before "and N more"
FLAG_DANGER = "DANGER FLAG"        # HIGH: clear large clusters, a strong cohort, or an uncontradicted alarm
FLAG_CAUTION = "CAUTION"           # UNRESOLVED: sources disagree or something is unproven
FLAG_NONE = "NO FLAG RAISED (not a safety signal)"  # LIMITED and NO_ALARM: never reassurance
AGGREGATE_CLUSTER_ALARM_PCT = 30.0  # SUM of a provider's cluster shares alarms too (CAPE: about 43% across clusters, largest only 25%)
# Funding-time cohort detector (provider-agnostic). Window and sizes come from ONE case (CAPE farm: 50 wallets,
# 5.7 h, 17.4% of supply; VEIL: 230 wallets inside ~25 min). No validated negatives exist yet, so the false-positive
# rate on organic launches (new users funded by exchanges just before buying) is UNKNOWN.
COHORT_WINDOW_S = 6 * 3600         # first-funding timestamps within this span form one candidate cohort
COHORT_MIN_WALLETS = 20            # a cohort needs this many wallets ...
COHORT_MIN_SUPPLY_PCT = 5.0        # ... or this share of total supply
COHORT_MIN_WALLETS_FLOOR = 5       # the supply route still needs this many wallets (two big wallets are not a cohort)
COHORT_AMOUNT_REL_BAND = 0.5       # first amounts within +-50% of the cohort median count as "similar"
COHORT_AMOUNT_SIMILAR_FRACTION = 0.8  # share of members inside the band for the cohort to be called similar-amount (info only)
# Severity of a flagged cohort. The supply route and single-funder groups are too easy to hit on young tokens whose
# holders were all funded in the last days (a Monte Carlo flagged about 99% of random young tokens), so they are
# UNRESOLVED (non-safe, named in the report) and only a larger multi-funder cohort is HIGH.
COHORT_HIGH_MIN_WALLETS = COHORT_MIN_WALLETS  # HIGH needs at least this many wallets (the supply route alone is not enough)
COHORT_HIGH_MIN_SIGNS = 2          # ... and at least this many of the three signs (dormancy, synchronized acquisition, similar amounts)
COHORT_HIGH_MIN_FUNDERS = 2        # and at least this many distinct funders (funders_toward_high); a single funder is UNRESOLVED
COHORT_DORMANT_GAP_S = 7 * 86400   # a dormant gap at least this long is one of the three HIGH discriminators (others: narrow acquisition window, similar amounts)
ACQUISITION_WINDOW_S = 600         # cohort members first acquiring the token inside this span is flagged (CAPE: ~9 min)
ACQUISITION_MIN_WALLETS = 10       # timestamped members needed before the acquisition check may flag
ACQUISITION_MIN_FRACTION = 0.8     # the narrowest window must hold this share of the timestamped members


class ForensicsError(Exception):
    """Base error; message must never contain secrets."""

    exit_code = 3


class ConfigError(ForensicsError):
    exit_code = 2


class BudgetError(ForensicsError):
    exit_code = 4


# ----------------------------------------------------------------------------- secrets / config


def find_env_file(explicit: str | None = None) -> Path:
    """Locate the repository .env without reading it. Only known locations, never an arbitrary ancestor."""
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    if os.environ.get("HOLDER_FORENSICS_ENV"):
        candidates.append(Path(os.environ["HOLDER_FORENSICS_ENV"]))
    marker = f"{os.sep}.claude{os.sep}worktrees{os.sep}"
    skill_str = str(SKILL_DIR)
    if marker in skill_str:  # running from a git worktree: use the base checkout's .env
        candidates.append(Path(skill_str.split(marker)[0]) / ".env")
    candidates.append(SKILL_DIR.parents[1] / ".env")  # <repo>/skills/dlmm-scan -> <repo>/.env
    seen: set[Path] = set()
    for path in candidates:
        if path not in seen:
            seen.add(path)
            if path.is_file():
                return path
    raise ConfigError("no .env found; set HELIUS_API_KEY in the environment or HOLDER_FORENSICS_ENV to a .env path")


def _clean_env_value(value: str) -> str:
    value = value.strip()
    if value[:1] in ("'", '"') and value[-1:] == value[:1] and len(value) >= 2:
        return value[1:-1].strip()
    return re.split(r"\s+#", value, maxsplit=1)[0].strip()  # drop an unquoted inline comment


def load_key(env_file: Path | None = None, name: str = KEY_NAME) -> str:
    """Environment variable first, then exactly one allowlisted variable from the .env. Never logs values."""
    if name not in ALLOWED_KEYS:
        raise ConfigError("unsupported key name requested")
    key = os.environ.get(name, "").strip()
    if not key and env_file is not None:
        for raw in env_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if line.startswith("export "):
                line = line[7:].lstrip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            var, _, value = line.partition("=")
            if var.strip() == name:
                key = _clean_env_value(value)
                break
    if not key:
        raise ConfigError(f"{name} is not set (environment or .env)")
    if not KEY_RE.match(key):
        raise ConfigError(f"{name} has an unexpected format")  # never echo the value
    return key


# ----------------------------------------------------------------------------- HTTP / Helius client


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any):  # noqa: ANN401
        raise ForensicsError("redirect rejected")


def _check_host(url: str) -> None:
    host = urllib.parse.urlparse(url).hostname or ""
    if host not in ALLOWED_HOSTS:
        raise ForensicsError(f"host not allowlisted: {host}")


class Budget:
    """Credit guard. Counts documented costs before dispatch so a typo cannot burn a plan. Thread-safe: the check and
    the charge happen under one lock, so parallel workers can never push `spent` past `max_credits`."""

    def __init__(self, max_credits: int) -> None:
        self.max_credits = max_credits
        self.spent = 0
        self._lock = threading.Lock()

    def remaining(self) -> int:
        return self.max_credits - self.spent

    def charge(self, credits: int) -> None:
        with self._lock:
            if self.spent + credits > self.max_credits:
                raise BudgetError(f"credit budget {self.max_credits} would be exceeded (spent {self.spent})")
            self.spent += credits


class RateGate:
    """One pace shared by every thread that uses a Helius client: at most `per_s` request starts in any 1 s window
    (each start is at least 1 s + RATE_WINDOW_MARGIN_S after the start `per_s` places earlier), and no start at all
    while a 429 pause runs. A thread passes only when, at that moment and under the lock, both
    hold; the pass time is recorded as the start. After a sleep the thread checks again, so a pause that began while
    it slept still holds it back. `floor` keeps a fake sleep (tests) from spinning against a real clock."""

    def __init__(self, per_s: int, clock: Callable[[], float], sleep: Callable[[float], None]) -> None:
        self._per_s = per_s
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._starts: collections.deque[float] = collections.deque(maxlen=per_s)  # last per_s pass times, non-decreasing
        self._pause_until = float("-inf")

    def pause(self, seconds: float) -> None:
        """Shared 429 backoff: no thread starts a request until `seconds` from now (extends, never shortens, a pause)."""
        with self._lock:
            self._pause_until = max(self._pause_until, self._clock() + seconds)

    def wait_turn(self) -> float:
        """Block until this thread may start one request; returns the recorded start time."""
        floor = float("-inf")
        while True:
            with self._lock:
                now = max(self._clock(), floor, self._starts[-1] if self._starts else floor)
                ready = self._pause_until
                if len(self._starts) == self._per_s:
                    ready = max(ready, self._starts[0] + 1.0 + RATE_WINDOW_MARGIN_S)
                if ready <= now:
                    self._starts.append(now)
                    return now
            self._sleep(ready - now)
            floor = ready


class Helius:
    def __init__(
        self,
        key: str,
        budget: Budget,
        *,
        opener: urllib.request.OpenerDirector | None = None,
        sleep: Callable[[float], None] = time.sleep,
        min_interval: float = 0.25,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._key = key
        self.budget = budget
        self._opener = opener or urllib.request.build_opener(_NoRedirect())
        self._sleep = sleep
        self._min_interval = min_interval
        self._clock = clock
        self._local = threading.local()  # per-thread time of that thread's last answered request (the 0.25 s gap)
        self.gate = RateGate(REQUEST_RATE_CAP_PER_S, clock, sleep)

    def _send(self, req: urllib.request.Request) -> tuple[int, Any]:
        """One request with bounded retries. Any unexpected exception becomes a ForensicsError carrying
        only the exception type name: tracebacks and messages can embed the request URL (and the key).
        Every attempt, retries included, waits for the shared RateGate; a 429 pauses ALL threads, and the same
        request is retried by this thread once the pause has passed (credits were charged once, by the caller)."""
        try:
            _check_host(req.full_url)
            wait = self._min_interval - (self._clock() - getattr(self._local, "last", float("-inf")))
            if wait > 0:
                self._sleep(wait)
            for attempt in range(5):
                self.gate.wait_turn()
                try:
                    with self._opener.open(req, timeout=60) as resp:
                        self._local.last = self._clock()
                        return resp.status, json.load(resp)
                except urllib.error.HTTPError as err:
                    if err.code == 429 and attempt < 4:
                        self.gate.pause(4 * (attempt + 1))
                        continue
                    self._local.last = self._clock()
                    try:
                        body: Any = json.load(err)
                    except Exception:  # noqa: BLE001 - error body is advisory only
                        body = None
                    return err.code, body
                except (urllib.error.URLError, TimeoutError, ConnectionError) as err:
                    if attempt < 4:
                        self._sleep(2 * (attempt + 1))
                        continue
                    raise ForensicsError(f"network error: {type(err).__name__}") from None
            raise ForensicsError("retries exhausted")
        except ForensicsError:
            raise
        except Exception as err:  # noqa: BLE001 - includes InvalidURL, SSLError, IncompleteRead, JSONDecodeError
            raise ForensicsError(f"request failed: {type(err).__name__}") from None

    def rpc(self, method: str, params: Any, cost: int) -> Any:
        self.budget.charge(cost)
        body = json.dumps({"jsonrpc": "2.0", "id": "hf", "method": method, "params": params}).encode()
        url = f"https://{HELIUS_RPC_HOST}/"
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "holder-forensics/1.0", "x-api-key": self._key},
        )
        status, payload = self._send(req)
        if status != 200 or not isinstance(payload, dict) or "result" not in payload:
            raise ForensicsError(f"helius rpc {method} failed (http {status})")
        return payload["result"]

    def token_accounts(self, mint: str, *, max_pages: int = MAX_DAS_PAGES) -> tuple[list[dict[str, Any]], bool]:
        """Return (accounts, truncated). truncated=True means the page cap was hit and holders are missing."""
        rows: list[dict[str, Any]] = []
        for page in range(1, max_pages + 1):
            result = self.rpc(
                "getTokenAccounts",
                {"mint": mint, "page": page, "limit": 1000, "options": {"showZeroBalance": False}},
                COST_DAS_PAGE,
            )
            batch = result.get("token_accounts", [])
            rows.extend(batch)
            if len(batch) < 1000:
                return rows, False
        return rows, True

    def funded_by(self, address: str) -> dict[str, Any] | None:
        """First incoming SOL funder of a wallet; None when the wallet has no funding record."""
        self.budget.charge(COST_FUNDED_BY)
        url = f"https://{HELIUS_API_HOST}/v1/wallet/{address}/funded-by"
        req = urllib.request.Request(url, headers={"User-Agent": "holder-forensics/1.0", "x-api-key": self._key})
        status, payload = self._send(req)
        if status == 404:
            return None
        if status != 200 or not isinstance(payload, dict):
            raise ForensicsError(f"helius funded-by failed (http {status})")
        return payload if payload.get("funder") else None


def dexscreener_pairs(mint: str, opener: urllib.request.OpenerDirector | None = None) -> tuple[list[dict[str, Any]], bool]:
    """Return (pairs, ok). ok=False means the lookup failed, so pool exclusion and launch time are unknown."""
    url = f"https://{DEXSCREENER_HOST}/latest/dex/tokens/{mint}"
    try:
        _check_host(url)
        req = urllib.request.Request(url, headers={"User-Agent": "holder-forensics/1.0"})
        with (opener or urllib.request.build_opener(_NoRedirect())).open(req, timeout=30) as resp:
            return json.load(resp).get("pairs") or [], True
    except Exception:  # noqa: BLE001 - advisory data only
        return [], False


# ----------------------------------------------------------------------------- parallel lookups


def _attempt(lookup: Callable[[str], Any], item: str) -> tuple[str, Any]:
    """Run one lookup and reduce its outcome to plain data: ("ok", answer), ("budget", None) when the credit cap refused
    the charge (nothing was sent), or ("error", message). An unexpected exception keeps only its type name, because
    messages and tracebacks can carry request URLs or headers, and with them the key."""
    try:
        return "ok", lookup(item)
    except BudgetError:
        return "budget", None
    except ForensicsError as err:
        return "error", str(err)
    except Exception as err:  # noqa: BLE001 - see docstring
        return "error", f"unexpected {type(err).__name__}"


def run_lookups(items: list[str], lookup: Callable[[str], Any], workers: int, on_outcome: Callable[[int, tuple[str, Any]], bool]) -> dict[int, tuple[str, Any]]:
    """Run `lookup` over `items` with at most `workers` in flight, dispatched in list order. Every outcome goes to
    `on_outcome(index, outcome)` in COMPLETION order; once it returns True, or any lookup is refused by the credit cap,
    no new lookup is dispatched, and the ones already in flight finish and are returned. The result is keyed by item
    position, so callers assemble output in list order, never completion order; a missing position was not reached.

    workers == 1 is the old one-at-a-time loop in the calling thread. Worker threads are daemons, so Ctrl-C (raised in
    the calling thread) is never held up by a request that is still running."""
    outcomes: dict[int, tuple[str, Any]] = {}
    if workers <= 1:
        for i, item in enumerate(items):
            outcomes[i] = _attempt(lookup, item)
            if on_outcome(i, outcomes[i]):
                break
        return outcomes
    stop = threading.Event()
    tasks: queue.Queue = queue.Queue()
    done: queue.Queue = queue.Queue()

    def worker() -> None:
        while True:
            task = tasks.get()
            if task is None:
                return
            i, item = task
            if stop.is_set():
                done.put((i, ("skipped", None)))  # handed over just as the run stopped: never started
                continue
            try:
                outcome = _attempt(lookup, item)
            except BaseException as err:  # noqa: BLE001 - a worker that died without reporting would leave the caller waiting forever
                outcome = ("error", f"unexpected {type(err).__name__}")
            if outcome[0] == "budget":
                stop.set()  # stop dispatch at once, before the calling thread has even read this outcome
            done.put((i, outcome))

    threads = [threading.Thread(target=worker, name=f"holder-forensics-lookup-{n}", daemon=True) for n in range(min(workers, len(items)))]
    for thread in threads:
        thread.start()
    nxt = in_flight = 0
    try:
        while True:
            while not stop.is_set() and in_flight < workers and nxt < len(items):
                tasks.put((nxt, items[nxt]))
                nxt += 1
                in_flight += 1
            if not in_flight:
                break
            i, outcome = done.get()
            in_flight -= 1
            if outcome[0] == "skipped":
                continue
            outcomes[i] = outcome
            if on_outcome(i, outcome):
                stop.set()
    finally:
        stop.set()  # on Ctrl-C too: queued work is skipped and idle workers exit
        for _ in threads:
            tasks.put(None)
    return outcomes


# ----------------------------------------------------------------------------- pure analysis (unit-tested)


def safe_label(value: Any) -> str | None:
    """Provider-supplied labels end up in reports that agents read: strip to a short, inert string, then (HS-LABELS-T1)
    replace any verdict word or phrase with provider_words.PLACEHOLDER. A label that is already safe passes unchanged."""
    return pw.label(value, LABEL_RE)


def _label_chars(value: Any) -> str | None:
    """The label rule before HS-LABELS-T1 (characters and length only). Used where a provider name is an identity (the
    duplicate and reserved-name checks of --providers-json) and to recognise a label saved by an earlier version; never
    printed."""
    if not isinstance(value, str) or not value.strip():
        return None
    return LABEL_RE.sub("", value)[:32].strip() or None


def aggregate_owners(token_accounts: Iterable[dict[str, Any]]) -> dict[str, float]:
    """Sum balances per owner (one owner can hold several token accounts)."""
    totals: dict[str, float] = collections.defaultdict(float)
    for row in token_accounts:
        owner = row.get("owner")
        if not owner:
            continue
        try:
            amount = float(row.get("amount") or 0)
        except (TypeError, ValueError):
            continue  # skip before touching the dict so a bad row cannot create a zero-balance owner
        totals[owner] += amount
    return dict(totals)


def gini(values: list[float]) -> float:
    xs = sorted(v for v in values if v >= 0)
    n = len(xs)
    total = sum(xs)
    if n == 0 or total == 0:
        return 0.0
    cum = list(itertools.accumulate(xs))
    return (n + 1 - 2 * sum(cum) / total) / n


def distribution(owner_balances: dict[str, float], excluded: set[str] | None = None) -> dict[str, Any]:
    """Distribution over ALL owners. `excluded` (pools/infrastructure) stay in supply but are labelled."""
    excluded = excluded or set()
    total = sum(owner_balances.values())
    if total <= 0:
        return {"owners": 0, "supply": 0.0}
    ranked = sorted(owner_balances.items(), key=lambda kv: -kv[1])
    shares = [(owner, amount / total * 100) for owner, amount in ranked]
    tops = {f"top_{n}": round(sum(s for _, s in shares[:n]), 2) for n in (1, 5, 10, 20, 50, 100, 250, 500)}
    ex_pools = [s for o, s in shares if o not in excluded]
    top_ex_infra = {"top_1": round(sum(ex_pools[:1]), 2), "top_10": round(sum(ex_pools[:10]), 2)}
    buckets: dict[str, dict[str, float]] = {}
    for label, lo, hi in ((">=1%", 1, 1e9), ("0.1-1%", 0.1, 1), ("0.01-0.1%", 0.01, 0.1), ("<0.01%", 0, 0.01)):
        members = [s for _, s in shares if lo <= s < hi]
        buckets[label] = {"wallets": len(members), "supply_pct": round(sum(members), 2)}
    return {
        "owners": len(shares),
        "supply": total,
        "gini": round(gini(list(owner_balances.values())), 3),
        "top": tops,
        "top_ex_infra": top_ex_infra,
        "buckets": buckets,
        "infrastructure_pct": round(sum(s for o, s in shares if o in excluded), 2),
        "ranked": [(o, round(s, 4)) for o, s in shares],
    }


def detect_batches(
    records: list[dict[str, Any]],
    *,
    min_wallets: int = MIN_BATCH_WALLETS,
    tight_window_s: int = TIGHT_WINDOW_S,
) -> list[dict[str, Any]]:
    """Group holders by the wallet that first funded them.

    Each record: {wallet, share_pct, funder, funder_name, funder_type, funded_at (unix s)}.
    A "batch" is a funder that first-funded >= min_wallets of the examined holders. A batch is "labeled"
    when ANY member's funder label is known (a labeled funder is an exchange/bridge/known entity).
    """
    groups: dict[str, list[dict[str, Any]]] = collections.defaultdict(list)
    for rec in records:
        if rec.get("funder") and isinstance(rec.get("funded_at"), int):
            groups[rec["funder"]].append(rec)
    batches = []
    for funder, members in groups.items():
        if len(members) < min_wallets:
            continue
        times = [m["funded_at"] for m in members]
        name = next((m["funder_name"] for m in members if m.get("funder_name")), None)
        ftype = next((m["funder_type"] for m in members if m.get("funder_type")), None)
        batches.append(
            {
                "funder": funder,
                "funder_name": name,
                "funder_type": ftype,
                "labeled": bool(name or ftype),
                "wallets": len(members),
                "share_pct": round(sum(m["share_pct"] for m in members), 2),
                "start": min(times),
                "window_s": max(times) - min(times),
                "tight": (max(times) - min(times)) <= tight_window_s,
                "members": [m["wallet"] for m in members],
            }
        )
    batches.sort(key=lambda b: -b["share_pct"])
    return batches


def cadence(batches: list[dict[str, Any]]) -> dict[str, Any]:
    """Regularity of batch start times. Machine schedules show a low coefficient of variation."""
    starts = sorted(b["start"] for b in batches)
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    if len(gaps) < 3:
        return {"rounds": len(starts), "gaps_s": gaps, "regular": False, "cv": None}
    mean = statistics.mean(gaps)
    cv = statistics.pstdev(gaps) / mean if mean else None
    return {"rounds": len(starts), "gaps_s": gaps, "mean_gap_s": round(mean, 1), "cv": None if cv is None else round(cv, 3), "regular": cv is not None and cv < 0.35}


def classify(batches: list[dict[str, Any]], launch_ts: int | None = None) -> dict[str, Any]:
    """FACTORY_PATTERN level (STRONG / WEAK / NOT_DETECTED) from unlabeled, tightly-timed funder batches.

    Heuristic, UNVALIDATED, and blind to farms that fund through labeled exchanges: NOT_DETECTED is not an
    all-clear. The overall verdict comes from `assess`, which also uses the cohort detector."""
    eligible = [b for b in batches if not b["labeled"] and b["tight"] and b["wallets"] >= CLASSIFY_MIN_WALLETS]
    share = round(sum(b["share_pct"] for b in eligible), 2)
    wallets = sum(b["wallets"] for b in eligible)
    cad = cadence(eligible)
    reasons = []
    if eligible:
        reasons.append(f"{len(eligible)} unlabeled funders each funded >={CLASSIFY_MIN_WALLETS} holders within {TIGHT_WINDOW_S}s")
    if cad["regular"]:
        reasons.append(f"batch start times are regular (gap CV {cad['cv']})")
    if launch_ts and eligible:
        reasons.append(f"{sum(1 for b in eligible if b['start'] >= launch_ts)}/{len(eligible)} batches started after the first DEX pair")
    if len(eligible) >= STRONG_MIN_BATCH_FUNDERS and share >= STRONG_SHARE_PCT:
        level = "STRONG"
    elif len(eligible) >= WEAK_MIN_BATCH_FUNDERS and share >= WEAK_SHARE_PCT:
        level = "WEAK"
    else:
        level = "NOT_DETECTED"  # absence of an unlabeled single-funder batch; never an all-clear
    return {
        "level": level,
        "share_pct": share,
        "wallets": wallets,
        "batch_funders": len(eligible),
        "cadence": cad,
        "reasons": reasons,
        "thresholds_are": "UNVALIDATED heuristics from one observed case; linkage is not proof of common control",
    }


def trace_upstream(batches: list[dict[str, Any]], funded_by: Callable[[str], dict[str, Any] | None], workers: int = 1) -> list[dict[str, Any]]:
    """Funded-by on each batch funder. Rows stay in batch order whatever order the lookups finish in. A failed lookup
    is skipped (it must not discard the run); a refused credit charge stops the trace and raises BudgetError."""
    refused = False

    def on_outcome(_: int, outcome: tuple[str, Any]) -> bool:
        nonlocal refused
        refused = refused or outcome[0] == "budget"
        return refused

    outcomes = run_lookups([b["funder"] for b in batches], funded_by, workers, on_outcome)
    if refused:
        raise BudgetError("credit budget reached during upstream trace")
    rows = []
    for i, batch in enumerate(batches):
        kind, up = outcomes.get(i, ("not_reached", None))
        if kind != "ok":
            continue
        if up and up.get("funder"):
            rows.append(
                {
                    "batch_funder": batch["funder"],
                    "upstream": up["funder"],
                    "upstream_name": safe_label(up.get("funderName")),
                    "upstream_type": safe_label(up.get("funderType")),
                    "amount_sol": up.get("amount") if isinstance(up.get("amount"), (int, float)) else None,
                    "funded_at": up.get("timestamp") if isinstance(up.get("timestamp"), int) else None,
                }
            )
    return rows


def build_records(owner_balances: dict[str, float], funded: dict[str, dict[str, Any] | None]) -> list[dict[str, Any]]:
    """Skip wallets with no funder or a malformed record instead of crashing the run."""
    total = sum(owner_balances.values()) or 1.0
    records = []
    for wallet, info in funded.items():
        if not isinstance(info, dict) or not info.get("funder"):
            continue
        ts = info.get("timestamp")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            continue
        records.append(
            {
                "wallet": wallet,
                "share_pct": owner_balances.get(wallet, 0.0) / total * 100,
                "funder": info["funder"],
                "funder_name": safe_label(info.get("funderName")),
                "funder_type": safe_label(info.get("funderType")),
                "funded_at": int(ts),
                "first_amount_sol": info.get("amount") if isinstance(info.get("amount"), (int, float)) else None,
            }
        )
    return records


def top_holder_rows(ranked: list[tuple[str, float]], infrastructure: set[str], top: int) -> list[dict[str, Any]]:
    """holders.json `top_holders`: full addresses in rank order down to the `top`-th ordinary wallet. Pools and other
    excluded owners in that range are listed with infrastructure=True and do not count toward `top`. `rank` is the
    position in the full holder list, pools included (the same rank funders.json `rows` uses)."""
    rows: list[dict[str, Any]] = []
    counted = 0
    for rank, (owner, share) in enumerate(ranked, 1):
        if counted >= top:
            break
        infra = owner in infrastructure
        counted += 0 if infra else 1
        rows.append({"rank": rank, "wallet": owner, "share_pct": share, "infrastructure": infra})
    return rows


def _utc_iso(ts: int | None) -> str | None:
    if ts is None:
        return None
    try:
        return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


def funder_row(rank: int, wallet: str, share_pct: float, outcome: tuple[str, Any] | None) -> dict[str, Any]:
    """funders.json `rows` entry for one requested wallet. status: funded | no_funding_record | failed | not_reached
    (not looked up because the run stopped early, or the credit cap refused the charge so nothing was sent). The
    funder fields follow build_records; labels go through safe_label; addresses are never shortened."""
    row: dict[str, Any] = {"rank": rank, "wallet": wallet, "share_pct": share_pct, "status": "not_reached", "funder": None, "funder_name": None,
                           "funder_type": None, "funded_at": None, "funded_at_utc": None, "first_amount_sol": None}
    kind, info = outcome or ("not_reached", None)
    if kind == "error":
        row["status"] = "failed"
    elif kind == "ok" and isinstance(info, dict) and info.get("funder"):
        ts = info.get("timestamp")
        funded_at = int(ts) if isinstance(ts, (int, float)) and not isinstance(ts, bool) else None
        row.update(
            status="funded",
            funder=info["funder"],
            funder_name=safe_label(info.get("funderName")),
            funder_type=safe_label(info.get("funderType")),
            funded_at=funded_at,
            funded_at_utc=_utc_iso(funded_at),
            first_amount_sol=info.get("amount") if isinstance(info.get("amount"), (int, float)) else None,
        )
    elif kind == "ok":
        row["status"] = "no_funding_record"
    return row


def estimate_funder_cost(top: int) -> int:
    # At most top // MIN_BATCH_WALLETS batch funders can exist, so the upstream traces scale with --top.
    traces = min(UPSTREAM_TRACE_LIMIT, max(1, top // MIN_BATCH_WALLETS))
    return top * COST_FUNDED_BY + traces * COST_FUNDED_BY


# ----------------------------------------------------------------------------- funding-time cohort detector (pure)
# Normalized row, one per examined holder (any source: Helius funded-by, GMGN rows, Jupiter datapi rows):
#   {wallet, first_funding_time (unix s), funder_address, funder_label (opt), first_funding_amount (opt),
#    supply_pct (percent of total supply), first_acquired_at (opt unix s)}


def _to_unix(value: Any) -> int | None:
    """Unix seconds from seconds, milliseconds or an ISO-8601 string; None when unusable."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and value == value and value > 0:
        return int(value / 1000) if value > 1e12 else int(value)
    if isinstance(value, str) and value.strip():
        try:
            return int(dt.datetime.fromisoformat(value.strip().replace("Z", "+00:00")).timestamp())
        except ValueError:
            return None
    return None


def _first_number(row: dict[str, Any], *keys: str) -> float | None:
    for key in keys:
        value = row.get(key)
        if isinstance(value, (int, float)) and not isinstance(value, bool) and value == value:
            return float(value)
    return None


def _unwrap(payload: Any) -> list[dict[str, Any]]:
    """A bare list, or a wrapper dict holding the list under body (probe envelope) / list / holders / data / items."""
    if isinstance(payload, dict):
        for key in ("body", "list", "holders", "data", "items"):
            inner = payload.get(key)
            if isinstance(inner, (list, dict)):
                found = _unwrap(inner)
                if found or key == "body":
                    return found
        return []
    return [r for r in payload if isinstance(r, dict)] if isinstance(payload, list) else []


def _rows_of(payload: Any, label: str = "holder payload") -> list[dict[str, Any]]:
    """Holder rows from a parsed payload. An empty payload is []; a NON-empty payload that yields no rows raises,
    because a changed provider shape must be loud, never read as 'no holders'."""
    rows = _unwrap(payload)
    if not rows and payload not in (None, [], {}, ""):
        raise ConfigError(f"{label} is not empty but holds no holder rows; the provider format may have changed")
    return rows


def _need_rows(payload: Any, out: list[dict[str, Any]], label: str) -> list[dict[str, Any]]:
    if not out and _unwrap(payload):
        raise ConfigError(f"{label} has rows but none carries a wallet address; the provider format may have changed")
    return out


def helius_cohort_rows(records: list[dict[str, Any]], acquisitions: dict[str, int] | None = None) -> list[dict[str, Any]]:
    """Normalized rows from build_records() output (Helius funded-by)."""
    acq = acquisitions or {}
    return [
        {
            "wallet": r["wallet"],
            "first_funding_time": r["funded_at"],
            "funder_address": r["funder"],
            "funder_label": r.get("funder_name") or r.get("funder_type"),
            "first_funding_amount": r.get("first_amount_sol"),
            "supply_pct": r["share_pct"],
            "first_acquired_at": acq.get(r["wallet"]),
        }
        for r in records
    ]


def gmgn_cohort_rows(payload: Any, share_by_wallet: dict[str, float] | None = None) -> list[dict[str, Any]]:
    """Normalized rows from an already-parsed GMGN holders payload (top 100, no network here).

    Two row shapes are read. Raw GMGN rows (the API answer, and the gmgn_rows.py collector's gmgn_top100.json, which
    keeps the raw names): address, native_transfer.{from_address, timestamp, name, amount}, start_holding_at, and a supply
    fraction under amount_percentage. The cleaned rows of the lp-research-companion collector (its sanitized
    `holders`): address, funder, funding_ts, start_holding_at, share_total_supply; they carry no funder label or amount.
    A row with a native_transfer object is read as raw; only a row without one falls back to funder / funding_ts. Field
    names match the cached GMGN docs (token_top_holders: native_transfer {from_address, amount, timestamp},
    start_holding_at, amount_percentage); a missing field leaves that value None. `share_by_wallet` (percent, e.g. from
    the Helius list) overrides the provider share."""
    out = []
    for row in _rows_of(payload, "GMGN holders payload"):
        wallet = row.get("address") or row.get("wallet")
        if not isinstance(wallet, str) or not wallet:
            continue
        if isinstance(row.get("native_transfer"), dict):
            nt = row["native_transfer"]
            funded_at, funder = _to_unix(nt.get("timestamp")), nt.get("from_address") if isinstance(nt.get("from_address"), str) else None
            label, amount = safe_label(nt.get("name")), _first_number(nt, "amount", "sol_amount")
        else:  # cleaned lp-research-companion shape (or a raw row without native_transfer: both fields then absent)
            funded_at, funder = _to_unix(row.get("funding_ts")), row.get("funder") if isinstance(row.get("funder"), str) else None
            label = amount = None
        frac = _first_number(row, "amount_percentage", "share_total_supply")
        pct = (share_by_wallet or {}).get(wallet, frac * 100 if frac is not None and 0 <= frac <= 1 else None)
        out.append(
            {
                "wallet": wallet,
                "first_funding_time": funded_at,
                "funder_address": funder,
                "funder_label": label,
                "first_funding_amount": amount,
                "supply_pct": pct,
                "first_acquired_at": _to_unix(row.get("start_holding_at")),
            }
        )
    return _need_rows(payload, out, "GMGN holders payload")


def jupiter_cohort_rows(payload: Any, share_by_wallet: dict[str, float] | None = None, total_supply: float | None = None) -> list[dict[str, Any]]:
    """Normalized rows from an already-parsed Jupiter datapi holders payload (top 100, no network here).

    Read per row: address, amount, addressInfo.{fundingAddress, fundingAmount, fundingBlockTime}. datapi is
    undocumented and may change. Share comes from `share_by_wallet` (percent), else amount / total_supply, else None."""
    out = []
    for row in _rows_of(payload, "Jupiter holders payload"):
        wallet = row.get("address")
        info = row.get("addressInfo") if isinstance(row.get("addressInfo"), dict) else {}
        if not isinstance(wallet, str) or not wallet:
            continue
        amount = _first_number(row, "amount")
        pct = (share_by_wallet or {}).get(wallet)
        if pct is None and amount is not None and total_supply:
            pct = amount / total_supply * 100
        out.append(
            {
                "wallet": wallet,
                "first_funding_time": _to_unix(info.get("fundingBlockTime")),
                "funder_address": info.get("fundingAddress") if isinstance(info.get("fundingAddress"), str) else None,
                "funder_label": None,  # datapi carries no funder label
                "first_funding_amount": _first_number(info, "fundingAmount"),
                "supply_pct": pct,
                "first_acquired_at": None,
            }
        )
    return _need_rows(payload, out, "Jupiter holders payload")


def normalize_acquisitions(raw: Any) -> dict[str, int]:
    """wallet -> unix time of first token acquisition (e.g. GMGN start_holding_at). Bad entries are dropped."""
    if not isinstance(raw, dict):
        return {}
    out = {}
    for wallet, value in raw.items():
        ts = _to_unix(value)
        if isinstance(wallet, str) and wallet and ts:
            out[wallet] = ts
    return out


def source_coverage(rows: list[dict[str, Any]]) -> dict[str, Any]:
    usable = [r for r in rows if r.get("first_funding_time")]
    return {
        "rows": len(rows),
        "with_funding_time": len(usable),
        "supply_pct": round(sum(r.get("supply_pct") or 0.0 for r in usable), 2),
        "share_known_for": sum(1 for r in usable if r.get("supply_pct") is not None),
    }


def _median(values: list[float]) -> float | None:
    return round(statistics.median(values), 4) if values else None


def share_text(c: dict[str, Any]) -> str:
    """Plain supply-share wording; never prints 0.0% for a share that is unknown."""
    unknown = c.get("share_unknown_wallets", 0 if c.get("share_known", True) else c["wallets"])
    if unknown >= c["wallets"]:
        return "supply share unknown"
    if unknown:
        return f"at least {c['share_pct']}% of supply (share unknown for {unknown} wallets)"
    return f"{c['share_pct']}% of supply"


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def coverage_share_text(cov: dict[str, Any]) -> str:
    return "supply share unknown" if not cov.get("share_known_for") and cov.get("with_funding_time") else f"{cov['supply_pct']}% of supply"


def _cohort_detail(members: list[dict[str, Any]], launch_ts: int | None, share_known: bool) -> dict[str, Any]:
    """HS-OWNER-1019-T1: a wallet whose row carries no funder address has an UNKNOWN funder. It is counted in
    unknown_funder_wallets, never as a funder: distinct_funders and funder_mix hold known funders only.
    HS-LABELS-T1 (N2): labeled_funder_wallets still counts every wallet whose row names a funder label; the ones among
    them with no funder address (a provider such as GMGN can give the label without the address) are counted in
    labeled_unknown_funder_wallets, so the report can say so instead of a labeled count that looks like known funders."""
    times = [m["first_funding_time"] for m in members]
    mix: dict[str, dict[str, Any]] = {}
    unknown_funder_wallets = 0
    for m in members:
        key = m.get("funder_address")
        if not key:
            unknown_funder_wallets += 1
            continue
        slot = mix.setdefault(key, {"funder": key, "label": m.get("funder_label"), "wallets": 0, "share_pct": 0.0})
        slot["wallets"] += 1
        slot["share_pct"] = round(slot["share_pct"] + (m.get("supply_pct") or 0.0), 4)
        slot["label"] = slot["label"] or m.get("funder_label")
    funder_mix = sorted(mix.values(), key=lambda x: -x["wallets"])
    labeled = sum(1 for m in members if m.get("funder_label"))
    amounts = [m["first_funding_amount"] for m in members if isinstance(m.get("first_funding_amount"), (int, float))]
    amount_info: dict[str, Any] = {"n": len(amounts)}
    if amounts:
        med = statistics.median(amounts)
        band = [a for a in amounts if med > 0 and abs(a - med) <= COHORT_AMOUNT_REL_BAND * med]
        amount_info |= {"min": round(min(amounts), 4), "median": round(med, 4), "max": round(max(amounts), 4), "similar_fraction": round(len(band) / len(amounts), 3)}
        amount_info["similar"] = amount_info["similar_fraction"] >= COHORT_AMOUNT_SIMILAR_FRACTION
    gaps = [m["first_acquired_at"] - m["first_funding_time"] for m in members if m.get("first_acquired_at")]
    return {
        "wallets": len(members),
        "share_pct": round(sum(m.get("supply_pct") or 0.0 for m in members), 2),
        "share_known": share_known,
        "share_unknown_wallets": sum(1 for m in members if m.get("supply_pct") is None),
        "start": min(times),
        "end": max(times),
        "window_s": max(times) - min(times),
        "distinct_funders": len(mix),  # known funders only
        "unknown_funder_wallets": unknown_funder_wallets,
        "labeled_funder_wallets": labeled,  # labeled exchange/service funders are kept visible, never excluded
        "labeled_unknown_funder_wallets": sum(1 for m in members if m.get("funder_label") and not m.get("funder_address")),  # N2: label, no address
        "funder_mix": funder_mix,
        "first_amounts": amount_info,
        "dormant_gap_s": {"n": len(gaps), "median": _median([float(g) for g in gaps]), "min": min(gaps) if gaps else None, "max": max(gaps) if gaps else None},
        "funding_to_launch_s_median": _median([float(launch_ts - t) for t in times]) if launch_ts else None,
        "members": [m["wallet"] for m in members],
    }


def cohort_dormant_gap_s(c: dict[str, Any]) -> float | None:
    """Median funding-to-first-holding gap when acquisition times exist, else median (launch - funding) when the launch
    time is known. Funded after launch gives a gap of zero or less, which never counts as dormancy."""
    gap = (c.get("dormant_gap_s") or {}).get("median")
    return gap if gap is not None else c.get("funding_to_launch_s_median")


NO_DISCRIMINATOR_REASON = "funded together but no sign of dormancy, synchronized buying or scripted amounts"
SIGN_NAMES = ("dormancy", "synchronized acquisition", "similar amounts")


def cohort_signs(c: dict[str, Any]) -> dict[str, str]:
    """The discriminating signs that fired for one cohort: {name: readable text}."""
    signs: dict[str, str] = {}
    gap = cohort_dormant_gap_s(c)
    if gap is not None and gap >= COHORT_DORMANT_GAP_S:
        signs["dormancy"] = f"dormant {gap / 86400:.0f} days"
    acq = c.get("acquisition") or {}
    if acq.get("flag"):
        signs["synchronized acquisition"] = f"bought within {acq['window_s']} s of each other"
    if (c.get("first_amounts") or {}).get("similar"):
        signs["similar amounts"] = "similar first amounts"
    return signs


def funders_toward_high(c: dict[str, Any]) -> int:
    """The funder count the HIGH rule compares with COHORT_HIGH_MIN_FUNDERS. Unchanged by HS-OWNER-1019-T1 (owner
    decision 2026-10-19, Option A: wording only, no verdict change): the known funders, plus ONE for all the wallets
    whose funder is unknown together. Counting known funders only would turn a cohort of one known funder plus
    unknown-funder wallets from HIGH into UNRESOLVED, a verdict change the owner has not approved (Option B, letting
    missing funder data stop blocking HIGH, is a later idea that needs negative controls). A funder field holding the
    text "unknown" was merged with the missing ones before, so it is merged here too: the count is exactly the old one."""
    merged = any(m.get("funder") == "unknown" for m in c.get("funder_mix") or [])
    return c["distinct_funders"] + (1 if c.get("unknown_funder_wallets") and not merged else 0)


def funder_text(c: dict[str, Any]) -> str:
    """Plain funder count for one cohort: '6 funders', or, when some funders are unknown, the known funders and
    'funder unknown for X of Y wallets'. Wallets with no funder address are never shown as one shared funder."""
    unknown = c.get("unknown_funder_wallets") or 0
    if not unknown:
        return _plural(c["distinct_funders"], "funder")
    known = _plural(c["distinct_funders"], "known funder") if c["distinct_funders"] else "no known funder"
    return f"{known}, funder unknown for {unknown} of {c['wallets']} wallets"


def labeled_funder_text(c: dict[str, Any], via: str) -> str:
    """HS-LABELS-T1 (N2): '40 via labeled funders', and, when some of those wallets have no funder address, ', 40 of them
    with no funder address', so a labeled count is never read as known funders. Wording only: no count or verdict changes."""
    no_address = c.get("labeled_unknown_funder_wallets") or 0
    return f"{c['labeled_funder_wallets']} {via} labeled funders" + (f", {no_address} of them with no funder address" if no_address else "")


def cohort_severity(c: dict[str, Any]) -> tuple[str, str]:
    """HIGH or UNRESOLVED for one flagged cohort.

    HIGH needs >= COHORT_HIGH_MIN_WALLETS wallets AND >= COHORT_HIGH_MIN_FUNDERS funders (funders_toward_high: the
    known funders, plus one for the unknown-funder wallets together, as before) AND at least
    COHORT_HIGH_MIN_SIGNS of three signs: (a) median dormant gap >= COHORT_DORMANT_GAP_S, (b) the acquisition check
    flagged a narrow buying window, (c) similar first amounts. One sign alone is UNRESOLVED (an influencer burst or a
    community that pre-funded wallets each show one sign on normal organic launches); so is no sign, or missing data.
    Many organic young launches meet "20 wallets and 2 funders" trivially (a Monte Carlo gave HIGH about 100% of the
    time when funding spanned 3 days or less). Flagged only by the supply route, or a single funder, is always
    UNRESOLVED. A farm funded straight through labeled exchanges with scripted amounts but no dormancy and no narrow
    buying window therefore reads UNRESOLVED (the funder-batch detector covers the unlabeled-funder style).
    Wording (HS-OWNER-1019-T1): "a single funder fed all N wallets" only for exactly one KNOWN funder and no unknown
    ones; a cohort whose funders are all unknown says so and states the rule as it is (HIGH needs 2+ funders, and
    wallets with an unknown funder count together as one); when the unknown-funder wallets are what makes the second
    funder, the reason says they were counted together as a second funder."""
    signs = cohort_signs(c)
    text = ", ".join(signs.values())
    extra = f"; signs: {text}" if text else ""
    unknown = c.get("unknown_funder_wallets") or 0
    if c["wallets"] < COHORT_HIGH_MIN_WALLETS:
        return VERDICT_UNRESOLVED, f"only {c['wallets']} wallets, flagged by supply share alone; HIGH needs {COHORT_HIGH_MIN_WALLETS} wallets{extra}"
    if funders_toward_high(c) < COHORT_HIGH_MIN_FUNDERS:
        if unknown:  # no known funder at all: every wallet's funder is unknown
            return VERDICT_UNRESOLVED, (f"funder unknown for {unknown} of {c['wallets']} wallets; HIGH needs {COHORT_HIGH_MIN_FUNDERS}+ funders, "
                                        f"and wallets with an unknown funder count together as one{extra}")
        return VERDICT_UNRESOLVED, f"a single funder fed all {c['wallets']} wallets{extra}"
    if unknown:
        counted = ", counted together as a second funder toward HIGH" if c["distinct_funders"] < COHORT_HIGH_MIN_FUNDERS else ""
        funders = f"{c['wallets']} wallets, {funder_text(c)}{counted}"
    else:
        funders = f"{c['wallets']} wallets from {c['distinct_funders']} funders"
    if not signs:
        return VERDICT_UNRESOLVED, f"{funders}: {NO_DISCRIMINATOR_REASON}"
    if len(signs) < COHORT_HIGH_MIN_SIGNS:
        missing = ", ".join(n for n in SIGN_NAMES if n not in signs)
        return VERDICT_UNRESOLVED, f"funded together; one sign only: {next(iter(signs))} ({text}); missing: {missing}; HIGH needs {COHORT_HIGH_MIN_SIGNS}"
    return VERDICT_HIGH, f"{funders}; signs: {text}"


def detect_cohorts(
    rows: list[dict[str, Any]],
    *,
    window_s: int = COHORT_WINDOW_S,
    min_wallets: int = COHORT_MIN_WALLETS,
    min_supply_pct: float = COHORT_MIN_SUPPLY_PCT,
    floor_wallets: int = COHORT_MIN_WALLETS_FLOOR,
    require_similar_amounts: bool = False,
    launch_ts: int | None = None,
) -> list[dict[str, Any]]:
    """Group holders by first-funding TIME across ALL funders (labeled exchange funders included).

    Greedy: take the window (span <= window_s) holding the most supply that qualifies (>= min_wallets wallets, or
    >= min_supply_pct supply with >= floor_wallets wallets), report it, remove its members, repeat. Linkage
    evidence only: it does not prove common control and its false-positive rate is unknown."""
    pool = sorted((r for r in rows if r.get("first_funding_time")), key=lambda r: r["first_funding_time"])
    cohorts: list[dict[str, Any]] = []
    while pool:
        best: tuple[float, int, int, int] | None = None
        share = [r.get("supply_pct") or 0.0 for r in pool]
        j = 0
        running = 0.0
        for i in range(len(pool)):
            if j < i:
                j, running = i, 0.0
            while j < len(pool) and pool[j]["first_funding_time"] - pool[i]["first_funding_time"] <= window_s:
                running += share[j]
                j += 1
            count = j - i
            ok = count >= min_wallets or (running >= min_supply_pct and count >= floor_wallets)
            if ok and require_similar_amounts:
                ok = bool(_cohort_detail(pool[i:j], None, True)["first_amounts"].get("similar"))
            if ok and (best is None or (running, count) > (best[0], best[1])):
                best = (running, count, i, j)
            running -= share[i]
        if best is None:
            break
        _, count, i, j = best
        members = pool[i:j]
        detail = _cohort_detail(members, launch_ts, all(m.get("supply_pct") is not None for m in members))
        by_wallets, by_supply = count >= min_wallets, detail["share_pct"] >= min_supply_pct
        detail["flagged_by"] = "wallets+supply" if by_wallets and by_supply else "wallets" if by_wallets else "supply"
        detail["severity"], detail["severity_reason"] = cohort_severity(detail)
        cohorts.append(detail)
        pool = pool[:i] + pool[j:]
    cohorts.sort(key=lambda c: -c["share_pct"])
    return cohorts


def acquisition_check(
    members: list[str],
    acquisitions: dict[str, int] | None,
    *,
    window_s: int = ACQUISITION_WINDOW_S,
    min_wallets: int = ACQUISITION_MIN_WALLETS,
    min_fraction: float = ACQUISITION_MIN_FRACTION,
) -> dict[str, Any]:
    """Token-acquisition-time check for one cohort over optionally supplied per-wallet timestamps (no network).

    Finds the narrowest span holding >= min_fraction of the timestamped members; flags when at least min_wallets
    members have timestamps and that span is <= window_s. With no timestamps it did not run."""
    if not acquisitions:
        return {"ran": False, "flag": False, "reason": "no acquisition timestamps supplied (--acquisition-json)"}
    stamps = sorted(acquisitions[w] for w in members if w in acquisitions)
    if not stamps:
        return {"ran": False, "flag": False, "reason": "none of the cohort wallets has an acquisition timestamp"}
    need = max(1, -(-int(min_fraction * 100) * len(stamps) // 100))  # ceil(min_fraction * n) without float error
    span = min(stamps[i + need - 1] - stamps[i] for i in range(len(stamps) - need + 1))
    flag = len(stamps) >= min_wallets and span <= window_s
    return {
        "ran": True,
        "flag": flag,
        "timestamped": len(stamps),
        "cohort_wallets": len(members),
        "window_s": span,
        "fraction": min_fraction,
        "median": int(statistics.median(stamps)),
        "reason": f"{need} of {len(stamps)} timestamped members acquired within {span} s" + ("" if len(stamps) >= min_wallets else f"; fewer than {min_wallets} timestamped, not flagged"),
    }


def run_cohort_source(rows: list[dict[str, Any]], *, launch_ts: int | None, acquisitions: dict[str, int] | None = None) -> dict[str, Any]:
    """One source's coverage + cohorts (+ acquisition check and final severity per cohort). Acquisition times fill
    rows that have none, so every source can use per-wallet timestamps from any other source."""
    acq = {r["wallet"]: r["first_acquired_at"] for r in rows if r.get("first_acquired_at")} | (acquisitions or {})
    rows = [dict(r, first_acquired_at=r.get("first_acquired_at") or acq.get(r["wallet"])) for r in rows]
    cohorts = detect_cohorts(rows, launch_ts=launch_ts)
    for c in cohorts:
        c["acquisition"] = acquisition_check(c["members"], acq)
        c["severity"], c["severity_reason"] = cohort_severity(c)  # recomputed: the acquisition check is a discriminator
    return {"coverage": source_coverage(rows), "cohorts": cohorts}


def tag_summary(payload: Any) -> dict[str, int]:
    """Count of provider tags on already-parsed holder rows (GMGN `tags` and `maker_token_tags`, or `maker_tags` in the
    cleaned lp-research-companion rows; Jupiter `holderTags`/`walletCategories`/`tags`). They are the provider's
    claims, not findings. Tags are untrusted text: reduced to short inert labels, only the most common are kept.
    HS-FOLLOWUPS-T1: tags with equal counts are ordered by label (count descending, then label ascending), so the order
    and the top-6 cut no longer follow the per-process set iteration order."""
    counts: dict[str, int] = {}
    for row in _unwrap(payload):
        seen = set()
        for key in ("tags", "maker_token_tags", "maker_tags", "holderTags", "walletCategories"):
            value = row.get(key)
            for tag in value if isinstance(value, list) else []:
                label = safe_label(tag) if isinstance(tag, str) else None
                if label:
                    seen.add(label.lower())
        for label in seen:
            counts[label] = counts.get(label, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:6])


GMGN_POOL_ADDR_TYPE = 2  # GMGN addr_type: 2 = DEX pool or exchange (gmgn_rows.POOL_ADDR_TYPE)


def _without_infrastructure(rows: list[dict[str, Any]], infra: set[str]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """HS-COHORT-POOLS-T1: the wallet rows, and a record of the infrastructure rows removed (rows, supply share of the
    rows whose share is known, and how many have no known share, so an unknown share is never printed as 0)."""
    gone = [r for r in rows if r["wallet"] in infra]
    shares = [r["supply_pct"] for r in gone if r.get("supply_pct") is not None]
    removed = {"rows": len(gone), "supply_pct": round(sum(shares), 2), "share_unknown_rows": len(gone) - len(shares)}
    return [r for r in rows if r["wallet"] not in infra], removed


def provider_cohort_sources(
    holders: dict[str, Any],
    gmgn_payload: Any = None,
    jupiter_payload: Any = None,
    acquisitions: dict[str, int] | None = None,
) -> dict[str, dict[str, Any]]:
    """Cohort detector over already-parsed GMGN / Jupiter datapi holder rows. Shares come from the Helius list when
    the wallet is in it. These top-100 sources cannot give an all-clear (they miss everything below rank 100).
    HS-COHORT-POOLS-T1: pools, bonding curves and other infrastructure never count as cohort wallets. Before each pass
    the rows of this run's infrastructure are removed: every holders.json `pool_addresses` entry (the Dexscreener pairs,
    every --exclude address and, since DS-AMM-VAULTS-T1, each shared DEX vault authority holding the token), every
    `top_holders` row marked infrastructure, and, in the GMGN pass, GMGN rows with addr_type 2. The source's coverage
    describes the rows the pass ran on and records the removed rows under `infrastructure_removed`. The Helius pass
    already runs on non-pool wallets only (run_funders, load_run_funders)."""
    balances = holders.get("_balances") or {}
    total = sum(balances.values()) or 0.0
    share = {w: a / total * 100 for w, a in balances.items()} if total else {}
    launch = holders.get("earliest_pair_created_at")
    infra = {a for a in holders.get("pool_addresses") or [] if isinstance(a, str)}
    infra |= {r["wallet"] for r in holders.get("top_holders") or [] if isinstance(r, dict) and r.get("infrastructure") is True and isinstance(r.get("wallet"), str)}
    out: dict[str, dict[str, Any]] = {}
    if gmgn_payload is not None:
        gmgn_pools = {r.get("address") or r.get("wallet") for r in _unwrap(gmgn_payload) if _is_int(r.get("addr_type")) and r["addr_type"] == GMGN_POOL_ADDR_TYPE}
        rows, removed = _without_infrastructure(gmgn_cohort_rows(gmgn_payload, share), infra | gmgn_pools)
        acq = dict(acquisitions or {})
        for r in rows:  # GMGN start_holding_at is itself acquisition data
            if r["first_acquired_at"] and r["wallet"] not in acq:
                acq[r["wallet"]] = r["first_acquired_at"]
        out["gmgn"] = run_cohort_source(rows, launch_ts=launch, acquisitions=acq)
        out["gmgn"]["coverage"]["infrastructure_removed"] = removed
        out["gmgn"]["tags"] = tag_summary(gmgn_payload)
    if jupiter_payload is not None:
        acq_j = dict(acquisitions or {})
        for r in gmgn_cohort_rows(gmgn_payload) if gmgn_payload is not None else []:
            if r["first_acquired_at"] and r["wallet"] not in acq_j:
                acq_j[r["wallet"]] = r["first_acquired_at"]
        rows, removed = _without_infrastructure(jupiter_cohort_rows(jupiter_payload, share), infra)
        out["jupiter"] = run_cohort_source(rows, launch_ts=launch, acquisitions=acq_j)
        out["jupiter"]["coverage"]["infrastructure_removed"] = removed
        out["jupiter"]["tags"] = tag_summary(jupiter_payload)
    return out


# ----------------------------------------------------------------------------- coverage + verdict gating (pure)


def coverage_block(holders: dict[str, Any], funders: dict[str, Any] | None) -> dict[str, Any]:
    """What the funding detectors actually looked at. Shares are percent of TOTAL supply unless named otherwise."""
    infra = float((holders.get("distribution") or {}).get("infrastructure_pct") or 0.0)
    f = funders or {}
    covered = float(f.get("covered_supply_pct") or 0.0)
    warnings = holders.get("warnings") or []
    pool_unreliable = any("no pool owner matched" in w or "Dexscreener lookup failed" in w for w in warnings)
    # When pool exclusion is unreliable the infrastructure share is a guess: do not shrink the denominator with it.
    basis = 100.0 if pool_unreliable else 100.0 - infra
    return {
        "truncated": bool(holders.get("truncated")),
        "pool_exclusion_reliable": not pool_unreliable,
        "examined_wallets": int(f.get("examined_wallets") or 0),
        "requested_wallets": int(f.get("requested_wallets") or 0),
        "with_funder": int(f.get("with_funder") or 0),
        "failed_wallets": int(f.get("failed_wallets") or 0),
        "examined_supply_pct": round(float(f.get("examined_supply_pct", covered) or 0.0), 2),
        "covered_supply_pct": round(covered, 2),
        "infrastructure_pct": round(infra, 2),
        "covered_noninfra_pct": round(min(100.0, covered / basis * 100.0), 2) if basis > 0 else 0.0,
        "aborted": f.get("aborted"),
    }


DEPTH_GUARD_START = "funding was checked on the top"  # DS-DEPTH-GUARD-T1 reason opening (next_step finds the reason by it)


def unchecked_listed(holders: dict[str, Any], funders: dict[str, Any] | None) -> dict[str, Any] | None:
    """DS-DEPTH-GUARD-T1: the ordinary holders listed in holders.json `top_holders` (pools and other infrastructure left
    out) that have no funders.json row, i.e. that sit below the funded-by depth (--funders-top). Saved data only, no call.
    None when funded-by did not run. `first` and `last` count listed ordinary holders only (pools not counted, as
    --funders-top counts them). A share that is not a number is counted as unknown, never as 0.
    DS-SPLIT-GUARD-T1: `checked_rows` are the rows the Helius funding-time cohort detector ran on (funders_result: a funded
    row with a funder and a first-funding time, through helius_cohort_rows, shares as saved in the rows), minus the members
    of every cohort it reported; split_guard_reason searches them."""
    if not funders:
        return None
    pools = set(holders.get("pool_addresses") or [])
    ordinary = [r for r in holders.get("top_holders") or [] if isinstance(r, dict) and r.get("infrastructure") is not True and r.get("wallet") not in pools]
    looked_up = {r.get("wallet") for r in funders.get("rows") or [] if isinstance(r, dict)}
    rest = [(n, r) for n, r in enumerate(ordinary, 1) if r.get("wallet") not in looked_up]
    shares = [r["share_pct"] for _, r in rest if isinstance(r.get("share_pct"), (int, float)) and not isinstance(r.get("share_pct"), bool)]
    reported = {w for c in (funders.get("cohorts") or {}).get("cohorts") or [] if isinstance(c, dict) for w in c.get("members") or []}
    timed = [r for r in funders.get("rows") or [] if isinstance(r, dict) and r.get("status") == "funded" and r.get("funder") and r.get("wallet") not in reported
             and isinstance(r.get("funded_at"), (int, float)) and not isinstance(r.get("funded_at"), bool)]  # build_records' rule
    return {"checked": len(ordinary) - len(rest), "wallets": len(rest), "supply_pct": sum(shares), "share_unknown_wallets": len(rest) - len(shares),
            "first": rest[0][0] if rest else None, "last": rest[-1][0] if rest else None, "checked_rows": helius_cohort_rows(timed)}


def depth_guard_reason(unchecked: dict[str, Any] | None) -> str | None:
    """DS-DEPTH-GUARD-T1 (owner 2026-10-29, "Detector's own bar"): the NO_ALARM blocker for listed holders that funded-by
    did not check, when they could hide a cohort the funding-time cohort detector would flag. The detector's own bars,
    read here at call time: at least COHORT_MIN_WALLETS of them, or at least COHORT_MIN_SUPPLY_PCT of total supply held
    by at least COHORT_MIN_WALLETS_FLOOR of them (an unknown share could be that large, so it counts). Returns the plain
    reason, or None. decide_verdict adds it after the raised-flag returns: raised flags and every threshold are unchanged."""
    if not unchecked or not unchecked["wallets"]:
        return None
    n, unknown, pct = unchecked["wallets"], unchecked["share_unknown_wallets"], unchecked["supply_pct"]
    if not (n >= COHORT_MIN_WALLETS or (n >= COHORT_MIN_WALLETS_FLOOR and (pct >= COHORT_MIN_SUPPLY_PCT or unknown))):
        return None
    shown = f"{round(pct, 2)}%" if round(pct, 2) > 0 or not pct else "under 0.01%"
    share = "supply share unknown" if unknown >= n else f"at least {shown} of supply, share unknown for {unknown}" if unknown else f"{shown} of supply"
    return (f"{DEPTH_GUARD_START} {unchecked['checked']} holders only; {_plural(n, 'holder')} ranked {unchecked['first']}-{unchecked['last']} ({share}) "
            "were not checked, enough to hide a cohort the detector would flag")


def split_guard_reason(unchecked: dict[str, Any] | None) -> str | None:
    """DS-SPLIT-GUARD-T1 (the same owner bar, "Detector's own bar", for a cohort split across the funded-by depth): the
    NO_ALARM blocker when the unchecked listed holders alone stay under the detector's bars (depth_guard_reason gives
    None) but checked wallets first funded inside one detector window could reach them together with those holders.
    detect_cohorts itself searches `checked_rows` (unchecked_listed: the detector's rows, minus every reported cohort),
    with the same COHORT_WINDOW_S windows and its bars lowered by what the n unchecked holders could add: at least
    COHORT_MIN_WALLETS - n wallets, or at least COHORT_MIN_WALLETS_FLOOR - n wallets holding COHORT_MIN_SUPPLY_PCT minus
    the unchecked share (any share when one is unknown: it could be that large). Constants are read at call time. Returns
    the plain reason, opening with DEPTH_GUARD_START so next_step and the summary find it, or None."""
    if not unchecked or not unchecked["wallets"] or depth_guard_reason(unchecked):
        return None
    n, unknown, pct = unchecked["wallets"], unchecked["share_unknown_wallets"], unchecked["supply_pct"]
    rows = unchecked.get("checked_rows") or []
    supply_bar = COHORT_MIN_SUPPLY_PCT - pct if not unknown and pct < COHORT_MIN_SUPPLY_PCT else -math.inf  # a window's share is never below 0
    found = detect_cohorts(rows, window_s=COHORT_WINDOW_S, min_wallets=COHORT_MIN_WALLETS - n, min_supply_pct=supply_bar, floor_wallets=COHORT_MIN_WALLETS_FLOOR - n)
    if not found:
        return None
    window, share_of = found[0], {r["wallet"]: r.get("supply_pct") for r in rows}
    known = [share_of[w] for w in window["members"] if isinstance(share_of[w], (int, float)) and not isinstance(share_of[w], bool)]

    def share(total: float, unknown_n: int, count: int, unit: str) -> str:  # depth_guard_reason's wording: an unknown share is never 0
        shown = f"{round(total, 2)}%" if round(total, 2) > 0 or not total else "under 0.01%"
        return "supply share unknown" if unknown_n >= count else f"at least {shown}{unit}, share unknown for {unknown_n}" if unknown_n else f"{shown}{unit}"

    k = window["wallets"]
    who = f"{k} checked holders funded within {COHORT_WINDOW_S / 3600:g} h" if k > 1 else "1 checked holder"
    ranks = f"{unchecked['first']}" if unchecked["first"] == unchecked["last"] else f"{unchecked['first']}-{unchecked['last']}"
    return (f"{DEPTH_GUARD_START} {unchecked['checked']} holders only; {who} ({share(sum(known), k - len(known), k, ' of supply')}) "
            f"plus {n} unchecked ranked {ranks} ({share(pct, unknown, n, '')}) may be a split cohort")


def detector_status(funders: dict[str, Any] | None, provider_cohorts: dict[str, dict[str, Any]] | None = None) -> list[dict[str, str]]:
    """Which detectors ran. state: ran | partial | not_run | unavailable."""
    rows: list[dict[str, str]] = []
    if not funders:
        state, detail = "not_run", "holders-only command, funders step not run"
    elif not funders.get("with_funder"):
        state, detail = "unavailable", "no wallet returned a funding record"
    elif funders.get("aborted"):
        state, detail = "partial", f"run stopped early: {funders['aborted']}"
    else:
        state, detail = "ran", f"funder found for {funders['with_funder']} wallets"
    rows.append({"name": "funder-batch (per funder, 300 s tight window)", "state": state, "detail": detail})
    cohorts = (funders or {}).get("cohorts")
    if not funders:
        cstate, cdetail = "not_run", "funders step not run"
    elif not funders.get("with_funder"):
        cstate, cdetail = "unavailable", "no wallet returned a funding record"
    elif cohorts is None:
        cstate, cdetail = "not_run", "no cohort result in the funders output"
    else:
        cstate = "partial" if funders.get("aborted") else "ran"
        found = len((cohorts or {}).get("cohorts", []))
        cdetail = f"Helius funded-by rows: {cohorts['coverage']['with_funding_time'] if cohorts else 0}; {_plural(found, 'cohort')} flagged"
    rows.append({"name": "funding-time cohort (all funders, labeled included)", "state": cstate, "detail": cdetail})
    for src, res in (provider_cohorts or {}).items():
        cov = res["coverage"]
        rows.append(
            {
                "name": f"cohort over {src.upper()} rows (top 100 only, cannot clear the rest)",
                "state": "ran" if cov["with_funding_time"] else "unavailable",
                "detail": f"{cov['with_funding_time']} of {cov['rows']} rows have a funding time, {coverage_share_text(cov)}; {_plural(len(res['cohorts']), 'cohort')} flagged",
            }
        )
    if not funders:
        astate, adetail = "not_run", "funders step not run"
    elif funders.get("acquisition_supplied") or any(any(c["acquisition"]["ran"] for c in r["cohorts"]) for r in (provider_cohorts or {}).values()):
        ran_any = any(c["acquisition"]["ran"] for c in (cohorts or {}).get("cohorts", [])) or any(c["acquisition"]["ran"] for r in (provider_cohorts or {}).values() for c in r["cohorts"])
        astate, adetail = ("ran", "per-wallet acquisition timestamps checked") if ran_any else ("ran", "timestamps supplied; no flagged cohort had any")
    else:
        astate, adetail = "not_run", "no --acquisition-json and no GMGN rows"
    rows.append({"name": "acquisition-time check", "state": astate, "detail": adetail})
    return rows


def _num(value: Any, lo: float = 0.0, hi: float = 100.0) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != value:
        return None
    return float(value) if lo <= value <= hi else None


UNITS = ("percent", "fraction")


def normalize_finding(raw: Any, default_unit: str | None = None) -> dict[str, Any] | None:
    """Provider finding in the common schema, always in PERCENT. A finding's own `unit` ("percent" or "fraction")
    wins over `default_unit`; fractions are converted. Without any unit, values are taken as percent (callers
    that read files use normalize_findings_file, which rejects ambiguous input). Provider text is untrusted.

    A share or age field that is PRESENT and non-null but not a number, or outside its valid range for its unit,
    raises ConfigError: an unreadable value must never turn into "no alarm". The cluster sum must also be at least
    the largest cluster (a smaller sum means mixed units). An `ok` finding with no readable value at all becomes
    `unavailable` and is flagged `unreadable`, so it never counts as a source."""
    if not isinstance(raw, dict):
        return None
    status = raw.get("status")
    unit = raw.get("unit") if raw.get("unit") in UNITS else default_unit
    scale = 100.0 if unit == "fraction" else 1.0
    name = safe_label(raw.get("provider")) or "unnamed_provider"

    def field(key: str, hi: float, mult: float = 1.0) -> float | None:
        value = raw.get(key)
        if value is None:
            return None
        v = _num(value, 0.0, hi)
        if v is None:
            raise ConfigError(f"provider {name}: {key} is not a number in range 0 to {hi:g}{' (unit ' + unit + ')' if unit else ''}")
        return round(v * mult, 6)

    top = 1.0 if unit == "fraction" else 100.0
    largest, total, bundle = field("largest_cluster_pct", top, scale), field("cluster_sum_pct", top, scale), field("bundle_pct", top, scale)
    age = field("data_age_min", 10**7)
    if largest is not None and total is not None and total + 1e-6 < largest:
        raise ConfigError(f"provider {name}: cluster_sum_pct is smaller than largest_cluster_pct (mixed units?)")
    status = status if status in PROVIDER_STATUSES else "unavailable"
    hint = safe_label(raw.get("alarm_hint"))
    detail = safe_label(raw.get("detail")) or ""
    unreadable = False
    if status == "ok" and largest is None and total is None and bundle is None and not hint:
        status, unreadable, detail = "unavailable", True, "answered but unreadable: no usable value"
    return {
        "provider": name,
        "status": status,
        "largest_cluster_pct": largest,
        "cluster_sum_pct": total,
        "bundle_pct": bundle,
        "data_age_min": age,
        "detail": detail,
        "unreadable": unreadable,
        # optional: a sub-metric that contradicts the provider's own low label (OKX on CAPE: same-fund-source 0.947
        # while its headline said Low). Raises UNRESOLVED at least; never counts as an all-clear.
        "alarm_hint": hint,
    }


def _fold_provider_name(name: str) -> str:
    """Unicode compatibility folding as in NFKC (full-width, mathematical, circled and other compatibility forms to plain
    letters), done through NFKD, which also splits an accented letter into the letter and its accent mark; then look-alike
    letters mapped to Latin (before and after casefolding, so a capital look-alike keeps its Latin case). The accent marks
    and invisible format characters (zero-width, soft hyphen) then go with every other non-letter in the letters-and-digits
    filter of presentation_only_provider (accent folding). NFKC first would change nothing here: NFKD applies the same
    compatibility mapping."""
    return unicodedata.normalize("NFKD", name).translate(PROVIDER_LOOKALIKES).casefold().translate(PROVIDER_LOOKALIKES)


def presentation_only_provider(name: Any) -> str | None:
    """The presentation-only provider a --providers-json provider name refers to, or None. Case, spaces and punctuation
    are ignored and the full name is searched (before any shortening), so "Solana Tracker", "solana_tracker",
    "SOLANA-TRACKER (bundlers)" and "SolanaTracker" are all recognised. HS-PROV-T2: the name is folded first
    (_fold_provider_name: compatibility forms, accents, Cyrillic / Greek / small-capital look-alikes), and a second
    pass reads digits and signs used as letters, a capital I used as l and "rn" used as m, and a third collapses repeated
    letters ("Fommo"); the aliases "Sol Tracker" / "Solana Track" count anywhere in the name, the bare abbreviations ST
    and MOS as a separate word or the whole name (never inside a longer word, never after collapsing: "Moss" passes)."""
    if not isinstance(name, str):
        return None
    folded = _fold_provider_name(name)
    tokens = (*PRESENTATION_ONLY_PROVIDERS.items(), *PRESENTATION_ONLY_ALIASES.items())
    signed = folded.translate(PROVIDER_LOOKALIKE_SIGNS)
    plain = re.sub(r"[^0-9a-z]", "", folded)
    signs = re.sub(r"[^0-9a-z]", "", signed).replace("rn", "m").replace("i", "l")
    for key in (plain, signs):
        label = next((label for token, label in tokens if token in key), None) or PRESENTATION_ONLY_ABBREVIATIONS.get(key)
        if label:
            return label
    for key in (plain, signs):  # repeated letters collapsed ("Fommo", "Maddeonsol"); none of the tokens has a doubled letter
        collapsed = re.sub(r"(.)\1+", r"\1", key)
        label = next((label for token, label in tokens if token in collapsed), None)
        if label:
            return label
    words = {re.sub(r"[^0-9a-z]", "", word) for text in (folded, signed) for word in PROVIDER_NAME_WORD_SPLIT.split(text)}
    return next((PRESENTATION_ONLY_ABBREVIATIONS[word] for word in sorted(words) if word in PRESENTATION_ONLY_ABBREVIATIONS), None)


def normalize_findings_file(data: Any) -> list[dict[str, Any]]:
    """Findings from a --providers-json payload: a list, or {"unit": ..., "providers": [...]}.

    Units are explicit: each finding or the file must say "percent" or "fraction". A finding with no unit (and no file
    unit) that carries ANY non-zero share value <= 1 is ambiguous (0.3 could be 0.3% or 30%, and one field may be a
    fraction while another is percent) and is REJECTED, never guessed. Provider names must be unique, and the name
    reserved for the --bubblemaps-json step cannot be used here, nor can a presentation-only provider (Solana Tracker,
    MadeOnSol, Fomo API): its numbers are shown by the synthesis and must never count toward NO_ALARM."""
    file_unit = data.get("unit") if isinstance(data, dict) else None
    if file_unit is not None and file_unit not in UNITS:
        raise ConfigError('--providers-json unit must be "percent" or "fraction"')
    rows = data.get("providers") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise ConfigError("--providers-json must hold a JSON list of findings")
    keys = ("largest_cluster_pct", "cluster_sum_pct", "bundle_pct")
    seen: set[str] = set()
    for r in rows:
        if not isinstance(r, dict):
            continue
        refused = presentation_only_provider(r.get("provider"))
        if refused:
            raise ConfigError(f"--providers-json cannot supply {refused}: it is a presentation-only provider, shown by the synthesis next to the FLAGs and never an engine input")
        name = (_label_chars(r.get("provider")) or "unnamed_provider").lower()  # identity: the same name as before HS-LABELS-T1
        shown = pw.neutral(name)  # a provider name printed in an error line has its verdict words removed too
        if name in RESERVED_PROVIDERS:
            raise ConfigError(f"--providers-json cannot supply {shown}; that name is reserved for --bubblemaps-json")
        if name in seen:
            raise ConfigError(f"--providers-json lists provider {shown} twice; each provider must appear once")
        seen.add(name)
        if r.get("unit") not in UNITS and file_unit is None:
            small = [v for k in keys if isinstance((v := r.get(k)), (int, float)) and not isinstance(v, bool) and 0 < v <= 1]
            if small:
                raise ConfigError(f'--providers-json is ambiguous for {shown}: no "unit" and a share is <= 1; add "unit": "percent" or "fraction"')
    return [f for f in (normalize_finding(r, file_unit) for r in rows) if f is not None]


def bubblemaps_finding(map_result: Any, mint: str | None = None, extra_age_min: float = 0.0) -> dict[str, Any]:
    """Turn bubblemaps_map.py JSON into a finding. A map that could not be read is unavailable, an empty parse is
    empty (unknown), never zero clusters. `extra_age_min` is how old the saved file is on top of the page's age pill."""
    base = {"provider": "bubblemaps_map", "largest_cluster_pct": None, "cluster_sum_pct": None, "bundle_pct": None, "data_age_min": None}
    if not isinstance(map_result, dict):
        return {**base, "status": "unavailable", "detail": "map result is not a JSON object"}
    if mint and map_result.get("mint") != mint:
        return {**base, "status": "unavailable", "detail": "map result is for a different mint"}
    if not map_result.get("parse_ok"):
        return {**base, "status": "unavailable", "detail": "parse_ok false: the page layout may have changed; this is not zero clusters"}
    age = _num(map_result.get("age_min_after"), 0.0, 10**7)
    base["data_age_min"] = None if age is None else round(age + max(extra_age_min, 0.0), 1)
    raw_clusters = map_result.get("clusters")
    if raw_clusters is not None and not isinstance(raw_clusters, list):
        return {**base, "status": "unavailable", "detail": "clusters field is not a list; map not readable"}
    shares = []
    for entry in raw_clusters or []:
        v = _num(entry.get("supply_pct")) if isinstance(entry, dict) else None
        if v is None:
            return {**base, "status": "unavailable", "detail": "a cluster has a non-numeric or out-of-range supply_pct; map not readable"}
        shares.append(v)
    note = "" if map_result.get("refresh_effective") else "refresh not confirmed; map may be stale"
    if not shares:
        return {**base, "status": "empty", "detail": "no clusters parsed (drained or empty map); unknown, not clean"}
    listed = [{"wallets": entry.get("wallets") if isinstance(entry.get("wallets"), int) and not isinstance(entry.get("wallets"), bool) else None, "supply_pct": v}
              for entry, v in zip(raw_clusters, shares)]
    return {**base, "status": "ok", "largest_cluster_pct": max(shares), "cluster_sum_pct": round(min(100.0, sum(shares)), 2), "detail": note,
            "clusters": listed[:LIST_CAP * 2], "cluster_count": len(listed), "refresh_effective": bool(map_result.get("refresh_effective"))}


# ----------------------------------------------------------------------------- Bubblemaps members and pre-refresh line (display only)
# HS-BM-MEMBERS-T1 (owner decisions 2026-10-20: "Show first, then count"; a stale map's pre-refresh cluster of 15%+ is
# "Show next to the FLAG", not counted). The saved map file can carry each cluster's member rows (bubblemaps_map.py) and
# the pre-refresh cluster sizes. Here the member rows are matched OFFLINE to full addresses from the run's holders.json
# (no network, no key, 0 credits) and shown with the claims the run folder already holds. Nothing here reaches
# finding_alarms, decide_verdict or flag_for: assessment.json `flag` and `verdict` are what they were without it.

MAP_SHOWN_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{3,10}\.\.\.[1-9A-HJ-NP-Za-km-z]{3,10}$")  # the same rule as bubblemaps_map.SHOWN_RE (a test pins it)
MAP_LABEL_STRIP = re.compile(r"[^\w .,:@&'\"()\-]")  # the same rule as bubblemaps_map.MAP_LABEL_STRIP (a test pins it)
MAP_SHARE_SHOWN_RE = re.compile(r"^(<\s?)?\d{1,3}(\.\d+)?%$")
MAP_MEMBER_KINDS = ("holder", "linking", "hidden")
MEMBER_RANK_DRIFT = 3          # rank_share: a holder within this many ranks of the map rank (when the exact rank does not fit)
MEMBER_SHARE_TOL_PCT = 0.05    # rank_share: share difference allowed, in percentage points
MEMBER_ROWS_SHOWN = 12         # holder rows printed per cluster before "and N more" (all are in assessment.json)
MEMBER_TAGS_SHOWN = 4          # tags printed per provider and member before "and N more"
BASE58_RE = re.compile(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$")


def _saved_member(raw: Any) -> dict[str, Any] | None:
    """One member row read back from a saved map file (untrusted): only the fields bubblemaps_map.py writes, re-checked
    (rank a whole number, share a number 0-100, a shown address base58 around "...", a label made inert again). None when
    it is not such a row."""
    if not isinstance(raw, dict) or raw.get("kind") not in MAP_MEMBER_KINDS:
        return None
    rank, share, shown = raw.get("rank"), raw.get("share_pct"), raw.get("shown")
    if rank is not None and not (_is_int(rank) and 0 < rank <= 1_000_000):
        return None
    if share is not None and _num(share) is None:
        return None
    if shown is not None and not (isinstance(shown, str) and MAP_SHOWN_RE.match(shown)):
        return None
    shown_share = raw.get("share_shown")
    row = {"rank": rank, "shown": shown, "label": None if shown else pw.label(raw.get("label"), MAP_LABEL_STRIP, 40),
           "share_pct": None if share is None else float(share), "share_shown": shown_share if isinstance(shown_share, str) and MAP_SHARE_SHOWN_RE.match(shown_share) else None,
           "share_lt": raw.get("share_lt") is True, "kind": raw["kind"]}
    if raw["kind"] == "linking":
        row["linking_icon"] = raw.get("linking_icon") if raw.get("linking_icon") in ("wand", "clock") else None
    return row


def _saved_map_clusters(raw: Any) -> list[dict[str, Any]] | None:
    """Clusters (with their member rows, when read) from a saved map file list; None when the list is not readable."""
    if not isinstance(raw, list):
        return None
    out = []
    for c in raw:
        if not isinstance(c, dict) or not _is_int(c.get("cluster")) or _num(c.get("supply_pct")) is None:
            return None
        wallets = c.get("wallets") if _is_int(c.get("wallets")) else None
        entry: dict[str, Any] = {"cluster": c["cluster"], "wallets": wallets, "supply_pct": float(c["supply_pct"])}
        members = c.get("members")
        if isinstance(members, list):
            rows = [_saved_member(m) for m in members]
            entry["members"] = [r for r in rows if r is not None]
            entry["refused_rows"] = sum(1 for r in rows if r is None)
            entry["members_complete"] = c.get("members_complete") is True and not entry["refused_rows"]
        else:
            entry["members"] = None
            entry["members_complete"] = False
        if c.get("members_note"):
            entry["members_note"] = clean_text(c["members_note"], 240)
        out.append(entry)
    return out


def holder_index(holders: Any) -> list[tuple[int, str, float]]:
    """(rank, wallet, share %) for every holder in rank order, pools included (the rank holders.json uses): the in-memory
    full ranking when present, else holders.json `top_holders`, then the rest of `owner_balances`. Only base58 wallets."""
    if not isinstance(holders, dict):
        return []
    ranked = holders.get("_ranked")
    if isinstance(ranked, list) and ranked:
        return [(i, o, float(s)) for i, (o, s) in enumerate(ranked, 1) if isinstance(o, str) and BASE58_RE.match(o)]
    rows = [(r["rank"], r["wallet"], float(r["share_pct"])) for r in holders.get("top_holders") or []
            if isinstance(r, dict) and _is_int(r.get("rank")) and isinstance(r.get("wallet"), str) and BASE58_RE.match(r["wallet"])
            and isinstance(r.get("share_pct"), (int, float)) and not isinstance(r.get("share_pct"), bool)]
    balances = holders.get("owner_balances")
    if isinstance(balances, dict):
        vals = {o: float(v) for o, v in balances.items() if isinstance(o, str) and isinstance(v, (int, float)) and not isinstance(v, bool) and v >= 0}
        total = sum(vals.values())
        if total > 0:
            seen = {w for _, w, _ in rows}
            rows += [(i, o, round(v / total * 100, 4)) for i, (o, v) in enumerate(sorted(vals.items(), key=lambda kv: -kv[1]), 1)
                     if o not in seen and BASE58_RE.match(o)]
    return rows


def resolve_members(groups: list[list[dict[str, Any]]], holders: Any) -> None:
    """Match each holder row of the given member lists to a full address from holders.json, in place, and record how.

    1. prefix_suffix: a row with a shown short address ("DuARUp...c6s6") matches the ONE holder whose address starts and
       ends that way; two or more is ambiguous, none is no match (both stay unresolved; a row with a shown address is
       never matched by rank).
    2. rank_share, for rows shown by a label only: the holder at exactly the map rank whose share is within
       MEMBER_SHARE_TOL_PCT points, else the ONE such holder within MEMBER_RANK_DRIFT ranks; holders already matched by
       their shown address are excluded. Two or more candidates, or none, stay unresolved.
    Unresolved rows keep the shown text and the reason. Never a guess."""
    index = holder_index(holders)
    rows = [m for g in groups for m in g if m.get("kind") == "holder"]
    claimed: set[str] = set()
    for m in rows:
        m.update(address=None, method=None, helius_rank=None, unresolved=None)
        if not index:
            m["unresolved"] = "no holders.json holder list to match against"
        elif m.get("shown"):
            head, tail = m["shown"].split("...", 1)
            hits = [(r, w) for r, w, _ in index if w.startswith(head) and w.endswith(tail)]
            if len(hits) == 1:
                m.update(address=hits[0][1], method="prefix_suffix", helius_rank=hits[0][0])
                claimed.add(hits[0][1])
            else:
                m["unresolved"] = f"{len(hits)} holders show as {m['shown']}" if hits else f"no holder in holders.json shows as {m['shown']}"
    for m in rows:
        if not index or m.get("shown") or m["address"]:
            continue
        rank, share = m.get("rank"), m.get("share_pct")
        if rank is None or share is None:
            m["unresolved"] = "the map row has no rank or no share to match by"
            continue

        def fits(s: float, share: float = share, upper: bool = bool(m.get("share_lt"))) -> bool:
            return s <= share + MEMBER_SHARE_TOL_PCT + 1e-9 if upper else abs(s - share) <= MEMBER_SHARE_TOL_PCT + 1e-9

        exact = [(r, w) for r, w, s in index if r == rank and fits(s) and w not in claimed]
        near = exact or [(r, w) for r, w, s in index if abs(r - rank) <= MEMBER_RANK_DRIFT and fits(s) and w not in claimed]
        if len(near) == 1:
            m.update(address=near[0][1], method="rank_share", helius_rank=near[0][0])
            claimed.add(near[0][1])
        else:
            what = f"rank #{rank} (+-{MEMBER_RANK_DRIFT}) and share {share:g}% (+-{MEMBER_SHARE_TOL_PCT:g} points)"
            m["unresolved"] = f"{len(near)} holders fit {what}" if near else f"no holder fits {what}"


def wallet_claims(gmgn_payload: Any = None, jupiter_payload: Any = None, funders: dict[str, Any] | None = None) -> dict[str, dict[str, Any]]:
    """Per wallet, the claims the run folder already holds: GMGN tags (`maker_token_tags`, `tags`), Jupiter tags and the
    Helius first funder's name. Provider text: short inert labels (safe_label), in the provider's order."""
    out: dict[str, dict[str, Any]] = {}
    for key, payload, fields in (("gmgn", gmgn_payload, ("maker_token_tags", "tags", "maker_tags")), ("jupiter", jupiter_payload, ("tags", "holderTags", "walletCategories"))):
        for row in _unwrap(payload) if payload is not None else []:
            wallet = row.get("address") or row.get("wallet")
            if not isinstance(wallet, str):
                continue
            tags: list[str] = []
            for field in fields:
                value = row.get(field)
                for tag in value if isinstance(value, list) else []:
                    lab = safe_label(tag) if isinstance(tag, str) else None
                    if lab and lab.lower() not in tags:
                        tags.append(lab.lower())
            out.setdefault(wallet, {})[key] = tags
    for r in (funders or {}).get("rows") or []:
        if isinstance(r, dict) and r.get("status") == "funded" and isinstance(r.get("wallet"), str):
            funder = r.get("funder") if isinstance(r.get("funder"), str) and BASE58_RE.match(r["funder"]) else None
            out.setdefault(r["wallet"], {})["funder"] = pw.neutral(r.get("funder_name")) or (f"unlabeled {funder[:6]}..." if funder else "unlabeled")
    return out


def _bundler_counts(clusters: list[dict[str, Any]], claims: dict[str, dict[str, Any]], gmgn_read: bool) -> dict[str, Any] | None:
    """GMGN bundler claims against the map's clusters: per cluster (set on each cluster) and the bundler-tagged wallets
    outside every listed cluster. None when no GMGN rows were given."""
    if not gmgn_read:
        return None
    tagged = {w for w, c in claims.items() if "bundler" in (c.get("gmgn") or [])}
    inside: set[str] = set()
    unresolved = not_full = 0
    for c in clusters:
        not_full += 0 if c.get("members_complete") else 1
        if c.get("members") is None:
            continue
        holders = [m for m in c["members"] if m["kind"] == "holder"]
        found = {m["address"] for m in holders if m.get("address")}
        inside |= found
        c["gmgn_bundler"] = {"tagged": len(found & tagged), "holders": len(holders), "unresolved": sum(1 for m in holders if not m.get("address"))}
        unresolved += c["gmgn_bundler"]["unresolved"]
    return {"tagged_total": len(tagged), "outside": len(tagged - inside), "unresolved_holders": unresolved, "clusters_not_fully_read": not_full}


def _not_closed(map_raw: dict[str, Any]) -> dict[str, Any] | None:
    """Clusters the pre-refresh member read could not close before the refresh click (bubblemaps_map.py
    `members_before_not_closed`): an open cluster pushes others out of the rendered window, so the refreshed size read may
    list fewer clusters. Display only; None when there were none."""
    raw = map_raw.get("members_before_not_closed")
    numbers = [n for n in raw if _is_int(n)] if isinstance(raw, list) else []
    if not numbers:
        return None
    names = ", ".join(str(n) for n in numbers[:LIST_CAP]) + (f" and {len(numbers) - LIST_CAP} more" if len(numbers) > LIST_CAP else "")
    return {"clusters": numbers, "note": (f"the pre-refresh member read could not close Cluster {names} before the refresh, so the refreshed size read "
                                          "may list fewer clusters than the map has (display only, not in the verdict)")}


def _pre_refresh(map_raw: dict[str, Any], before: list[dict[str, Any]] | None) -> dict[str, Any] | None:
    """The pre-refresh line: only when the refresh was effective and the pre-refresh read had a largest cluster at or over
    CLUSTER_ALARM_PCT or clusters together at or over AGGREGATE_CLUSTER_ALARM_PCT. Display only, never counted."""
    if not map_raw.get("refresh_effective"):
        return None  # without an effective refresh the current clusters are the stale ones and count as before
    if before is None:
        return {"line": "Bubblemaps pre-refresh snapshot: unreadable in the saved map file; not in the verdict", "counted": False}
    if not before:
        return None
    big = max(before, key=lambda c: c["supply_pct"])
    total = round(min(100.0, sum(c["supply_pct"] for c in before)), 2)
    if big["supply_pct"] < CLUSTER_ALARM_PCT and total < AGGREGATE_CLUSTER_ALARM_PCT:
        return None
    after = _saved_map_clusters(map_raw.get("clusters")) or []
    after_big = max((c["supply_pct"] for c in after), default=None)
    after_total = round(min(100.0, sum(c["supply_pct"] for c in after)), 2) if after else None
    age = _num(map_raw.get("age_min_before"), 0.0, 10**7)
    wallets = f" ({big['wallets']} wallets)" if big.get("wallets") is not None else ""
    parts = [f"largest {big['supply_pct']:g}%{wallets}"]
    if total >= AGGREGATE_CLUSTER_ALARM_PCT:
        parts.append(f"all clusters together {total:g}%")
    now = "the refreshed map reads " + ("no clusters" if after_big is None else f"{after_big:g}%" + (f", together {after_total:g}%" if total >= AGGREGATE_CLUSTER_ALARM_PCT else ""))
    line = f"clear large cluster seen by Bubblemaps (pre-refresh snapshot, {'age unknown' if age is None else f'{age:.0f} min old'}): {'; '.join(parts)}; {now}; not in the verdict"
    read = [c for c in before if c.get("members") is not None]
    if read:
        line += "; its members are listed under Sources read, Bubblemaps free map"
    elif "members_before_reason" in map_raw:
        line += f"; its members were not read ({clean_text(map_raw.get('members_before_reason') or 'no reason given', 100)})"
    else:
        line += "; its members were not read (this map file was written before the member read)"
    not_closed = _not_closed(map_raw)
    if not_closed:
        line += f"; {not_closed['note']}"
    return {"line": line, "counted": False, "age_min": age, "largest_pct": big["supply_pct"], "largest_wallets": big.get("wallets"), "cluster_sum_pct": total,
            "refreshed_largest_pct": after_big, "refreshed_cluster_sum_pct": after_total, "clusters": read, "not_closed": not_closed}


def bubblemaps_display(map_raw: Any, mint: str, holders: Any = None, funders: dict[str, Any] | None = None, gmgn_payload: Any = None, jupiter_payload: Any = None) -> dict[str, Any] | None:
    """The display fields assess adds to assessment.json from the saved map file: `members` (each cluster's member rows,
    matched to full addresses, with GMGN / Jupiter / Helius claims) and `pre_refresh` (the pre-refresh line or None).
    None when no map file was given or it is for another mint. Offline and display only."""
    if not isinstance(map_raw, dict) or map_raw.get("mint") != mint:
        return None
    clusters = _saved_map_clusters(map_raw.get("clusters"))
    list_only = _saved_map_clusters(map_raw.get("clusters_list_only") or [])
    before = _saved_map_clusters(map_raw.get("clusters_before") if map_raw.get("clusters_before") is not None else [])
    claims = wallet_claims(gmgn_payload, jupiter_payload, funders)
    now_groups = [c["members"] for c in (clusters or []) + (list_only or []) if c.get("members")]
    before_groups = [c["members"] for c in before or [] if c.get("members")]
    resolve_members(now_groups, holders)
    resolve_members(before_groups, holders)  # the pre-refresh snapshot is matched on its own (a wallet can be in both)
    for g in now_groups + before_groups:
        for m in g:
            if m.get("address"):
                m["claims"] = claims.get(m["address"], {})
    if "members_parse_ok" not in map_raw:
        members: dict[str, Any] = {"read": False, "reason": "this map file was written before the member read and holds no member rows"}
    elif map_raw.get("members_parse_ok") is not True or clusters is None:
        members = {"read": False, "reason": clean_text(map_raw.get("members_reason") or "the member rows could not be read", 300)}
    else:
        members = {"read": True, "reason": clean_text(map_raw["members_reason"], 300) if map_raw.get("members_reason") else None,
                   "seconds": _num(map_raw.get("members_seconds"), 0.0, 10**4), "clusters": clusters, "list_only": list_only or [],
                   "gmgn_bundlers": _bundler_counts((clusters or []) + (list_only or []), claims, gmgn_payload is not None), "gmgn_read": gmgn_payload is not None}
    settle = {k: map_raw[k] for k in ("settle_s", "settle_list_changed_s") if _num(map_raw.get(k), 0.0, 10**4) is not None}
    if map_raw.get("settle_note"):
        settle["settle_note"] = clean_text(map_raw["settle_note"], 240)
    if settle:
        members["settle"] = settle
    not_closed = _not_closed(map_raw)
    if not_closed:  # shown whenever present, whatever the member read and the pre-refresh line say
        members["pre_refresh_not_closed"] = not_closed
    return {"members": members, "pre_refresh": _pre_refresh(map_raw, before)}


def finding_alarms(f: dict[str, Any]) -> list[str]:
    """Alarm reasons from one finding. Data of any age can alarm; only status ok can."""
    if f.get("status") != "ok":
        return []
    out = []
    if (f.get("largest_cluster_pct") or 0) >= CLUSTER_ALARM_PCT:
        out.append(f"largest cluster {f['largest_cluster_pct']:g}% >= {CLUSTER_ALARM_PCT:g}%")
    if (f.get("cluster_sum_pct") or 0) >= AGGREGATE_CLUSTER_ALARM_PCT:
        out.append(f"clusters together hold {f['cluster_sum_pct']:g}% >= {AGGREGATE_CLUSTER_ALARM_PCT:g}%")
    if (f.get("bundle_pct") or 0) >= BUNDLE_ALARM_PCT:
        out.append(f"bundles {f['bundle_pct']:g}% >= {BUNDLE_ALARM_PCT:g}%")
    return out


def is_young(token_age_h: float | None) -> bool:
    return token_age_h is None or token_age_h < YOUNG_TOKEN_MAX_AGE_H


def all_clear_counts(f: dict[str, Any], token_age_h: float | None) -> bool:
    """Does this finding's all-clear count toward NO_ALARM? Needs readable data, no alarm, and on a young token
    (or unknown age) data no older than STALE_ALL_CLEAR_MIN; an unreadable data age counts as stale."""
    if f.get("status") != "ok" or finding_alarms(f) or f.get("alarm_hint"):
        return False
    if is_young(token_age_h):
        age = f.get("data_age_min")
        return age is not None and age <= STALE_ALL_CLEAR_MIN
    return True


def apply_disagreement(findings: list[dict[str, Any]], own_verdict: str) -> dict[str, Any]:
    """Cross-provider disagreement rule (pure). own_verdict is this skill's own level: HIGH, UNRESOLVED, LIMITED or
    NO_ALARM (NO_ALARM here means the own detectors ran and found nothing). Returns level HIGH or UNRESOLVED,
    naming the alarming provider(s) and whoever disagrees, or level None when no provider alarms. A provider
    `alarm_hint` (a contradicting sub-metric) raises UNRESOLVED at least, whatever the provider's own label says."""
    alarming = [{"provider": f["provider"], "reasons": finding_alarms(f)} for f in findings if finding_alarms(f)]
    hinted = [f for f in findings if f.get("status") == "ok" and f.get("alarm_hint") and not finding_alarms(f)]
    hint_reasons = [f"{finding_text(f, 'provider', 40)} alarm hint: {finding_text(f, 'alarm_hint', 60)} (the provider's own headline may disagree)" for f in hinted]
    if not alarming and not hinted:
        return {"level": None, "alarming": [], "disagreeing": [], "reasons": []}
    if not alarming:
        return {"level": VERDICT_UNRESOLVED, "alarming": [f["provider"] for f in hinted], "disagreeing": [], "reasons": hint_reasons}
    names = [a["provider"] for a in alarming]
    calm = [f["provider"] for f in findings if f.get("status") == "ok" and not finding_alarms(f) and not f.get("alarm_hint")]
    if own_verdict == VERDICT_NO_ALARM:
        calm.insert(0, "own detectors")
    if own_verdict == VERDICT_HIGH or not calm:
        level = VERDICT_HIGH
        reasons = [f"{a['provider']} alarms: {'; '.join(a['reasons'])}" for a in alarming]
    else:
        level = VERDICT_UNRESOLVED
        reasons = [f"{a['provider']} alarms ({'; '.join(a['reasons'])}) while {', '.join(calm)} report no alarm" for a in alarming]
    return {"level": level, "alarming": names, "disagreeing": calm if level == VERDICT_UNRESOLVED else [], "reasons": reasons + hint_reasons}


def own_detector_level(coverage: dict[str, Any], detectors: list[dict[str, str]], own_alarms: list[str], own_unresolved: list[str] | None = None) -> str:
    """This skill's own detectors only: HIGH if they alarmed, NO_ALARM if the cohort detector completed with
    enough coverage and found nothing, else LIMITED. The DS-DEPTH-GUARD-T1 depth guard is deliberately not applied here:
    this level feeds the disagreement rule, and a provider alarm must read exactly as before (raised flags unchanged)."""
    if own_alarms:
        return VERDICT_HIGH
    if own_unresolved:
        return VERDICT_UNRESOLVED
    cohort_ran = any(d["name"].startswith("funding-time cohort") and d["state"] == "ran" for d in detectors)
    if cohort_ran and not coverage["aborted"] and not coverage.get("truncated") and coverage.get("pool_exclusion_reliable", True) and coverage["covered_noninfra_pct"] >= COVERAGE_MIN_SUPPLY_PCT:
        return VERDICT_NO_ALARM
    return VERDICT_LIMITED


def decide_verdict(
    coverage: dict[str, Any],
    detectors: list[dict[str, str]],
    own_alarms: list[str],
    findings: list[dict[str, Any]] | None = None,
    *,
    token_age_h: float | None = None,
    required: tuple[str, ...] = (),
    own_unresolved: list[str] | None = None,
    unchecked: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """HIGH / UNRESOLVED / LIMITED / NO_ALARM. Unknown is never safe: NO_ALARM needs all of coverage >=
    COVERAGE_MIN_SUPPLY_PCT, a completed cohort detector, every `required` provider returning readable data,
    and MIN_CLUSTER_SOURCES independent cluster-capable sources whose all-clear counts (the own cohort detector
    is one), with no alarm anywhere. A provider alarm always surfaces as HIGH or UNRESOLVED. DS-DEPTH-GUARD-T1:
    `unchecked` (unchecked_listed) also blocks NO_ALARM when the listed holders funded-by did not check could hide a
    cohort (depth_guard_reason); it is read only after the HIGH / UNRESOLVED returns, so it never moves a raised flag.
    DS-SPLIT-GUARD-T1: when that tail alone is under the bar, a cohort split across the depth (checked wallets of one
    detector window plus the unchecked holders) blocks NO_ALARM the same way (split_guard_reason)."""
    findings = findings or []
    own = own_detector_level(coverage, detectors, own_alarms, own_unresolved)
    alarms = list(own_alarms)
    dis = apply_disagreement(findings, own)
    if own == VERDICT_HIGH or dis["level"] == VERDICT_HIGH:
        return {"level": VERDICT_HIGH, "reasons": alarms + list(own_unresolved or []) + dis["reasons"], "sources_counted": [], "no_alarm_blockers": [], "disagreement": dis}
    if dis["level"] == VERDICT_UNRESOLVED or own_unresolved:
        return {"level": VERDICT_UNRESOLVED, "reasons": list(own_unresolved or []) + dis["reasons"], "sources_counted": [], "no_alarm_blockers": [], "disagreement": dis}
    blockers: list[str] = []
    cohort_ran = any(d["name"].startswith("funding-time cohort") and d["state"] == "ran" for d in detectors)
    if not cohort_ran:
        blockers.append("funding-time cohort detector did not complete")
    if coverage["aborted"]:
        blockers.append(f"funder lookups stopped early ({coverage['aborted']})")
    if coverage.get("truncated"):
        blockers.append("the holder list was truncated; shares and coverage are incomplete")
    if not coverage.get("pool_exclusion_reliable", True):
        blockers.append("pool exclusion unreliable (pool owner not matched or Dexscreener lookup failed); coverage may be inflated or understated")
    depth = depth_guard_reason(unchecked) or split_guard_reason(unchecked)
    if depth:
        blockers.append(depth)
    if coverage["covered_noninfra_pct"] < COVERAGE_MIN_SUPPLY_PCT:
        blockers.append(f"only {coverage['covered_noninfra_pct']}% of the supply held by ordinary wallets was checked; at least {COVERAGE_MIN_SUPPLY_PCT:g}% is needed")
    by_name = {f["provider"]: f for f in findings}
    for name in required:
        f = by_name.get(name)
        if f is None or f["status"] == "skipped":
            blockers.append(f"{name} step did not run; the verdict cannot exceed LIMITED")
        elif f["status"] != "ok":
            blockers.append(f"{name} returned no usable data ({f['status']}); the verdict cannot exceed LIMITED")
    sources = ["own funding-time cohort detector"] if cohort_ran else []
    for f in findings:
        if f.get("largest_cluster_pct") is None or f.get("status") != "ok":
            continue
        if all_clear_counts(f, token_age_h):
            sources.append(f["provider"])
        else:
            blockers.append(f"{f['provider']} all-clear not counted: data age {_none(f.get('data_age_min'))} min on a young token (must be at most {STALE_ALL_CLEAR_MIN:g} min old)")
    if len(sources) < MIN_CLUSTER_SOURCES:
        blockers.append(f"{len(sources)} independent cluster-capable source(s) with a countable all-clear; {MIN_CLUSTER_SOURCES} are needed")
    if blockers:
        return {"level": VERDICT_LIMITED, "reasons": blockers, "sources_counted": sources, "no_alarm_blockers": blockers, "disagreement": dis}
    return {"level": VERDICT_NO_ALARM, "reasons": ["no detector alarmed; this is not proof of independent holders"], "sources_counted": sources, "no_alarm_blockers": [], "disagreement": dis}


def token_age_hours(holders: dict[str, Any], now: float | None = None) -> float | None:
    launch = holders.get("earliest_pair_created_at")
    if not isinstance(launch, int):
        return None
    return max(0.0, ((now if now is not None else time.time()) - launch) / 3600)


def assess(
    holders: dict[str, Any],
    funders: dict[str, Any] | None,
    findings: list[dict[str, Any]] | None = None,
    *,
    now: float | None = None,
    provider_cohorts: dict[str, dict[str, Any]] | None = None,
    solscanner: dict[str, Any] | None = None,
    bubblemaps_members: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Coverage block + detector status + verdict for one run. Pure; consumes only data already collected.
    `findings` are normalized provider rows (Bubblemaps map first). A required provider with no row is recorded as skipped.
    `bubblemaps_members` (bubblemaps_display's result) is display only: it is copied into the result as the
    `bubblemaps_members` and `bubblemaps_pre_refresh` fields and never reaches the verdict or the flag."""
    cov = coverage_block(holders, funders)
    detectors = detector_status(funders, provider_cohorts)
    rows = list(findings or [])
    present = {f["provider"] for f in rows}
    for name in REQUIRED_PROVIDERS:
        if name not in present:
            rows.insert(0, {"provider": name, "status": "skipped", "largest_cluster_pct": None, "bundle_pct": None, "data_age_min": None, "detail": "no --bubblemaps-json given, so the step did not run"})
    own_alarms: list[str] = []
    if funders and funders["verdict"]["level"] in ("STRONG", "WEAK"):
        v = funders["verdict"]
        own_alarms.append(f"funder-batch FACTORY_PATTERN {v['level']}: {v['batch_funders']} unlabeled funders, {v['share_pct']}% of supply")
    sources = {"helius": (funders or {}).get("cohorts")} | dict(provider_cohorts or {})
    own_unresolved: list[str] = []
    for src, res in sources.items():
        for c in (res or {}).get("cohorts", []):
            text = (
                f"funding-time cohort ({src}): {c['wallets']} wallets, {share_text(c)}, first funded within {c['window_s'] / 3600:.1f} h "
                f"via {funder_text(c)}, {labeled_funder_text(c, 'through')}"
            )
            signs = "; ".join(cohort_signs(c).values())
            if signs:
                text += f"; signs: {signs}"
            if c.get("severity") == VERDICT_UNRESOLVED:
                own_unresolved.append(f"{text}; UNRESOLVED, not HIGH: {c['severity_reason']}")
            else:
                own_alarms.append(text)
    age_h = token_age_hours(holders, now)
    verdict = decide_verdict(cov, detectors, own_alarms, rows, token_age_h=age_h, required=REQUIRED_PROVIDERS, own_unresolved=own_unresolved,
                             unchecked=unchecked_listed(holders, funders))
    out = {"verdict": verdict, "flag": flag_for(verdict, rows), "sources": read_sources(holders, funders, rows, provider_cohorts, solscanner), "coverage": cov, "detectors": detectors, "findings": rows, "cohort_sources": {k: {"coverage": v["coverage"], "cohorts": len(v["cohorts"])} for k, v in sources.items() if v}, "token_age_h": None if age_h is None else round(age_h, 2)}
    if bubblemaps_members is not None:  # HS-BM-MEMBERS-T1: display fields, added after the verdict and the flag are fixed
        out["bubblemaps_members"] = bubblemaps_members["members"]
        out["bubblemaps_pre_refresh"] = bubblemaps_members["pre_refresh"]
    return out


# ----------------------------------------------------------------------------- evidence: flag, sources read, summary (presentation)
# The tool presents EVIDENCE; the owner decides. The flag is a plain mapping of the underlying level and never
# changes a gating or disagreement rule: HIGH -> DANGER FLAG, UNRESOLVED -> CAUTION, LIMITED/NO_ALARM -> no flag.


def flag_for(verdict: dict[str, Any], findings: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Presentation mapping only; the underlying level and every gating rule are unchanged.

    HIGH is a DANGER FLAG. UNRESOLVED is CAUTION, EXCEPT when a cluster-grade provider finding (largest cluster,
    clusters together, or bundle share at or over its alarm bar) is present: owner rule, clear large clusters mean a
    dangerous token, and a calm reading from a source with known blind spots (GMGN tags caught about 0.8% of CAPE's
    17% farm) does not cancel it. The flag then names the disagreement. A SolScanner hint, an alarm_hint-only finding,
    a single-sign cohort and stale or unknown conditions alone stay CAUTION."""
    level = verdict["level"]
    label = {VERDICT_HIGH: FLAG_DANGER, VERDICT_UNRESOLVED: FLAG_CAUTION}.get(level, FLAG_NONE)
    if level == VERDICT_UNRESOLVED and any(finding_alarms(f) for f in findings or []):
        calm = (verdict.get("disagreement") or {}).get("disagreeing") or []
        label = FLAG_DANGER + (f" (clear large cluster; sources disagree: {', '.join(_display_name(n) + ' reads calm' if n != 'own detectors' else 'own detectors read calm' for n in calm)})" if calm else " (clear large cluster)")
    why = [r for r in verdict.get("reasons", [])][:3] if level in (VERDICT_HIGH, VERDICT_UNRESOLVED) else []
    caveat = None
    if level == VERDICT_LIMITED:
        first = (verdict.get("reasons") or ["too little was checked"])[0]
        caveat = f"coverage is limited: {first}"
    elif level == VERDICT_NO_ALARM:
        caveat = "every required check ran and none alarmed; that is still not proof of independent holders"
    return {"label": label, "level": level, "why": why, "caveat": caveat}


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f\u0085\u2028\u2029]+")
_MD_START_RE = re.compile(r"^[\s#>*+|\-=`~]+")
TEXT_CAP = 120  # longest single free-text value printed into a report (presentation limit)


def clean_text(value: Any, cap: int = TEXT_CAP) -> str:
    """The one sanitizer for free text that comes from a saved input file or a provider before it is printed: no control
    characters or newlines (so no extra lines), no leading markdown heading, quote, table or bullet marks, capped."""
    text = _CONTROL_RE.sub(" ", str(value))
    text = _MD_START_RE.sub("", " ".join(text.split()))
    return text[:cap]


def _text_chars(text: str) -> str:
    """clean_text's character rule without its cut."""
    return _MD_START_RE.sub("", " ".join(_CONTROL_RE.sub(" ", text).split()))


def clean_provider_text(value: Any, cap: int = TEXT_CAP) -> str:
    """clean_text for PROVIDER text (HS-LABELS-T1): provider_words.cut() with clean_text's character rule, so the text is
    cut where clean_text cut it and then marked (a placeholder counts as the text it replaced; longer than `cap` only by
    the placeholders' extra length). Without a verdict word, HTML tag, entity, markdown link or bidi control the result is
    clean_text's exactly. This tool's own fixed wording keeps clean_text (finding_text decides for a finding)."""
    return pw.cut(str(value), _text_chars, cap, trim=False)


# SolScanner reason codes written by solscanner_scan.py (and this module): this tool's own fixed codes, printed as they are.
SOLSCANNER_OWN_REASONS = frozenset({"bundle_groups", "cache_hit", "expired_scan", "http_error", "identity_mismatch", "invalid_mint", "invalid_scan_time",
                                    "malformed_result", "malformed_sse", "missing_bundle_groups", "missing_scan_time", "missing_stale_status", "network_error",
                                    "non_sse_response", "provider_stale", "redirect_disallowed", "response_too_large", "scan_incomplete", "timeout",
                                    "not_cached_needs_login", "access_denied", "not_found", "rate_limited", "server_error"})


def finding_text(f: dict[str, Any], key: str, cap: int = TEXT_CAP) -> str:
    """A finding's provider name, detail or alarm hint for printing (HS-LABELS-T1 R1/R2). This tool's own findings (the
    reserved bubblemaps_map and solscanner rows, which --providers-json cannot supply, and the "skipped" row assess inserts)
    and the detail this module writes for an unreadable finding are this tool's own wording: printed with clean_text,
    never through the provider rule. Everything else is provider text: clean_provider_text."""
    own = f.get("provider") in RESERVED_PROVIDERS or (key == "detail" and f.get("unreadable"))
    return (clean_text if own else clean_provider_text)(f.get(key) or "", cap)


def _oneline(line: str) -> str:
    """Last guard over every rendered report line: control characters and newlines become spaces."""
    return _CONTROL_RE.sub(" ", line)


PROVIDER_PROSE = {"bubblemaps_map": "Bubblemaps map", "bubblemaps": "Bubblemaps", "solscanner": "SolScanner", "gmgn": "GMGN", "jupiter": "Jupiter",
                  "okx": "OKX", "insightx": "InsightX", "cabalspy": "CabalSpy", "helius": "Helius"}


def _none(value: Any) -> Any:
    """Print the word none, never Python's None, in tables and lines."""
    return "none" if value is None else value


def _short_reason(reason: str) -> str:
    """A reason cut down for the one-line 'Why' in the executive summary."""
    m = re.match(r"funding-time cohort \((\w+)\): (\d+ wallets), ([^,]+),", reason)
    if m:
        signs = re.search(r"signs: ([^;]+(?:; [^;]+)?)", reason)
        unresolved = " (UNRESOLVED)" if "UNRESOLVED, not HIGH" in reason else ""
        unknown = re.search(r"funder unknown for \d+ of \d+ wallets", reason)  # never hidden from the summary
        return (f"{_display_name(m.group(1))} cohort{unresolved}: {m.group(2)}, {m.group(3)}" + (f", {unknown.group(0)}" if unknown else "")
                + (f" ({signs.group(1)})" if signs and not unresolved else ""))
    return reason if len(reason) <= 110 else pw.keep_whole(reason, 107).rstrip() + "..."  # a placeholder is never cut


def _age_text(minutes: float | None, unknown: str = "age unknown") -> str:
    if minutes is None:
        return unknown
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{minutes:.0f} min old"
    if minutes < 48 * 60:
        return f"{minutes / 60:.1f} h old"
    return f"{minutes / 1440:.1f} days old"


def _capped(items: list[str], cap: int = LIST_CAP) -> list[str]:
    return items[:cap] + ([f"and {len(items) - cap} more"] if len(items) > cap else [])


def _cohort_one_liner(c: dict[str, Any]) -> str:
    return f"{c['wallets']} wallets, {share_text(c)}, {funder_text(c)}, {c.get('severity', '?')}"


def _cohort_source_lines(res: dict[str, Any] | None) -> list[str]:
    cohorts = (res or {}).get("cohorts", [])
    if not cohorts:
        return ["funding cohorts found: none"]
    return [f"funding cohorts found: {len(cohorts)}"] + [f"  cohort: {_cohort_one_liner(c)}" for c in cohorts[:3]] + ([f"  and {len(cohorts) - 3} more"] if len(cohorts) > 3 else [])


def _solscanner_source(result: dict[str, Any] | None, finding: dict[str, Any] | None) -> dict[str, Any]:
    block = {"key": "solscanner", "name": "SolScanner public scan", "status": "not run", "age": None, "lines": [],
             "cannot_see": "its bundle groups are broad and its risk score is noisy; corroboration only, never an all-clear; the scan's own funding fields are not kept"}
    if result is None:
        block["lines"] = ["not run (use --solscanner or --solscanner-json)"]
        return block
    groups = result.get("groups") or []
    reason = result.get("reason")
    if finding is not None and finding.get("status") == "unavailable":
        block.update(status="unavailable")
        shown = clean_text(reason, 40) if reason in SOLSCANNER_OWN_REASONS else clean_provider_text(reason or "unreadable result", 40)  # own codes as they are
        block["lines"] = [f"could not be read: {shown}"] + _solscanner_source_line(result)
        return block
    block["status"] = "read" if groups else "empty"
    age = finding.get("data_age_min") if finding and finding.get("data_age_min") is not None else result.get("scan_age_min")
    block["age"] = age
    flags = []
    label = None
    if result.get("is_stale") is True or reason == "provider_stale":
        flags.append("the provider marks it stale")
        label = "STALE"
    if reason == "expired_scan":
        import solscanner_scan as _ss0

        flags.append(f"older than {_ss0.SCAN_FRESH_SECONDS // 60} min")
        label = label or f"older than {_ss0.SCAN_FRESH_SECONDS // 60} min"
    elif reason in ("scan_incomplete", "invalid_scan_time", "missing_scan_time", "missing_stale_status"):
        flags.append(reason.replace("_", " "))
        label = label or reason.replace("_", " ")
    block["stale_label"] = label
    lines = [f"scan {_age_text(age)}" + (f" ({'; '.join(flags)})" if flags else "")]
    block["stale"] = bool(flags)
    block["stale_note"] = f"{_age_text(age)}" + (f"; {'; '.join(flags)}" if flags else "")
    if not groups:
        lines.append("no bundle groups listed (unknown, not a reassurance)")
    else:
        lines.append(f"{len(groups)} bundle group{'' if len(groups) == 1 else 's'} listed")
        biggest = max(min(100.0, sum(w.get("share_pct", 0.0) for w in g.get("wallets", []))) for g in groups)
        block["summary"] = f"{len(groups)} bundle group{'' if len(groups) == 1 else 's'}, largest {biggest:.1f}% of listed supply (broad groups, corroboration only)"
        rows = []
        for i, g in enumerate(groups, 1):
            share = min(100.0, sum(w.get("share_pct", 0.0) for w in g.get("wallets", [])))
            # SolScanner's confidence is one of low / medium / high (validated): printed in this tool's words, weak / medium / strong
            # (HS-LABELS-T1 R3); its bundle type is provider text (the rule)
            level = pw.level_text(g.get("confidence")) or pw.neutral(g.get("confidence")) or "n/a"
            rows.append(f"  group {i}: {len(g.get('wallets', []))} wallets, {share:.1f}% of listed supply, risk {g.get('risk_score', 'n/a')}, "
                        f"confidence {level}, type {pw.neutral(g.get('bundle_type')) or 'n/a'}")
        lines += _capped(rows, 5)
    lines.append("funding sources: not read (the scan's funding fields are not kept by this tool)")
    if finding and finding.get("alarm_hint"):
        import solscanner_scan as _ss

        hinting = [g for g in groups if type(g.get("risk_score")) is int and g["risk_score"] >= _ss.SOLSCANNER_HINT_MIN_RISK and g.get("confidence") == "high"
                   and min(100.0, sum(w.get("share_pct", 0.0) for w in g.get("wallets", []))) >= _ss.SOLSCANNER_HINT_MIN_SHARE_PCT]
        if hinting:
            g = max(hinting, key=lambda x: sum(w.get("share_pct", 0.0) for w in x.get("wallets", [])))
            share = min(100.0, sum(w.get("share_pct", 0.0) for w in g.get("wallets", [])))
            block["hint_text"] = (f"SolScanner (corroboration only): {len(groups)} bundle group{'' if len(groups) == 1 else 's'}, {len(g.get('wallets', []))} wallets, "
                                  f"{share:.0f}% of listed supply, risk {g['risk_score']}, scan {_age_text(age)}")
        lines.append("corroboration hint raised: " + block.get("hint_text", "SolScanner (corroboration only)"))
    block["lines"] = lines + _solscanner_source_line(result)
    return block


def _solscanner_source_line(result: dict[str, Any]) -> list[str]:
    """DS-SCANNER-FREE-T1: where the scan was read (the free keyless SolScanner endpoint or the owner's logged-in scanner.net
    page), as one display line built from validated codes; only for a result that carries the collector's source facts (an
    older saved result shows none). Display only: no verdict rule reads it."""
    import solscanner_scan as _ss

    text = _ss.source_text(result)
    return [text] if text else []


def removed_infrastructure_text(removed: dict[str, Any]) -> str:
    """HS-COHORT-POOLS-T1: the GMGN / Jupiter Sources-read line for the infrastructure rows removed before the cohort
    pass. An unknown share is never printed as 0."""
    n, unknown = removed.get("rows") or 0, removed.get("share_unknown_rows") or 0
    if not n:
        return "pools removed: none in these rows"
    if unknown >= n:
        share = "supply share unknown"
    elif unknown:
        share = f"at least {removed['supply_pct']}% of supply (share unknown for {_plural(unknown, 'row')})"
    else:
        share = f"{removed['supply_pct']}% of supply"
    return f"pools and bonding curves removed: {_plural(n, 'row')}, {share}"


def read_sources(holders: dict[str, Any], funders: dict[str, Any] | None, findings: list[dict[str, Any]], provider_cohorts: dict[str, dict[str, Any]] | None, solscanner: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """What each source actually read, in a fixed order, with what it cannot see. Plain data, JSON-serializable."""
    out: list[dict[str, Any]] = []
    d = holders.get("distribution") or {}
    ex = d.get("top_ex_infra") or {}
    pool_note = "" if not any("no pool owner matched" in w or "Dexscreener lookup failed" in w for w in holders.get("warnings") or []) else " (pool exclusion unreliable)"
    lines = [
        f"{holders.get('token_accounts')} token accounts, {d.get('owners')} owners; top holder {ex.get('top_1', 'n/a')}%, top 10 {ex.get('top_10', 'n/a')}% excluding pools{pool_note}; "
        f"pools hold {d.get('infrastructure_pct')}%; concentration score {d.get('gini') if d.get('gini') is not None else 'n/a'}",
    ]
    if funders:
        lines.append(f"funding checked for {funders['examined_wallets']} of {funders.get('requested_wallets', funders['examined_wallets'])} wallets; funder found for {funders['with_funder']}; "
                     f"failed {funders.get('failed_wallets', 0)}; {funders['covered_supply_pct']}% of supply had a funding record" + (f"; STOPPED EARLY: {funders['aborted']}" if funders.get("aborted") else ""))
        batches = funders.get("batches", [])
        lines.append(f"funder batches (3+ holders from one funder): {len(batches)}")
        lines += _capped([f"  {pw.neutral(b.get('funder_name')) or 'unlabeled'}: {b['wallets']} wallets, {b['share_pct']}% of supply" for b in batches], 3)
        lines += _cohort_source_lines(funders.get("cohorts"))
    else:
        lines.append("funding lookups: not run (holder list only)")
    out.append({"key": "helius", "name": "Helius full holder list", "status": "read", "age": 0.0, "lines": lines,
                "cannot_see": "funding data only for the wallets examined; the first funder can be a small top-up; labels are incomplete"})

    by_name = {f["provider"]: f for f in findings}
    bm = by_name.get("bubblemaps_map")
    status_text = {"ok": "read", "empty": "empty", "unavailable": "unavailable", "skipped": "not run"}
    bblock = {"key": "bubblemaps_map", "name": "Bubblemaps free map", "status": "not run", "age": None, "lines": ["not run (pass --bubblemaps-json from bubblemaps_map.py)"],
              "cannot_see": "only the top 250 holders; the page can be stale"}
    if bm is not None:
        bblock["status"] = status_text[bm["status"]]
        bblock["age"] = bm.get("data_age_min")
        if bm["status"] == "ok":
            cl = bm.get("clusters") or []
            ls = [f"map {_age_text(bm.get('data_age_min'))}" + ("" if bm.get("refresh_effective") else " (refresh not confirmed)"),
                  f"{bm.get('cluster_count', len(cl))} clusters; largest {bm['largest_cluster_pct']}%; all together {bm.get('cluster_sum_pct')}% of supply"]
            ls += _capped([f"  cluster {i}: {c.get('wallets') if c.get('wallets') is not None else '?'} wallets, {c['supply_pct']}%" for i, c in enumerate(cl, 1)])
            bblock["lines"] = ls
            bage = bm.get("data_age_min")
            if bage is None or bage > STALE_ALL_CLEAR_MIN:
                bblock["stale"] = True
                bblock["stale_note"] = f"{_age_text(bage)}, older than the {STALE_ALL_CLEAR_MIN:g} min freshness limit" + ("" if bm.get("refresh_effective") else "; refresh not confirmed")
        else:
            bblock["lines"] = [clean_text(bm.get("detail") or bblock["status"])]
    out.append(bblock)

    ss_finding = by_name.get("solscanner")
    out.append(_solscanner_source(solscanner, ss_finding))

    for key, name, limit in (("gmgn", "GMGN holder rows", "the top 100 holders only"), ("jupiter", "Jupiter datapi holder rows", "the top 100 holders only; the endpoint is undocumented")):
        res = (provider_cohorts or {}).get(key)
        if res is None:
            out.append({"key": key, "name": name, "status": "not run", "age": None, "lines": [f"not run (pass --{key}-holders-json)"], "cannot_see": limit})
            continue
        cov = res["coverage"]
        removed = cov.get("infrastructure_removed")
        ls = [f"{cov['rows']} rows read; {cov['with_funding_time']} carry a funding time; {coverage_share_text(cov)}"]
        if removed is not None:
            ls.append(removed_infrastructure_text(removed))
        ls += _cohort_source_lines(res)
        tags = res.get("tags") or {}
        ls.append(f"tags ({_display_name(key)}'s claims, not proof): " + (", ".join(f"{pw.neutral(k)} {v}" for k, v in tags.items()) if tags else "none present in the rows"))
        out.append({"key": key, "name": name, "status": "read" if cov["rows"] or (removed or {}).get("rows") else "empty", "age": None, "lines": ls, "cannot_see": limit})

    for f in findings:
        if f["provider"] in ("bubblemaps_map", "solscanner"):
            continue
        vals = [f"largest cluster {f['largest_cluster_pct']}%" if f.get("largest_cluster_pct") is not None else None,
                f"clusters together {f['cluster_sum_pct']}%" if f.get("cluster_sum_pct") is not None else None,
                f"bundles {f['bundle_pct']}%" if f.get("bundle_pct") is not None else None,
                f"alarm hint: {clean_provider_text(f['alarm_hint'], 60)}" if f.get("alarm_hint") else None]
        ls = [", ".join(v for v in vals if v) or (finding_text(f, "detail") if f.get("detail") else "no values")]
        pstale = f["status"] == "ok" and f.get("data_age_min") is not None and f["data_age_min"] > STALE_ALL_CLEAR_MIN
        out.append({"key": clean_provider_text(f["provider"], 40), "name": f"Provider {_display_name(f['provider'])} (--providers-json)", "status": status_text[f["status"]], "age": f.get("data_age_min"), "lines": ls,
                    "cannot_see": "whatever the provider does not report; an empty answer is unknown, not a reassurance",
                    **({"stale": True, "stale_note": f"{_age_text(f['data_age_min'])}, older than the {STALE_ALL_CLEAR_MIN:g} min freshness limit"} if pstale else {})})
    return out


def _display_name(provider: str) -> str:
    """Readable provider name for prose (raw ids stay in JSON); always sanitized, verdict words removed from provider names
    ("own detectors" is this tool's own wording)."""
    return PROVIDER_PROSE.get(provider) or (provider if provider == "own detectors" else clean_provider_text(provider, 40))


def cluster_alarm_texts(findings: list[dict[str, Any]], sources: list[dict[str, Any]] | None = None) -> list[str]:
    """Every clear large cluster (or bundle share) a provider reported over its bar, named with the bar. These lead the
    'Why' line: the owner's rule is that clear large clusters make a token dangerous."""
    out = []
    for f in findings:
        if f.get("status") != "ok":
            continue
        parts = []
        if (f.get("largest_cluster_pct") or 0) >= CLUSTER_ALARM_PCT:
            parts.append(f"largest cluster {f['largest_cluster_pct']:g}% of supply (bar {CLUSTER_ALARM_PCT:g}%)")
        if (f.get("cluster_sum_pct") or 0) >= AGGREGATE_CLUSTER_ALARM_PCT:
            parts.append(f"all clusters together {f['cluster_sum_pct']:g}% (bar {AGGREGATE_CLUSTER_ALARM_PCT:g}%)")
        if (f.get("bundle_pct") or 0) >= BUNDLE_ALARM_PCT:
            parts.append(f"bundles {f['bundle_pct']:g}% of supply (bar {BUNDLE_ALARM_PCT:g}%)")
        if parts:
            out.append(f"{_display_name(f['provider'])}: " + "; ".join(parts))
        elif f.get("alarm_hint"):
            blk = next((x for x in sources or [] if x["key"] == f["provider"]), None)
            out.append((blk or {}).get("hint_text") or f"{_display_name(f['provider'])} hint (corroboration only): {finding_text(f, 'alarm_hint', 60)}")
    return out


def not_read_items(a: dict[str, Any]) -> list[str]:
    """Everything required that was not run, unavailable, empty or only partly read, from the same facts the
    Sources-read blocks use. Optional sources nobody asked for are reported separately ('Not requested')."""
    items: list[str] = []
    det = {d["name"].split(" (")[0]: d for d in a["detectors"]}
    batch = next((d for d in a["detectors"] if d["name"].startswith("funder-batch")), None)
    cohort = next((d for d in a["detectors"] if d["name"].startswith("funding-time cohort")), None)
    acq = next((d for d in a["detectors"] if d["name"].startswith("acquisition-time")), None)
    if batch and batch["state"] == "not_run":
        items.append("Helius funding lookups and the funding-time cohort detector (not run)")
    else:
        if batch and batch["state"] in ("partial", "unavailable"):
            items.append(f"Helius funding lookups ({batch['detail']})")
        if cohort and cohort["state"] != "ran":
            items.append(f"funding-time cohort detector (did not complete: {_STATE_TEXT[cohort['state']].lower()})")
    if acq and acq["state"] == "not_run":
        items.append("acquisition-time check (no timestamps supplied)")
    cov = a["coverage"]
    if cov.get("with_funder") and cov["covered_noninfra_pct"] < COVERAGE_MIN_SUPPLY_PCT:
        items.append(f"supply coverage (only {cov['covered_noninfra_pct']}% of ordinary-wallet supply checked, minimum {COVERAGE_MIN_SUPPLY_PCT:g}%)")
    if any(r.startswith(DEPTH_GUARD_START) for r in a["verdict"].get("no_alarm_blockers") or []):  # DS-DEPTH-GUARD-T1, never on a raised flag
        items.append(f"funding lookups below the top {cov['requested_wallets']} holders (funded-by depth)")
    if cov.get("truncated"):
        items.append("the full holder list (truncated)")
    if not cov.get("pool_exclusion_reliable", True):
        items.append("pool exclusion (unreliable)")
    for src in a["sources"]:
        if src["key"] == "helius":
            continue
        required = src["key"] == "bubblemaps_map"
        if src["status"] == "read":
            if src["key"] == "solscanner":
                items.append("SolScanner funding sources (not kept by this tool)")
            if src.get("stale"):
                items.append(f"fresh {src['name']} data (stale: {src['stale_note']})")
            continue
        if src["status"] == "not run" and not required:
            continue  # optional source nobody asked for
        items.append(f"{src['name']} ({'not supplied' if src['status'] == 'not run' else src['status']})")
    return items


def executive_summary(mint: str, holders: dict[str, Any], a: dict[str, Any], now: dt.datetime | None = None) -> list[str]:
    """At most SUMMARY_MAX_LINES plain-English lines. Evidence first; the owner decides."""
    now = now or dt.datetime.now(dt.timezone.utc)
    flag, sources = a["flag"], a["sources"]
    by_key = {s["key"]: s for s in sources}
    d = holders.get("distribution") or {}
    ex = d.get("top_ex_infra") or {}
    age = a.get("token_age_h")
    lines = [f"Token {mint}, read {now.strftime('%Y-%m-%d %H:%M')} UTC; " + (f"token age {age} h." if age is not None else "token age unknown."),
             f"FLAG: {flag['label']}"]
    pre = a.get("bubblemaps_pre_refresh")
    if pre and pre.get("line"):  # HS-BM-MEMBERS-T1, owner decision: shown next to the FLAG, never counted
        lines.append(pre["line"])
    if flag["why"]:
        texts = cluster_alarm_texts(a["findings"], sources)
        minor = [t for t in texts if "corroboration only" in t]
        main = [t for t in texts if t not in minor]
        rest = [_short_reason(r) for r in a["verdict"].get("reasons", []) if not re.match(r"\w+ alarms", r) and " alarm hint:" not in r]
        main += [r for r in rest if "(UNRESOLVED)" not in r]
        minor += [r for r in rest if "(UNRESOLVED)" in r]
        dis = a["verdict"].get("disagreement") or {}
        if a["verdict"]["level"] == VERDICT_UNRESOLVED and dis.get("disagreeing"):
            main.append("disagreeing source(s): " + ", ".join(_display_name(n) for n in dis["disagreeing"]))
        if not main:  # a CAUTION always states its reason
            hint_only = [f["provider"] for f in a["findings"] if f.get("status") == "ok" and f.get("alarm_hint") and not finding_alarms(f)]
            if hint_only and all(n == "solscanner" for n in hint_only):
                main.append("only SolScanner raised it (corroboration only, not confirmed by any other source)")
            elif hint_only:
                main.append(f"only {', '.join(_display_name(n) for n in hint_only)} raised it (hint only, not confirmed by any other source)")
            else:
                main.append("no clear large cluster; only unproven items, see the Also line")
        if main:
            lines.append("Why: " + " | ".join(main[:5]))
        if minor:
            lines.append("Also: " + " | ".join(minor[:4]))
    elif flag["caveat"]:
        lines.append("Note: " + pw.keep_whole(flag["caveat"], 200))
    lines.append(f"Holders: top holder {ex.get('top_1', 'n/a')}% and top 10 {ex.get('top_10', 'n/a')}% of supply excluding pools; pools hold {d.get('infrastructure_pct')}%.")
    clusters = []
    bm = next((f for f in a["findings"] if f["provider"] == "bubblemaps_map" and f["status"] == "ok"), None)
    if bm:
        bsrc = by_key.get("bubblemaps_map", {})
        clusters.append(f"Bubblemaps largest {bm['largest_cluster_pct']}% (all together {bm.get('cluster_sum_pct')}%; map {_age_text(bm.get('data_age_min'))}{', STALE' if bsrc.get('stale') else ''})")
    ss = by_key.get("solscanner")
    if ss and ss["status"] == "read":
        clusters.append("SolScanner " + ss.get("summary", ss["lines"][1]) + f", scan {_age_text(ss['age'])}" + (f" ({ss.get('stale_label') or 'STALE'})" if ss.get("stale") else ""))
    clusters += [f"{_display_name(f['provider'])} largest {f['largest_cluster_pct']}%" for f in a["findings"] if f["provider"] not in ("bubblemaps_map", "solscanner") and f["status"] == "ok" and f.get("largest_cluster_pct") is not None]
    lines.append("Largest clusters: " + ("; ".join(clusters) if clusters else "no source returned cluster data") + ".")
    coh = []
    for key, label in (("helius", "Helius list"), ("gmgn", "GMGN rows"), ("jupiter", "Jupiter rows")):
        blk = by_key.get(key)
        if blk and blk["status"] == "read":
            first = next((ln for ln in blk["lines"] if ln.startswith("funding cohorts found")), None)
            if first:
                coh.append(f"{label} {first.split(': ')[1]} found")
    lines.append("Funding cohorts (wallets first funded close together): " + ("; ".join(coh) if coh else "not checked") + ".")
    helius = by_key["helius"]
    batch = next((dd for dd in a["detectors"] if dd["name"].startswith("funder-batch")), None)
    cov = a["coverage"]  # the top N: funded-by depth (--funders-top, owner 2026-10-28 "Top 100"), so the summary says it
    helius_text = "Helius holder list (funding lookups not run)" if batch and batch["state"] == "not_run" else f"Helius holder list and funding lookups ({cov['examined_wallets']} wallets) on the top {cov['requested_wallets'] or cov['examined_wallets']} holders"
    read = [helius_text] + [f"{s['name']} ({_age_text(s['age'], 'as supplied')})" for s in sources if s["key"] != "helius" and s["status"] == "read"]
    optional_missing = [s["name"] for s in sources if s["key"] in ("solscanner", "gmgn", "jupiter") and s["status"] == "not run"]
    lines.append("Read: " + ", ".join(read) + "." + (f" Not requested: {', '.join(optional_missing)}." if optional_missing else ""))
    missing = not_read_items(a)
    lines.append("Could not read: " + ("; ".join(missing) if missing else "nothing") + ".")
    lines.append("Your call: this tool raises a danger flag only on clear large clusters; no flag is NOT a safety signal.")
    return lines[:SUMMARY_MAX_LINES]


# ----------------------------------------------------------------------------- orchestration


def _validate_mint(mint: str) -> str:
    if not MINT_RE.match(mint):
        raise ConfigError("mint is not a valid base58 Solana address")
    return mint


def _stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _outdir(mint: str, out: str | None) -> Path:
    path = Path(out) if out else REPORTS_DIR / f"{_stamp()}-{mint}"
    path.mkdir(parents=True, exist_ok=True)
    return path


WARN_DEX_FAILED = "Dexscreener lookup failed: pool exclusion and launch time are unknown"
WARN_TRUNCATED = f"holder list truncated at {MAX_DAS_PAGES * 1000} token accounts: distribution and shares are incomplete"
WARN_NO_POOL = "no pool owner matched the holder list; pools may be counted as holders (use --exclude ADDRESS)"


# ----------------------------------------------------------------------------- shared DEX vault authorities (cited)
# DS-AMM-VAULTS-T1: Raydium CPMM, Raydium AMM v4, Meteora DAMM v2 and Meteora DBC keep the token vaults of every pool of the
# program under ONE authority PDA, not under the pair address Dexscreener lists, so such a pool counted as a holder ($LAUNCH,
# 2026-10-26: its Raydium CPMM pool, 4.64% of supply, was the top holder). run_holders counts each of these authorities that
# holds this token as a pool. Cited program ids and seeds (one seed each; the tests derive every authority again):
# - Raydium CPMM: declare_id! "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C" (the not-devnet build) and AUTH_SEED
#   "vault_and_lp_mint_auth_seed" in programs/cp-swap/src/lib.rs; programs/cp-swap/src/instructions/initialize.rs creates both
#   pool vaults with the authority of seeds = [AUTH_SEED], bump. raydium-io/raydium-cp-swap at commit
#   f4b9b26342afe9122d5ff67cd7a4f19ded4ac0a5, https://raw.githubusercontent.com/raydium-io/raydium-cp-swap/<commit>/<path>,
#   read 2026-10-27 (public GitHub, no key).
# - Raydium AMM v4: declare_id! "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8" (the not-devnet build) in program/src/lib.rs;
#   AUTHORITY_AMM "amm authority" in program/src/processor.rs, whose initialize2 refuses any amm_authority other than
#   find_program_address([AUTHORITY_AMM], program_id) and creates the coin and pc vaults with it. raydium-io/raydium-amm at
#   commit 91739d8d9f5cf347e0ce14ebe4d2bb7069fb31b6, https://raw.githubusercontent.com/raydium-io/raydium-amm/<commit>/<path>,
#   read 2026-10-27 (public GitHub, no key).
# - Meteora DAMM v2 (cp_amm): program "cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG" and its Pool Authority
#   HLnpSz9h2S4hiLQ43rnSD9XkcUThA7B8hQMKmDaiTLcC (provider-docs current/meteora/fulldocs.pages/developer-guides/damm-v2/index.md,
#   "Program IDs"); seed "pool_authority" (damm-v2/program/accounts.md, "PDA Map").
# - Meteora DBC (dynamic_bonding_curve): program "dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN" and its Pool Authority
#   FhVo3mqL8PW5pH5U2CN4XE33DokiyZnUwuGpH2hmHLuM (current/meteora/fulldocs.pages/developer-guides/dbc/index.md, "Program IDs");
#   seed "pool_authority" (dbc/program/accounts.md, "Address Map").
# - Raydium LaunchLab (raydium_launchpad, the bonding curve behind letsbonk-style launches; DS-AMM-VAULTS-T2): declare_id!
#   "LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj" (the not-devnet build) and AUTH_SEED "vault_auth_seed" in
#   programs/launch-cpi/src/lib.rs; programs/launch-cpi/src/context.rs (Initialize) takes the authority as the PDA of
#   seeds = [AUTH_SEED] and creates the base and quote pool vaults with token::authority = authority. raydium-io/raydium-cpi
#   (Raydium's CPI crate for the program) at commit 115df2779d53bacc7db9d0be2773a4b48a6d372b,
#   https://raw.githubusercontent.com/raydium-io/raydium-cpi/<commit>/<path>, read 2026-10-28 (public GitHub, no key).
#   raydium-io/raydium-sdk-V2 at commit f8549145afe75d4c486e30c43331c2c4da32b1eb, src/common/programId.ts, prints the same
#   LAUNCHPAD_AUTH WLHv2UAZm6z4KyaaELi5pjdbJh6RESMva1Rnn8pJVVh.
SHARED_VAULT_PROGRAMS = (
    ("Raydium CPMM", "CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C", b"vault_and_lp_mint_auth_seed"),
    ("Raydium AMM v4", "675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8", b"amm authority"),
    ("Meteora DAMM v2", "cpamdpZCGKUy5JxQXB4dcpGPiikHawvSWAd6mEn1sGG", b"pool_authority"),
    ("Meteora DBC", "dbcij3LWUppWqq96dh6gJWwBifmcGfLSB5D4DuSMaqN", b"pool_authority"),
    ("Raydium LaunchLab", "LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj", b"vault_auth_seed"),
)
# DS-AMM-VAULTS-T2: a Meteora DAMM v1 pool keeps no token itself. Each side sits in the Meteora Dynamic Vault of that mint, in a
# token vault owned by the vault PDA, and that PDA is one per mint, not one shared address, so dynamic_vault_authority derives
# it for THIS mint. Cited from the provider-docs cache current/meteora/fulldocs.pages/developer-guides/ (fetched 2026-10-21):
# program "24Uqj9JCLxUeoC3hGfh5W3s9FM9uCHDS2SG3LYwBpyTi" (dynamic-vault/index.md, "Program IDs"); seeds "vault", token mint and
# the rebalance-vault base address HWzXGcGHy4tcpYfaRDCyLNzXqBTv3E6BttpCH2vJxArv (a public address, no secret;
# dynamic-vault/program/accounts.md, "PDA Map" and "Constants"; dynamic-vault/rust-integration/library.md, "PDA Derivation");
# a_token_vault / b_token_vault are "Token accounts owned by each Dynamic Vault" (damm-v1/program/accounts.md, "Dynamic Vault
# Relationship"). The same vault also holds lender deposits of the mint (rare for a memecoin): a program vault, not a trader,
# so it counts as infrastructure all the same.
DYNAMIC_VAULT_PROGRAM = "24Uqj9JCLxUeoC3hGfh5W3s9FM9uCHDS2SG3LYwBpyTi"
DYNAMIC_VAULT_BASE = "HWzXGcGHy4tcpYfaRDCyLNzXqBTv3E6BttpCH2vJxArv"
_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58encode(raw: bytes) -> str:
    number = int.from_bytes(raw, "big")
    out = ""
    while number:
        number, rest = divmod(number, 58)
        out = _B58_ALPHABET[rest] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def find_program_address(seeds: list[bytes], program_id: str) -> str | None:
    """Solana's program-derived address: the first bump from 255 down whose sha256(seeds, bump, program, marker) is off the
    ed25519 curve (Pubkey::find_program_address in the cited Raydium sources)."""
    program = b58decode(program_id)
    for bump in range(255, -1, -1):
        candidate = _b58encode(hashlib.sha256(b"".join(seeds) + bytes([bump]) + program + b"ProgramDerivedAddress").digest())
        if not is_on_curve(candidate):
            return candidate
    return None


SHARED_VAULT_AUTHORITIES = {a: name for name, program, seed in SHARED_VAULT_PROGRAMS if (a := find_program_address([seed], program))}


def dynamic_vault_authority(mint: str) -> str | None:
    """This mint's Meteora Dynamic Vault PDA, seeds ("vault", mint, DYNAMIC_VAULT_BASE): the owner of the token vault that holds
    the mint's side of every DAMM v1 pool (DS-AMM-VAULTS-T2). None when the mint is not a 32-byte base58 address."""
    try:
        raw = b58decode(mint)
    except ValueError:
        return None
    return find_program_address([b"vault", raw, b58decode(DYNAMIC_VAULT_BASE)], DYNAMIC_VAULT_PROGRAM) if len(raw) == 32 else None


def run_holders(client: Helius, mint: str, extra_exclude: set[str] | None = None, top: int = 250) -> dict[str, Any]:
    pairs, dex_ok = dexscreener_pairs(mint)
    pools = {p["pairAddress"] for p in pairs if isinstance(p.get("pairAddress"), str) and MINT_RE.match(p["pairAddress"])}
    pools |= {a for a in (extra_exclude or set()) if MINT_RE.match(a)}
    created = [p["pairCreatedAt"] // 1000 for p in pairs if isinstance(p.get("pairCreatedAt"), int)]
    accounts, truncated = client.token_accounts(mint)
    balances = aggregate_owners(accounts)
    paired = set(pools)  # DS-AMM-VAULTS-T1 R1: the no-pool warning is still decided on the Dexscreener pairs and --exclude owners alone
    pools |= {a for a in (*SHARED_VAULT_AUTHORITIES, dynamic_vault_authority(mint)) if a in balances}  # DS-AMM-VAULTS-T1/T2: a DEX vault authority holding this token is a pool
    dist = distribution(balances, pools)
    warnings: list[str] = []
    if not dex_ok:
        warnings.append(WARN_DEX_FAILED)
    if truncated:
        warnings.append(WARN_TRUNCATED)
    if dex_ok and (dist if pools == paired else distribution(balances, paired)).get("infrastructure_pct", 0) == 0:
        warnings.append(WARN_NO_POOL)
    return {
        "mint": mint,
        "token_accounts": len(accounts),
        "truncated": truncated,
        "earliest_pair_created_at": min(created) if created else None,
        "pool_addresses": sorted(pools),
        "distribution": {k: v for k, v in dist.items() if k != "ranked"},
        "warnings": warnings,
        "top_holders": top_holder_rows(dist.get("ranked", []), pools, top),
        "_ranked": dist.get("ranked", []),
        "_balances": balances,
    }


def run_funders(client: Helius, holders: dict[str, Any], *, top: int, start_rank: int = 0, acquisitions: dict[str, int] | None = None, workers: int = 1) -> dict[str, Any]:
    """Per-wallet failures are recorded, not fatal. Stops early (partial result) after repeated failures
    or when the credit budget is reached. `workers` lookups run at once (1 = the old one-at-a-time loop); results are
    assembled in holder-rank order, so the output does not depend on which lookup finished first."""
    pools = set(holders["pool_addresses"])
    ranked = [o for o, _ in holders["_ranked"] if o not in pools][start_rank : start_rank + top]
    aborted: str | None = None
    consecutive = 0

    def on_outcome(_: int, outcome: tuple[str, Any]) -> bool:
        """Completion order. True stops dispatch; the first stop reason is kept."""
        nonlocal aborted, consecutive
        if outcome[0] == "ok":
            consecutive = 0
            return False
        if outcome[0] == "budget":
            aborted = aborted or "credit budget reached"
            return True
        consecutive += 1
        if consecutive >= MAX_CONSECUTIVE_FAILURES:
            aborted = aborted or f"{MAX_CONSECUTIVE_FAILURES} consecutive failures"
            return True
        return False

    outcomes = run_lookups(ranked, client.funded_by, workers, on_outcome)
    result = funders_result(holders, ranked, outcomes, aborted=aborted, acquisitions=acquisitions)
    if not aborted:
        try:
            result["upstream"] = trace_upstream([b for b in result["batches"] if not b["labeled"]][:UPSTREAM_TRACE_LIMIT], client.funded_by, workers)
        except BudgetError:
            result["aborted"] = "credit budget reached during upstream trace"
    return result


def funders_result(
    holders: dict[str, Any],
    ranked: list[str],
    outcomes: dict[int, tuple[str, Any]],
    *,
    aborted: str | None = None,
    upstream: list[dict[str, Any]] | None = None,
    acquisitions: dict[str, int] | None = None,
) -> dict[str, Any]:
    """Everything the funders stage reports, from the lookup outcomes (pure: no network, no credits). run_funders calls
    it after its lookups; the offline `assess` subcommand calls it again on outcomes rebuilt from funders.json `rows`, so
    both give the same records, batches, classification and cohorts. `outcomes` is keyed by position in `ranked`."""
    funded: dict[str, dict[str, Any] | None] = {}
    errors: dict[str, str] = {}
    for i, wallet in enumerate(ranked):  # rank order, never completion order: batch and cohort output depend on it
        kind, value = outcomes.get(i, ("not_reached", None))
        if kind == "ok":
            funded[wallet] = value
        elif kind == "error":
            errors[wallet] = value
    position = {owner: (rank, share) for rank, (owner, share) in enumerate(holders["_ranked"], 1)}
    rows = [funder_row(position[w][0], w, position[w][1], outcomes.get(i)) for i, w in enumerate(ranked)]
    records = build_records(holders["_balances"], funded)
    batches = detect_batches(records)
    verdict = classify(batches, holders.get("earliest_pair_created_at"))
    cohort_source = run_cohort_source(helius_cohort_rows(records, acquisitions), launch_ts=holders.get("earliest_pair_created_at"), acquisitions=acquisitions)
    covered = round(sum(r["share_pct"] for r in records), 2)
    types: dict[str, list] = collections.defaultdict(lambda: [0, 0.0])
    for r in records:
        key = r["funder_type"] or "unlabeled"
        types[key][0] += 1
        types[key][1] += r["share_pct"]
    return {
        "examined_wallets": len(funded),
        "requested_wallets": len(ranked),
        "failed_wallets": len(errors),
        "aborted": aborted,
        "with_funder": len(records),
        "covered_supply_pct": covered,
        "examined_supply_pct": round(sum(holders["_balances"].get(w, 0.0) for w in funded) / (sum(holders["_balances"].values()) or 1.0) * 100, 2),
        "verdict": verdict,
        "cohorts": cohort_source,
        "acquisition_supplied": bool(acquisitions),
        "batches": [{k: v for k, v in b.items() if k != "members"} | {"member_count": len(b["members"])} for b in batches],
        "upstream": list(upstream or []),
        "funder_types": {k: {"wallets": v[0], "supply_pct": round(v[1], 2)} for k, v in types.items()},
        "errors": errors,
        "rows": rows,
    }


_STATE_TEXT = {"ran": "ran", "partial": "ran PARTIALLY", "not_run": "NOT RUN", "unavailable": "UNAVAILABLE"}
_LEVEL_TEXT = {
    VERDICT_HIGH: "HIGH - coordinated structure or a provider alarm; do not treat the holders as independent",
    VERDICT_UNRESOLVED: "UNRESOLVED - sources disagree or an alarm is unconfirmed; resolve before relying on either side",
    VERDICT_LIMITED: "LIMITED (unverified) - too little was checked to say anything is fine. This is NOT an all-clear",
    VERDICT_NO_ALARM: "NO_ALARM - every required check ran and none alarmed. This is NOT proof of independent holders",
}


def next_step(a: dict[str, Any]) -> str:
    """One plain 'what to do next' line per verdict."""
    v, cov = a["verdict"], a["coverage"]
    if v["level"] == VERDICT_HIGH:
        return "Do not enter on the assumption that holders are independent. Verify the flagged wallets by hand (Bubblemaps map, Solscan) before any decision."
    if v["level"] == VERDICT_UNRESOLVED:
        dis = v.get("disagreement") or {}
        names = sorted(set(dis.get("alarming", [])) | set(dis.get("disagreeing", [])))
        who = f"Compare {', '.join(names)} and refresh the Bubblemaps step" if names else "Open the flagged cohort wallets by hand and refresh the Bubblemaps step"
        return f"{who}; do not treat the holders as independent until the conflict is explained."
    if v["level"] == VERDICT_LIMITED:
        todo = []
        if any("bubblemaps_map" in r for r in v["reasons"]):
            todo.append("run the Bubblemaps step (bubblemaps_map.py) and pass --bubblemaps-json")
        if cov["with_funder"] == 0:
            todo.append("run the funders step (report) so funding data exists")
        elif cov["covered_noninfra_pct"] < COVERAGE_MIN_SUPPLY_PCT:  # since PR #202 the funded-by depth is --funders-top; --top is the holder list
            todo.append(f"raise --funders-top to check more wallets ({COST_FUNDED_BY} Helius credits a wallet; the owner decides, under the Helius budget rules); "
                        "it cannot exceed --top, the holder list, so raise --top too if every listed holder was already checked")
        if any(r.startswith(DEPTH_GUARD_START) for r in v["reasons"]) and not any(t.startswith("raise --funders-top") for t in todo):
            todo.append(f"to check the holders below the funded-by depth, rerun funded-by with a larger --funders-top ({COST_FUNDED_BY} Helius credits a wallet; the owner decides, under the Helius budget rules)")
        if not cov.get("pool_exclusion_reliable", True):
            todo.append("rerun with --exclude <pool owner address>")
        if cov.get("truncated"):
            todo.append("treat shares as incomplete (holder list truncated)")
        if cov.get("aborted"):
            todo.append("rerun with a higher --max-credits")
        if not todo:
            todo.append("add a second independent cluster source (--providers-json) or refresh stale data")
        return "Unverified, so do not rely on the missing flag: " + "; ".join(todo) + "."
    return "Re-run before acting if the token is young: provider data ages quickly. This is not proof of independent holders."


def _examined_lines(a: dict[str, Any], cov: dict[str, Any]) -> list[str]:
    if a["detectors"][0]["state"] == "not_run":
        return ["- Wallets examined: not run (the funders step did not run, so no funding data exists)", "- Supply examined: not run"]
    return [
        f"- Wallets examined: {cov['examined_wallets']} of {cov['requested_wallets']} requested; funder found for {cov['with_funder']}; failed lookups {cov['failed_wallets']}",
        f"- Supply examined: {cov['examined_supply_pct']}% of total supply; {cov['covered_supply_pct']}% had a funding record "
        f"({cov['covered_noninfra_pct']}% of the supply held by ordinary wallets, pools excluded; pools hold {cov['infrastructure_pct']}%). "
        f"NO_ALARM needs at least {COVERAGE_MIN_SUPPLY_PCT:g}%",
    ]


def _assessment_lines(a: dict[str, Any], saved_at: str | None = None) -> list[str]:
    v, cov = a["verdict"], a["coverage"]
    lines = ["", "## Underlying level (details)", f"**{_LEVEL_TEXT[v['level']]}**"]
    lines += [f"- {r}" for r in v["reasons"]]
    lines.append(f"- What to do next: {next_step(a)}")
    lines += [
        "",
        "## Coverage",
        *_examined_lines(a, cov),
    ]
    if not cov.get("pool_exclusion_reliable", True):
        lines.append("- Pool exclusion unreliable: the pool owner was not matched or the Dexscreener lookup failed, so pools may be counted as holders; coverage is measured against total supply and NO_ALARM is impossible")
    if cov.get("truncated"):
        lines.append("- Holder list TRUNCATED: shares and coverage are incomplete and NO_ALARM is impossible")
    lines.append("- Detectors:")
    lines += [f"  - {d['name']}: {_STATE_TEXT[d['state']]}" + (f", {d['detail']}" if d.get("detail") else "") for d in a["detectors"]]
    for f in a.get("findings", []):
        state = {"ok": "ran", "empty": "ran, EMPTY (unknown, not a reassurance)", "unavailable": "ANSWERED BUT UNREADABLE" if f.get("unreadable") else "UNAVAILABLE", "skipped": "NOT RUN"}[f["status"]]
        lines.append(f"  - provider {finding_text(f, 'provider', 40)}: {state}" + (f", {finding_text(f, 'detail')}" if f.get("detail") else ""))
    if saved_at is None:
        lines.append("- Data ages: Helius holder list and funded-by: collected at report time")
    else:  # offline assess: the Helius data is as old as the collector's saved files
        lines.append(f"- Data ages: Helius holder list and funded-by: collected by the collector run, files saved {saved_at} UTC")
    if a.get("token_age_h") is not None:
        lines.append(f"  - token age {a['token_age_h']} h (younger than {YOUNG_TOKEN_MAX_AGE_H:g} h counts as young)")
    else:
        lines.append("  - token age unknown (treated as young)")
    for f in a.get("findings", []):
        if f["status"] in ("ok", "empty"):
            age = "unknown" if f.get("data_age_min") is None else f"{f['data_age_min']} min"
            lines.append(f"  - {finding_text(f, 'provider', 40)}: {age}")
    findings = [f for f in a.get("findings", []) if f["status"] == "ok"]
    if findings:
        lines += ["", "| Provider | Largest cluster % | All clusters together % | Bundles % | Data age min | Alarm | All-clear counts |", "|---|---|---|---|---|---|---|"]
        young_age = a.get("token_age_h")
        for f in findings:
            alarm = "; ".join(finding_alarms(f)) or "no"
            lines.append(
                f"| {finding_text(f, 'provider', 40)} | {_none(f['largest_cluster_pct'])} | {_none(f.get('cluster_sum_pct'))} | {_none(f['bundle_pct'])} | {_none(f['data_age_min'])} | {alarm} | {'yes' if all_clear_counts(f, young_age) else 'no'} |"
            )
    return lines


GLOSSARY = (
    "Glossary: a cohort is a group of holder wallets first funded close together in time; the Bubblemaps map is the free web map that "
    "groups wallets it believes are linked; concentration is how much of the supply a few wallets hold; FACTORY_PATTERN is the older "
    "check for a single funder that has no exchange label feeding many wallets within minutes. A flag is linkage evidence, not proof of common control."
)


FULL_ADDRESSES_LINE = (
    "- Full addresses (this report shortens them): funders.json `rows` lists every requested wallet with its status, funder and funding time; "
    "holders.json `top_holders` lists the top holders."
)


def _utc(ts: int) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%d %H:%M")


def _cohort_lines(sources: dict[str, dict[str, Any] | None]) -> list[str]:
    lines = [
        "",
        "## Funding-time cohorts (all funders; labeled exchange funders are included, never excluded)",
        f"- Windows of {COHORT_WINDOW_S / 3600:g} h, at least {COHORT_MIN_WALLETS} wallets or {COHORT_MIN_SUPPLY_PCT:g}% of supply (at least {COHORT_MIN_WALLETS_FLOOR} wallets). "
        f"HIGH needs {COHORT_HIGH_MIN_WALLETS}+ wallets, {COHORT_HIGH_MIN_FUNDERS}+ funders and {COHORT_HIGH_MIN_SIGNS} of: dormant {COHORT_DORMANT_GAP_S // 86400}+ days, synchronized acquisition, similar amounts; anything less is UNRESOLVED. "
        "All thresholds are provisional (two positive cases, two older-wallet negatives); a flag is linkage evidence, not proof of common control.",
    ]
    for src, res in sources.items():
        if not res:
            continue
        cov = res["coverage"]
        lines.append(f"- Source {src}: {cov['with_funding_time']} of {cov['rows']} rows with a funding time, {coverage_share_text(cov)}; {_plural(len(res['cohorts']), 'cohort')} flagged")
        for c in res["cohorts"][:5]:
            by_label: dict[str, int] = {}
            for m in c["funder_mix"]:
                shown = pw.neutral(m["label"]) or "unlabeled"  # labels are safe_label'd at read time; neutral() again guards any other path
                by_label[shown] = by_label.get(shown, 0) + m["wallets"]
            mix = ", ".join(f"{k} {v}" for k, v in sorted(by_label.items(), key=lambda kv: -kv[1])[:8])
            if c.get("unknown_funder_wallets"):
                mix = ", ".join(p for p in (mix, f"funder unknown {c['unknown_funder_wallets']}") if p)
            amt = c["first_amounts"]
            lines.append(
                f"  - {c['wallets']} wallets, {share_text(c)}, first funded {_utc(c['start'])} to {_utc(c['end'])} UTC "
                f"({c['window_s'] / 3600:.1f} h), {funder_text(c)}, {labeled_funder_text(c, 'via')}; flagged by {c['flagged_by']}"
            )
            lines.append(f"    - severity: {c.get('severity')}: {c.get('severity_reason')}")
            lines.append(f"    - funder mix: {mix}")
            if amt.get("n"):
                lines.append(f"    - first amounts SOL: min {amt['min']}, median {amt['median']}, max {amt['max']}; similar {amt['similar']} ({amt['similar_fraction']:.0%} within +-{COHORT_AMOUNT_REL_BAND:.0%} of median)")
            gap = c["dormant_gap_s"]
            if gap["n"]:
                lines.append(f"    - dormant gap funding to first holding: median {gap['median'] / 86400:.1f} days (n={gap['n']})")
            if c.get("funding_to_launch_s_median") is not None:
                lines.append(f"    - funding to first DEX pair: median {c['funding_to_launch_s_median'] / 86400:.1f} days")
            acq = c.get("acquisition") or {}
            lines.append(f"    - acquisition-time check: {'FLAGGED' if acq.get('flag') else 'not flagged' if acq.get('ran') else 'NOT RUN'}: {acq.get('reason')}")
    lines.append("- Top-100 provider sources (GMGN, Jupiter) cannot clear wallets below rank 100; only the Helius full list covers the rest.")
    return lines


MEMBERS_CANNOT_SHOW = (
    "members cannot show: why the map links these wallets (its link evidence is not read), holders beyond its top 250, or the "
    "full addresses (the page shows short ones: matched offline by the shown start and end, or for label rows by rank and share, "
    "which can be wrong when ranks moved between the map read and the Helius read); a linking wallet holds none of the token; "
    "tags are each provider's claims, not proof"
)


def _tag_list(tags: list[str]) -> str:
    shown = [str(pw.neutral(t)) for t in tags[:MEMBER_TAGS_SHOWN]]
    return ", ".join(shown) + (f" and {len(tags) - MEMBER_TAGS_SHOWN} more" if len(tags) > MEMBER_TAGS_SHOWN else "")


def _member_claims(m: dict[str, Any], gmgn_read: bool) -> str:
    c = m.get("claims") or {}
    parts = []
    if gmgn_read:
        if c.get("gmgn"):
            parts.append("GMGN claims: " + _tag_list(c["gmgn"]))
        else:
            parts.append("GMGN: no tag" if "gmgn" in c else "GMGN: not in its top 100 rows")
    if c.get("jupiter"):
        parts.append("Jupiter claims: " + _tag_list(c["jupiter"]))
    if c.get("funder"):
        parts.append(f"Helius first funder: {pw.neutral(c['funder'])}")
    return "; ".join(parts)


def _member_share(m: dict[str, Any]) -> str:
    if m.get("share_shown"):
        return m["share_shown"]
    return "share not shown" if m.get("share_pct") is None else f"{m['share_pct']:g}%"


def _member_name(m: dict[str, Any]) -> str:
    return m.get("shown") or (f"map label {pw.neutral(m['label'])}" if m.get("label") else "no name shown")


def _cluster_member_lines(c: dict[str, Any], gmgn_read: bool, indent: str) -> list[str]:
    """One cluster: a head line, its holders in rank order (full address when resolved, share, map rank, method, the
    claims), its linking and hidden rows, and the GMGN bundler count."""
    head = f"Cluster {c['cluster']}, {_none(c.get('wallets'))} wallets, {c['supply_pct']:g}%"
    note = c.get("members_note")
    if c.get("members") is None:
        return [f"{indent}- {head}: members not read" + (f" ({note})" if note else "")]
    ms = c["members"]
    holders = sorted((m for m in ms if m["kind"] == "holder"), key=lambda m: (m.get("rank") is None, m.get("rank") or 0))
    linking = [m for m in ms if m["kind"] == "linking"]
    hidden = [m for m in ms if m["kind"] == "hidden"]
    status = "all rows read" if c.get("members_complete") else "NOT every row was read"
    extra = (f"; {note}" if note else "") + (f"; {c['refused_rows']} saved rows refused (not the format this tool writes)" if c.get("refused_rows") else "")
    out = [f"{indent}- {head}: {len(holders)} holders, {len(linking)} linking, {len(hidden)} hidden; {status}{extra}"]
    for m in holders[:MEMBER_ROWS_SHOWN]:
        rank = f"#{m['rank']}" if m.get("rank") is not None else "no rank"
        if m.get("address"):
            how = "resolved by prefix and suffix" if m["method"] == "prefix_suffix" else f"{_member_name(m)}; resolved by rank and share"
            if m.get("helius_rank") is not None and m["helius_rank"] != m.get("rank"):
                how += f"; Helius #{m['helius_rank']}"
            text = f"{rank} `{m['address']}` {_member_share(m)} ({how})"
            claims = _member_claims(m, gmgn_read)
            text += f"; {claims}" if claims else ""
        else:
            text = f"{rank} {_member_name(m)} {_member_share(m)}: not resolved ({m.get('unresolved') or 'no holder list'})"
        out.append(f"{indent}  - {text}")
    if len(holders) > MEMBER_ROWS_SHOWN:
        out.append(f"{indent}  - and {len(holders) - MEMBER_ROWS_SHOWN} more holders (all in assessment.json bubblemaps_members)")
    out += [f"{indent}  - linking wallet, holds none: {m.get('shown') or (pw.neutral(m['label']) if m.get('label') else 'no name shown')}" for m in linking[:5]]
    if len(linking) > 5:
        out.append(f"{indent}  - and {len(linking) - 5} more linking wallets, hold none")
    out += [f"{indent}  - hidden on the map: {'#' + str(m['rank']) if m.get('rank') is not None else 'no rank'} {_member_name(m)} {_member_share(m)}" for m in hidden]
    b = c.get("gmgn_bundler")
    if gmgn_read and b:
        out.append(f"{indent}  - GMGN claims bundler on {b['tagged']} of {b['holders']} holders" + (f" ({b['unresolved']} not resolved)" if b["unresolved"] else ""))
    return out


def bubblemaps_member_lines(a: dict[str, Any]) -> list[str]:
    """The Bubblemaps block's member lines (HS-BM-MEMBERS-T1; display only): each cluster with its members, the clusters
    only the list read saw, GMGN's bundler wallets outside every cluster, the pre-refresh members, what members cannot show."""
    mem = a.get("bubblemaps_members")
    if mem is None:
        return []
    pre = a.get("bubblemaps_pre_refresh") or {}
    out = []
    settle = mem.get("settle")
    if settle:
        changed = settle.get("settle_list_changed_s")
        out.append(f"  - refresh: read {settle.get('settle_s')} s after the refresh click" + (f"; the cluster list changed {changed} s after it" if changed is not None else "")
                   + (f"; {settle['settle_note']}" if settle.get("settle_note") else ""))
    if mem.get("pre_refresh_not_closed"):
        out.append(f"  - size read warning: {mem['pre_refresh_not_closed']['note']}")
    if not mem.get("read"):
        out.append(f"  - cluster members: not read ({mem.get('reason')}); the cluster sizes above are read as before")
    else:
        gmgn_read = bool(mem.get("gmgn_read"))
        secs = f", read in {mem['seconds']:g} s" if mem.get("seconds") is not None else ""
        out.append(f"  - cluster members (rows of the expanded Address List{secs}; full addresses matched offline to holders.json; display only, never counted):")
        for c in mem.get("clusters") or []:
            out += _cluster_member_lines(c, gmgn_read, "    ")
        if mem.get("list_only"):
            out.append(f"    - further down the list: {len(mem['list_only'])} more cluster(s) the size read did not see (display only, not counted):")
            for c in mem["list_only"]:
                out += _cluster_member_lines(c, gmgn_read, "      ")
        if mem.get("reason"):
            out.append(f"    - note: {mem['reason']}")
        b = mem.get("gmgn_bundlers")
        if b is None:
            out.append("  - GMGN bundler cross-check: not read (no GMGN rows were passed to assess)")
        else:
            caveat = "; ".join(p for p in (f"{b['unresolved_holders']} cluster holders not resolved" if b["unresolved_holders"] else "",
                                            f"{b['clusters_not_fully_read']} clusters not fully read" if b["clusters_not_fully_read"] else "") if p)
            out.append(f"  - GMGN bundler-tagged wallets outside every listed Bubblemaps cluster: {b['outside']} of {b['tagged_total']} (GMGN's top 100 rows only"
                       + (f"; {caveat}, so some of them may sit in a cluster" if caveat else "") + ")")
    if pre.get("clusters"):
        age = "age unknown" if pre.get("age_min") is None else f"{pre['age_min']:.0f} min old"
        out.append(f"  - pre-refresh snapshot ({age}; display only, not in the verdict):")
        for c in pre["clusters"]:
            out += _cluster_member_lines(c, False, "    ")
    out.append(f"  - {MEMBERS_CANNOT_SHOW}")
    return out


def markdown_report(mint: str, holders: dict[str, Any], funders: dict[str, Any] | None, credits: int, assessment: dict[str, Any] | None = None, provider_cohorts: dict[str, dict[str, Any]] | None = None,
                    *, saved_at: str | None = None) -> str:
    """`saved_at` is set only by the offline `assess` subcommand (UTC time the collector saved its files): the credits
    line then says the credits were recorded by the collector run and that this step used none."""
    d = holders["distribution"]
    a = assessment or assess(holders, funders, provider_cohorts=provider_cohorts)
    credit_note = "" if saved_at is None else " (as recorded by the collector run in its saved files; this offline assess step used 0)"
    lines = [f"# Holder forensics: {mint}", "", f"Generated {dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')} - Helius credits used: {credits}{credit_note}", "", "## Executive summary", ""]
    lines += [f"- {ln}" for ln in executive_summary(mint, holders, a)]
    for w in holders.get("warnings", []):
        lines.append(f"- WARNING: {w}")
    lines += ["", "## Sources read"]
    for src in a["sources"]:
        lines.append(f"- {src['name']}: {src['status']}" + (f", {_age_text(src['age'], 'as supplied')}" if src["status"] == "read" and src["key"] != "helius" else ""))
        lines += [f"  - {ln}" if not ln.startswith("  ") else f"  {ln}" for ln in src["lines"]]
        if src["key"] == "bubblemaps_map":
            lines += bubblemaps_member_lines(a)
        lines.append(f"  - cannot see: {src['cannot_see']}")
    removed_at = len(lines)  # HS-LABELS-T1: the counted line goes here, the last item of Sources read, once the whole report is built
    lines += _assessment_lines(a, saved_at)
    lines += [
        "",
        "## Distribution (all holders, Helius DAS)",
        f"- Token accounts: {holders['token_accounts']}; distinct owners: {d.get('owners')}; concentration score {d.get('gini')} (0 = everyone holds the same, 1 = one wallet holds everything)",
    ]
    if d.get("top"):
        lines.append("- Top holders: " + ", ".join(f"{k.replace('top_', 'top ')} {v}%" for k, v in d["top"].items()))
    lines.append(f"- Infrastructure (pools) {d.get('infrastructure_pct')}% of supply")
    if d.get("buckets"):
        lines.append("- Size buckets: " + "; ".join(f"{k}: {v['wallets']} wallets, {v['supply_pct']}%" for k, v in d["buckets"].items()))
    sources = ({"helius": funders.get("cohorts")} if funders else {}) | dict(provider_cohorts or {})
    if any(sources.values()):
        lines += _cohort_lines(sources)
    if funders:
        v = funders["verdict"]
        lines += ["", "## Funder batches (Helius funded-by)"]
        if funders.get("aborted"):
            lines.append(f"- RUN STOPPED EARLY: {funders['aborted']}. Results below are PARTIAL.")
        level = v["level"]
        shown = level if level != "NOT_DETECTED" else "not detected (the funder-batch detector sees only unlabeled single-funder batches; not an all-clear)"
        lines.append(f"- FACTORY_PATTERN: **{shown}** - {v['batch_funders']} unlabeled tight-batch funders, {v['wallets']} wallets, {v['share_pct']}% of supply")
        lines += [f"  - {r}" for r in v["reasons"]]
        lines += ["- " + v["thresholds_are"], FULL_ADDRESSES_LINE, "", "| Funder | Label | Wallets | Supply % | Window s | Tight |", "|---|---|---|---|---|---|"]
        for b in funders["batches"][:15]:
            lines.append(f"| `{b['funder'][:8]}...` | {pw.neutral(b['funder_name']) or 'unlabeled'} | {b['wallets']} | {b['share_pct']} | {b['window_s']} | {b['tight']} |")
        if funders["upstream"]:
            names = sorted({(pw.neutral(u["upstream_name"]) or u["upstream"][:8]) for u in funders["upstream"]})
            lines += ["", "Upstream funders of the batch funders: " + ", ".join(names)]
    lines += ["", GLOSSARY]
    removed = pw.count(lines)
    if removed:  # provider text that held a verdict word is shown as the placeholder; say how many the report shows
        lines.insert(removed_at, f"- {pw.removed_line(removed)}")
    return "\n".join(_oneline(ln) for ln in lines) + "\n"


def _public(obj: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in obj.items() if not k.startswith("_")}


def _write(out: Path, holders: dict[str, Any], funders: dict[str, Any] | None, credits: int, mint: str, findings: list[dict[str, Any]] | None = None, provider_cohorts: dict[str, dict[str, Any]] | None = None, solscanner: dict[str, Any] | None = None,
           extras: dict[str, Any] | None = None) -> str:
    # owner_balances (every owner's raw balance, in the order Helius listed them) and credits_spent let the offline
    # `assess` subcommand rebuild exactly the same assessment later, without a network call.
    (out / "holders.json").write_text(json.dumps(_public(holders) | {"owner_balances": holders["_balances"], "credits_spent": credits}, indent=1))
    if funders:
        (out / "funders.json").write_text(json.dumps(funders, indent=1))
    return _write_assessment(out, mint, holders, funders, credits, findings, provider_cohorts, solscanner, extras=extras)


def _write_assessment(out: Path, mint: str, holders: dict[str, Any], funders: dict[str, Any] | None, credits: int, findings: list[dict[str, Any]] | None,
                      provider_cohorts: dict[str, dict[str, Any]] | None, solscanner: dict[str, Any] | None, *, saved_at: str | None = None,
                      extras: dict[str, Any] | None = None) -> str:
    """assessment.json and report.md. Shared by report/funders (after collecting) and the offline assess subcommand.
    `extras` holds the raw saved map file and GMGN / Jupiter rows for the Bubblemaps member display (display only)."""
    sf = solscanner_finding_for(solscanner)
    ex = extras or {}
    display = bubblemaps_display(ex.get("map"), mint, holders, funders, ex.get("gmgn"), ex.get("jupiter")) if ex.get("map") is not None else None
    assessment = assess(_public(holders), funders, list(findings or []) + ([sf] if sf else []), provider_cohorts=provider_cohorts, solscanner=solscanner, bubblemaps_members=display)
    (out / "assessment.json").write_text(json.dumps(assessment, indent=1))
    report = markdown_report(mint, _public(holders), funders, credits, assessment, provider_cohorts, saved_at=saved_at)
    (out / "report.md").write_text(report)
    return report


def load_json_file(path: str, what: str) -> tuple[Any, float]:
    """Read a local JSON input (no network). Returns (data, file age in minutes). Errors name the flag, never the content."""
    p = Path(path)
    try:
        age = max(0.0, (time.time() - p.stat().st_mtime) / 60)
        return json.loads(p.read_text(encoding="utf-8")), age
    except (OSError, UnicodeDecodeError, ValueError):
        raise ConfigError(f"{what} is not a readable JSON file") from None


def load_findings(args: argparse.Namespace, mint: str, raw: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Findings from the saved input files. `raw`, when given, receives the saved map file as read (key "map"), for the
    Bubblemaps member display (HS-BM-MEMBERS-T1); the findings are the same either way."""
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    if getattr(args, "bubblemaps_json", None):
        data, age = load_json_file(args.bubblemaps_json, "--bubblemaps-json")
        findings.append(bubblemaps_finding(data, mint, age))
        if raw is not None:
            raw["map"] = data
        seen.add("bubblemaps_map")
    if getattr(args, "providers_json", None):
        data, _ = load_json_file(args.providers_json, "--providers-json")
        found = normalize_findings_file(data)
        rows = data.get("providers") if isinstance(data, dict) else data
        # HS-LABELS-T1 B1: a provider's identity is its name under the old character rule, read from the RAW name (as in
        # normalize_findings_file), never the printed name: "Safe Scanner" and "Clean Scanner" both print as
        # "[provider word removed] Scanner" and are still two providers. normalize_finding returns None only for a row
        # that is not an object, so the rows that are objects line up with the findings.
        names = [(_label_chars(r.get("provider")) or "unnamed_provider").lower() for r in rows if isinstance(r, dict)]
        for f, name in zip(found, names):
            if name in seen:
                raise ConfigError(f"provider {f['provider']} is given by both --bubblemaps-json and --providers-json")
            seen.add(name)
            findings.append(f)
    return findings


def solscanner_finding_for(result: dict[str, Any] | None, now: dt.datetime | None = None) -> dict[str, Any] | None:
    """Corroboration-only finding from a SolScanner result (None when the source was not used). It never carries a
    cluster or bundle number, so it can raise CAUTION at most and never counts as a calm source."""
    if result is None:
        return None
    import solscanner_scan

    raw = solscanner_scan.solscanner_finding(result, now)
    finding = normalize_finding({k: v for k, v in raw.items() if k != "note"})
    # HS-LABELS-T1 R2: the hint ("corrob only 10w r96 44pct ...") and detail are this tool's own text, built from validated
    # numbers: the old character rule only, never the provider rule ("10w" must stay 10 wallets, not read as a word)
    finding["alarm_hint"], finding["detail"] = _label_chars(raw.get("alarm_hint")), _label_chars(raw.get("detail")) or ""
    finding["note"] = str(raw.get("note") or "")[:240]
    return finding


def validate_solscanner_result(data: Any) -> dict[str, Any]:
    """Revalidate a SAVED SolScanner result with the same strictness as the live parser, so an edited or corrupted file
    cannot feed bad numbers into the report. Raises ConfigError naming the problem, never the content."""
    import solscanner_scan as ss

    def bad(what: str) -> ConfigError:
        return ConfigError(f"--solscanner-json is not a valid saved SolScanner result: {what}")

    if not isinstance(data, dict) or not isinstance(data.get("groups"), list):
        raise bad("expected an object with a groups list")
    groups = data["groups"]
    if len(groups) > ss.MAX_GROUPS:
        raise bad(f"more than {ss.MAX_GROUPS} groups")
    occurrences = 0
    for group in groups:
        if not isinstance(group, dict) or not isinstance(group.get("wallets"), list):
            raise bad("a group is not an object with a wallets list")
        occurrences += len(group["wallets"])
        if occurrences > ss.MAX_OCCURRENCES:
            raise bad(f"more than {ss.MAX_OCCURRENCES} wallet rows")
        for w in group["wallets"]:
            if not isinstance(w, dict):
                raise bad("a wallet row is not an object")
            addr_ = w.get("address")
            share = w.get("share_pct")
            if not isinstance(addr_, str) or not 32 <= len(addr_) <= 44 or any(c not in ss._BASE58 for c in addr_):
                raise bad("a wallet address is not a valid base58 address")
            if isinstance(share, bool) or not isinstance(share, (int, float)) or not math.isfinite(share) or not 0 <= share <= 100:
                raise bad("a wallet share is not a number from 0 to 100")
        risk = group.get("risk_score")
        if risk is not None and (type(risk) is not int or not 0 <= risk <= 100):
            raise bad("a risk score is not an integer from 0 to 100")
        confidence = group.get("confidence")
        if confidence is not None and (not isinstance(confidence, str) or confidence not in ss._CONFIDENCE):
            raise bad("a confidence is not low, medium or high")
        bundle_type = group.get("bundle_type")
        if bundle_type is not None and (not isinstance(bundle_type, str) or not ss._LABEL.fullmatch(bundle_type)):
            raise bad("a bundle type is not a short plain label")
    for key, kind in (("is_stale", bool), ("scan_complete", bool)):
        if data.get(key) is not None and type(data[key]) is not kind:
            raise bad(f"{key} is not true or false")
    for key in ("scan_age_min",):
        v = data.get(key)
        if v is not None and (isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or v < 0):
            raise bad(f"{key} is not a non-negative number")
    reason = data.get("reason")
    if reason is not None and (not isinstance(reason, str) or not re.fullmatch(r"[a-z_]{1,40}", reason)):
        raise bad("reason is not a short lowercase code")
    mint_value = data.get("mint")
    if mint_value is not None and (not isinstance(mint_value, str) or not MINT_RE.match(mint_value)):
        raise bad("mint is not a valid base58 address")
    scanned = data.get("scanned_at")
    if scanned is not None:
        try:
            ok = isinstance(scanned, str) and len(scanned) <= 40 and re.fullmatch(r"[0-9T:.\-+Z]+", scanned) and dt.datetime.fromisoformat(scanned.replace("Z", "+00:00")) is not None
        except ValueError:
            ok = False
        if not ok:
            raise bad("scanned_at is not an ISO timestamp")
    # DS-SCANNER-FREE-T1: the collector's source facts (absent in older saved results). They are printed only through
    # solscanner_scan.source_text, so each one is a fixed value or a short lowercase code.
    if "source" in data and data["source"] is not None and data["source"] not in ss.SOURCES:
        raise bad("source is not legacy_keyless or scanner_browser")
    if data.get("keyless_status") is not None and data["keyless_status"] not in ss.KEYLESS_STATUSES:
        raise bad("keyless_status is not answered or failed")
    v = data.get("keyless_reason")
    if v is not None and (not isinstance(v, str) or not re.fullmatch(r"[a-z_]{1,40}", v)):
        raise bad("keyless_reason is not a short lowercase code")
    if data.get("keyless_error_code") is not None and data["keyless_error_code"] not in ss.ERROR_CODES:
        raise bad("keyless_error_code is not a known Scanner code")
    for key, lo, hi in (("keyless_http_status", 100, 599), ("scans_spent", 0, 1)):
        v = data.get(key)
        if v is not None and (type(v) is not int or not lo <= v <= hi):
            raise bad(f"{key} is not a whole number from {lo} to {hi}")
    for key in ("cache_hit", "needs_browser"):
        if data.get(key) is not None and type(data[key]) is not bool:
            raise bad(f"{key} is not true or false")
    if data.get("source") == "legacy_keyless" and data.get("keyless_status") != "answered":
        raise bad("source does not match the status of the endpoint it names")
    return data


def load_solscanner(args: argparse.Namespace, mint: str) -> dict[str, Any] | None:
    """--solscanner-json reads a saved result (offline); --solscanner fetches once, bounded, no credits. A failed
    fetch becomes an unavailable result (the run continues). Returns None when neither flag is given."""
    saved, live = getattr(args, "solscanner_json", None), getattr(args, "solscanner", False)
    if saved and live:
        raise ConfigError("use either --solscanner or --solscanner-json, not both")
    if saved:
        data, _ = load_json_file(saved, "--solscanner-json")
        validate_solscanner_result(data)
        if data.get("mint") != mint:
            return {"provider": "SolScanner", "mint": mint, "status": "unknown", "reason": "identity_mismatch", "groups": [], "scanned_at": None, "scan_age_min": None}
        return data
    if live:
        import solscanner_scan

        try:
            # DS-SCANNER-FREE-T1: the same free keyless read as the collector, labelled the same way (the same source line).
            return solscanner_scan.collect_keyless(mint)
        except Exception:  # noqa: BLE001 - never let a read-only corroboration source stop the run
            return {"provider": "SolScanner", "mint": mint, "status": "unknown", "reason": "network_error", "groups": [], "scanned_at": None, "scan_age_min": None}
    return None


def load_cohort_inputs(args: argparse.Namespace) -> tuple[dict[str, int], Any, Any]:
    acquisitions: dict[str, int] = {}
    if getattr(args, "acquisition_json", None):
        data, _ = load_json_file(args.acquisition_json, "--acquisition-json")
        if not isinstance(data, dict):
            raise ConfigError("--acquisition-json must hold a JSON object wallet -> unix time")
        acquisitions = normalize_acquisitions(data)
    gmgn = jup = None
    if getattr(args, "gmgn_holders_json", None):
        gmgn, _ = load_json_file(args.gmgn_holders_json, "--gmgn-holders-json")
    if getattr(args, "jupiter_holders_json", None):
        jup, _ = load_json_file(args.jupiter_holders_json, "--jupiter-holders-json")
    gmgn_cohort_rows(gmgn) if gmgn is not None else None  # fail loudly on a changed shape before any credit is spent
    jupiter_cohort_rows(jup) if jup is not None else None
    return acquisitions, gmgn, jup


# ----------------------------------------------------------------------------- offline assess (saved run folder)
# The dlmm-scan synthesis runs `assess` after every collector has finished, so the forensics collector never waits for
# the Bubblemaps map or any other source. It reads only the saved run folder and the saved input files, rebuilds the
# funders stage from funders.json `rows` with the same pure functions, and writes assessment.json and report.md. A run
# folder that is missing, for another mint, from an older version, or inconsistent is refused (exit 2), never guessed.

RUN_WARNINGS = frozenset({WARN_DEX_FAILED, WARN_TRUNCATED, WARN_NO_POOL})
RUN_ABORTS = frozenset({"credit budget reached", f"{MAX_CONSECUTIVE_FAILURES} consecutive failures", "credit budget reached during upstream trace"})
FUNDER_ROW_STATUSES = ("funded", "no_funding_record", "failed", "not_reached")
UPSTREAM_KEYS = ["batch_funder", "upstream", "upstream_name", "upstream_type", "amount_sol", "funded_at"]
SAVED_ADDRESS_RE = re.compile(r"^[A-Za-z0-9]{32,44}$")  # an address from a saved file that the report prints: letters and digits only


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _run_json(folder: Path, name: str) -> Any:
    try:
        return json.loads((folder / name).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError):
        raise ConfigError(f"--from: {name} is not a readable JSON file") from None


def _older_version(what: str) -> ConfigError:
    return ConfigError(f"--from: the run folder was written by an older version of this tool ({what}); run the forensics collector again (assess never guesses)")


def load_run_holders(raw: Any, mint: str) -> tuple[dict[str, Any], int]:
    """Validate a saved holders.json and rebuild the holder list as run_holders returned it (full ranking and balances
    included). The distribution and top_holders are recomputed from owner_balances and must match the saved ones."""

    def bad(what: str) -> ConfigError:
        return ConfigError(f"--from: holders.json {what}")

    if not isinstance(raw, dict):
        raise bad("is not a holder-list object")
    if raw.get("mint") != mint:
        raise ConfigError("--from: the run folder is for a different mint (holders.json does not match the mint given)")
    missing = [k for k in ("top_holders", "owner_balances", "credits_spent") if k not in raw]
    if missing:
        raise _older_version(f"holders.json has no {', '.join(missing)}")
    balances, credits, pools = raw["owner_balances"], raw["credits_spent"], raw.get("pool_addresses")
    if not isinstance(balances, dict) or not all(type(v) is float and math.isfinite(v) for v in balances.values()):
        raise bad("owner_balances is not an object of owner -> balance")
    if not _is_int(credits) or credits < 0:
        raise bad("credits_spent is not a whole number of credits")
    if not isinstance(pools, list) or not all(isinstance(p, str) for p in pools):
        raise bad("pool_addresses is not a list of addresses")
    if not _is_int(raw.get("token_accounts")) or not isinstance(raw.get("truncated"), bool):
        raise bad("token_accounts or truncated has the wrong type")
    launch = raw.get("earliest_pair_created_at")
    if launch is not None and not _is_int(launch):
        raise bad("earliest_pair_created_at is not a unix time")
    warnings = raw.get("warnings")
    if not isinstance(warnings, list) or not all(isinstance(w, str) and w in RUN_WARNINGS for w in warnings):
        raise bad("warnings are not the warnings this tool writes")
    if raw["truncated"] != (WARN_TRUNCATED in warnings):  # run_holders writes the warning exactly when the list was truncated
        raise bad("is inconsistent: truncated does not match the truncation warning (the files were edited or mixed)")
    dist = distribution(balances, set(pools))
    ranked = dist.pop("ranked", [])
    if dist != raw.get("distribution"):
        raise bad("is inconsistent: its owner_balances do not give its saved distribution (the files were edited or mixed)")
    top = raw["top_holders"]
    if not isinstance(top, list) or top != top_holder_rows(ranked, set(pools), len(ranked))[: len(top)]:
        raise bad("is inconsistent: top_holders do not match its owner_balances (the files were edited or mixed)")
    holders = {"mint": mint, "token_accounts": raw["token_accounts"], "truncated": raw["truncated"], "earliest_pair_created_at": launch, "pool_addresses": pools,
               "distribution": dist, "warnings": warnings, "top_holders": top, "_ranked": ranked, "_balances": balances}
    return holders, credits


def _saved_label(value: Any) -> Any:
    """A funder label read back from a saved funders.json (HS-LABELS-T1). A label saved before the verdict-word rule (it is
    exactly what the old character rule gives) gets the rule now, so an older run folder still assesses and prints no
    verdict word; a label saved by this version is unchanged by it; anything else is kept exactly as saved, so an edited
    label still fails the rebuild comparison."""
    return safe_label(value) if isinstance(value, str) and _label_chars(value) == value else value


def _saved_labels(raw: dict[str, Any]) -> dict[str, Any]:
    """A copy of a saved funders.json with every funder label passed through _saved_label (rows, batches, funder types);
    only keys that are present are touched, so a missing key still fails the comparison."""
    saved = dict(raw)
    if isinstance(raw.get("rows"), list):
        saved["rows"] = [{**r, **{k: _saved_label(r[k]) for k in ("funder_name", "funder_type") if k in r}} if isinstance(r, dict) else r for r in raw["rows"]]
    if isinstance(raw.get("batches"), list):
        saved["batches"] = [{**b, **{k: _saved_label(b[k]) for k in ("funder_name", "funder_type") if k in b}} if isinstance(b, dict) else b for b in raw["batches"]]
    if isinstance(raw.get("funder_types"), dict):
        saved["funder_types"] = {_saved_label(k): v for k, v in raw["funder_types"].items()}
    return saved


def load_run_funders(raw: Any, holders: dict[str, Any], acquisitions: dict[str, int] | None) -> dict[str, Any]:
    """Validate a saved funders.json against the holder list and rebuild the funders stage from its `rows` with
    funders_result (records, batches, classification, cohorts with this run's acquisition times, coverage). Only
    `aborted`, `upstream` and the `errors` texts come from the file as saved: they cannot be recomputed offline.
    HS-LABELS-T1: funder labels saved before the verdict-word rule are read with the rule applied (_saved_labels), so
    the rebuilt files compare equal and the report prints no verdict word; an edited label is still refused."""

    def bad(what: str) -> ConfigError:
        return ConfigError(f"--from: funders.json {what}")

    if not isinstance(raw, dict):
        raise bad("is not a funders object")
    if "rows" not in raw:
        raise _older_version("funders.json has no rows")
    rows, errors, aborted, upstream = raw["rows"], raw.get("errors"), raw.get("aborted"), raw.get("upstream")
    if not isinstance(rows, list) or not all(isinstance(r, dict) and r.get("status") in FUNDER_ROW_STATUSES for r in rows):
        raise bad("rows are not funder rows")
    pools = set(holders["pool_addresses"])
    ranked = [o for o, _ in holders["_ranked"] if o not in pools][: len(rows)]
    if [r.get("wallet") for r in rows] != ranked:
        raise ConfigError("--from: funders.json does not belong to holders.json (its wallets are not the top holders of this holder list)")
    failed = [r["wallet"] for r in rows if r["status"] == "failed"]
    if not isinstance(errors, dict) or set(errors) != set(failed) or not all(isinstance(m, str) for m in errors.values()):
        raise bad("errors do not match the failed rows")
    if aborted is not None and (not isinstance(aborted, str) or aborted not in RUN_ABORTS):
        raise bad("aborted is not a stop reason this tool writes")
    if not aborted and any(r["status"] == "not_reached" for r in rows):  # wallets go unreached only when the run stopped early
        raise bad("is inconsistent: some wallets were not reached but the run is not marked as stopped early (the files were edited or mixed)")
    if not all(SAVED_ADDRESS_RE.match(r["funder"]) if isinstance(r.get("funder"), str) else r["status"] != "funded" for r in rows):
        raise bad("a funded row has no plain funder address")
    outcomes: dict[int, tuple[str, Any]] = {}
    for i, r in enumerate(rows):  # the lookup outcome each row was made from
        if r["status"] == "funded":
            outcomes[i] = ("ok", {"funder": r.get("funder"), "funderName": r.get("funder_name"), "funderType": r.get("funder_type"), "timestamp": r.get("funded_at"), "amount": r.get("first_amount_sol")})
        elif r["status"] == "no_funding_record":
            outcomes[i] = ("ok", None)
        elif r["status"] == "failed":
            outcomes[i] = ("error", errors[r["wallet"]])
    result = funders_result(holders, ranked, outcomes, aborted=aborted, acquisitions=acquisitions)
    saved = _saved_labels(raw)
    for key in ("rows", "errors", "examined_wallets", "requested_wallets", "failed_wallets", "with_funder", "covered_supply_pct", "examined_supply_pct", "verdict", "batches", "funder_types"):
        if result[key] != saved.get(key):
            raise ConfigError(f"--from: funders.json is inconsistent with holders.json ({key} differs when rebuilt from the rows; the files were edited or mixed)")
    if not isinstance(upstream, list) or (upstream and aborted is not None):
        raise bad("upstream is not a list of upstream rows (or a run that stopped early lists some)")
    traced = [b["funder"] for b in result["batches"] if not b["labeled"]][:UPSTREAM_TRACE_LIMIT]
    last = -1
    for u in upstream:
        ok = isinstance(u, dict) and list(u) == UPSTREAM_KEYS and u["batch_funder"] in traced[last + 1:]
        ok = ok and isinstance(u["upstream"], str) and bool(SAVED_ADDRESS_RE.match(u["upstream"]))
        ok = ok and all(u[k] is None or (isinstance(u[k], str) and safe_label(_saved_label(u[k])) == _saved_label(u[k])) for k in ("upstream_name", "upstream_type"))
        ok = ok and (u["amount_sol"] is None or isinstance(u["amount_sol"], (int, float))) and (u["funded_at"] is None or isinstance(u["funded_at"], int))
        if not ok:
            raise bad("upstream rows do not match the unlabeled batch funders of this run")
        last = traced.index(u["batch_funder"], last + 1)
    result["upstream"] = [{**u, "upstream_name": _saved_label(u["upstream_name"]), "upstream_type": _saved_label(u["upstream_type"])} for u in upstream]
    return result


def _assess_main(args: argparse.Namespace, mint: str) -> int:
    """The offline `assess` subcommand: saved files only. No network call, no key, no credits."""
    saved_inputs: dict[str, Any] = {}
    findings = load_findings(args, mint, saved_inputs)  # the same loaders and validators as report
    acquisitions, gmgn_payload, jupiter_payload = load_cohort_inputs(args)
    solscanner = load_solscanner(args, mint)
    folder = Path(args.from_dir)
    if not folder.is_dir():
        raise ConfigError("--from is not a folder: give the run folder the forensics collector wrote (its --out)")
    if not (folder / "holders.json").is_file():
        raise ConfigError("--from holds no holders.json: the forensics collector did not save this run (or stopped before saving)")
    saved_at = _utc(int((folder / "holders.json").stat().st_mtime))
    holders, credits = load_run_holders(_run_json(folder, "holders.json"), mint)
    funders = None
    if (folder / "funders.json").is_file():
        raw = _run_json(folder, "funders.json")
        funders = load_run_funders(raw, holders, acquisitions)
        if raw.get("acquisition_supplied") and not acquisitions:
            print("note: the collector run was given --acquisition-json; pass the same file to assess or the acquisition-time check counts as not run", file=sys.stderr)
    else:
        print("note: the run folder has no funders.json (holders-only or interrupted collector run): the funding detectors count as not run", file=sys.stderr)
    provider_cohorts = provider_cohort_sources(holders, gmgn_payload, jupiter_payload, acquisitions)
    out = Path(args.out) if args.out else folder
    try:
        out.mkdir(parents=True, exist_ok=True)
    except OSError:
        raise ConfigError("--out is not a writable folder") from None
    extras = {"map": saved_inputs.get("map"), "gmgn": gmgn_payload, "jupiter": jupiter_payload}
    report = _write_assessment(out, mint, holders, funders, credits, findings, provider_cohorts, solscanner, saved_at=saved_at, extras=extras)
    print(report)
    print(f"[assessed offline from {folder}, written to {out}; no network call, 0 Helius credits]", file=sys.stderr)
    return 0


def _add_input_flags(p: argparse.ArgumentParser, *, live: bool) -> None:
    """Saved-file inputs shared by funders/report and assess (`--solscanner`, the one live read, only when live)."""
    p.add_argument("--bubblemaps-json", metavar="PATH", help="saved bubblemaps_map.py JSON for this mint; without it the map step counts as not run and the verdict cannot exceed LIMITED")
    p.add_argument("--acquisition-json", metavar="PATH", help="JSON object wallet -> unix time of first token acquisition (e.g. GMGN start_holding_at); enables the acquisition-time check")
    if live:
        p.add_argument("--solscanner", action="store_true", help="read the public SolScanner scan once (no key, no credits, bounded; a failure is reported and the run continues)")
    p.add_argument("--solscanner-json", metavar="PATH", help="saved SolScanner result (the dict solscanner_scan.collect_solscanner returns) for offline use")
    p.add_argument("--gmgn-holders-json", metavar="PATH", help="already-fetched GMGN top-holders JSON (raw GMGN rows, the gmgn_rows.py collector's gmgn_top100.json, or the lp-research-companion cleaned rows); run the cohort detector over its funding rows (no network)")
    p.add_argument("--jupiter-holders-json", metavar="PATH", help="already-fetched Jupiter datapi holders JSON; run the cohort detector over its funding rows (no network)")
    p.add_argument("--providers-json", metavar="PATH", help='JSON list (or {"unit": "percent"|"fraction", "providers": [...]}) of findings [{provider, status, largest_cluster_pct, cluster_sum_pct, bundle_pct, data_age_min, unit, alarm_hint}]; a missing unit with all shares <= 1 is rejected as ambiguous')


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("holders", "funders", "report"):
        p = sub.add_parser(name)
        p.add_argument("mint")
        if name != "holders":
            _add_input_flags(p, live=True)
            p.add_argument("--funders-top", type=int, default=None, help=f"holders to run funded-by on (100 credits each), 1-1000, at most --top (default: the smaller of {DEFAULT_FUNDERS_TOP} and --top, since 2026-10-28, owner: Helius budget)")
            p.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help=f"funded-by lookups run at once, 1-{MAX_WORKERS} (default {DEFAULT_WORKERS}); all share one pace of at most {REQUEST_RATE_CAP_PER_S} Helius requests/s and one 429 pause; same credits; 1 = the old one-at-a-time order")
        p.add_argument("--top", type=int, default=250, help="holders listed in holders.json, 1-1000 (default 250); funded-by runs on --funders-top of them")
        p.add_argument("--max-credits", type=int, default=40_000, help="stop before exceeding this many Helius credits")
        p.add_argument("--env-file", help="path to the repository .env (HELIUS_API_KEY in the environment is used first)")
        p.add_argument("--exclude", action="append", default=[], metavar="ADDRESS", help="extra pool/infrastructure owner to exclude (repeatable)")
        p.add_argument("--out", help="output directory (default <skill>/reports/<ts>-<mint>)")
    p = sub.add_parser("assess", help="offline: rebuild assessment.json and report.md from a saved run folder and saved input files; no network call, no key, 0 credits")
    p.add_argument("mint")
    p.add_argument("--from", dest="from_dir", required=True, metavar="RUN_DIR", help="run folder the funders (or report) collector wrote: holders.json, plus funders.json when the funded-by stage ran")
    _add_input_flags(p, live=False)
    p.add_argument("--out", help="output directory for assessment.json and report.md (default: the --from folder)")
    args = parser.parse_args(argv)
    try:
        mint = _validate_mint(args.mint)
        if args.cmd == "assess":
            return _assess_main(args, mint)
        if not 1 <= args.top <= 1000:
            raise ConfigError("--top must be between 1 and 1000")
        funders_top = getattr(args, "funders_top", None)
        if funders_top is None:
            funders_top = min(DEFAULT_FUNDERS_TOP, args.top)
        if not 1 <= funders_top <= 1000:
            raise ConfigError("--funders-top must be between 1 and 1000")
        funders_top = min(funders_top, args.top)  # funded-by never covers more holders than the list
        workers = getattr(args, "workers", 1)
        if not 1 <= workers <= MAX_WORKERS:
            raise ConfigError(f"--workers must be between 1 and {MAX_WORKERS}")
        saved_inputs: dict[str, Any] = {}
        findings = load_findings(args, mint, saved_inputs)  # local files only; fail before any credit is spent
        acquisitions, gmgn_payload, jupiter_payload = load_cohort_inputs(args)
        extras = {"map": saved_inputs.get("map"), "gmgn": gmgn_payload, "jupiter": jupiter_payload}
        solscanner = load_solscanner(args, mint)
        env_file = None
        if not os.environ.get(KEY_NAME):
            env_file = find_env_file(args.env_file)
        client = Helius(load_key(env_file), Budget(args.max_credits))
        if args.cmd in ("funders", "report") and estimate_funder_cost(funders_top) > args.max_credits:
            raise BudgetError(f"estimated cost {estimate_funder_cost(funders_top)} exceeds --max-credits {args.max_credits}; lower --funders-top or raise the cap")
        holders = run_holders(client, mint, set(args.exclude), args.top)
        out = _outdir(mint, args.out)
        provider_cohorts = provider_cohort_sources(holders, gmgn_payload, jupiter_payload, acquisitions) if args.cmd in ("funders", "report") else None
        _write(out, holders, None, client.budget.spent, mint, findings, provider_cohorts, solscanner, extras)  # checkpoint before the expensive stage
        funders = run_funders(client, holders, top=funders_top, acquisitions=acquisitions, workers=workers) if args.cmd in ("funders", "report") else None
        report = _write(out, holders, funders, client.budget.spent, mint, findings, provider_cohorts, solscanner, extras)
        print(report)
        print(f"[written to {out}]", file=sys.stderr)
        return 4 if funders and funders.get("aborted") == "credit budget reached" else 0
    except ForensicsError as err:
        print(f"error: {err}", file=sys.stderr)
        return err.exit_code
    except Exception as err:  # noqa: BLE001 - never show a traceback: it can contain request URLs with the key
        print(f"error: unexpected {type(err).__name__}", file=sys.stderr)
        return 3
    except KeyboardInterrupt:  # Ctrl-C: no traceback; lookup threads are daemons, so nothing holds the exit up
        print("error: interrupted (Ctrl-C); no new Helius lookups were started", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
