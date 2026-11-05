#!/usr/bin/env python3
"""Scanner (formerly SolScanner) token scan read from the owner's logged-in scanner.net page, for dlmm-scan (follow-up-wave
collector `scanner_browser`, DS-SCANNER-FREE-T1): the browser fallback of the free keyless `solscanner` collector.

Owner decision 2026-11-04 (~21:30 WIB): "just use the free one then, make the skill use the free fallback only as well or dont
use the api, and use the solscanner way of using camoufox with scanner.net login". The keyless endpoint answers only for
tokens Scanner has cached (a fresh token: HTTP 401 NOT_AUTHENTICATED, "Please log in"); this lane reads such a token through
the owner's own logged-in scanner.net page. The older lp-research-companion scripts (open-solscanner-profile.py,
fetch-solscanner.py) used the same profile but read the session token from its local storage and deleted lock files; this
lane does neither: the page makes its own logged-in request and only the answer the page received is read.

When it reads (it reads <RUN>/solscanner.json, a first-wave file, so it is a follow-up lane):
- solscanner.json says needs_browser (the keyless read failed: not cached / needs login, another HTTP status, a timeout, a
  renamed field), or there is no solscanner.json: one read of the token's scanner page.
- solscanner.json read the scan (source legacy_keyless): not_needed, NO browser launched.
- an unreadable or foreign file, or a failure the browser cannot help (needs_browser false): skipped, no browser.

The read: Camoufox, headless, a persistent context on the owner's profile (PROFILE_DIR, the "solscanner" profile; --profile for
another folder), ONE page load of https://www.scanner.net/sol/scanner/<MINT> (the docs' "Deep Scan of an address" URL,
provider-docs current/scanner/fulldocs.pages/docs/urls.md): no click, no typing, no scrolling, never a login. A hard 90 s
wall-clock limit (HARD_LIMIT_S) counts from before the launch; every browser step gets only what is left of it, and the browser
is always closed, on errors too. What is read:
- the page's own address (whether it left www.scanner.net);
- the page's own requests to Scanner's hosts: whether the token-scan request (GET /contracts/<MINT>/scan/stream on
  api.scanner.net or api.solscanner.app) started and, once it finished, its status and its response body (the event stream:
  cache_hit, then complete with bundleGroups), parsed by solscanner_scan's parser (the same field checks); for the other
  requests to those hosts only the method, the status and whether the path is this token's /contracts path (else "other");
- only when no scan request started, or once after the page's scan request answered 403: how many elements show exactly the
  text "Login" (the logged-out page shows its Login button where the scan would be; seen live 2026-11-04 with an empty
  profile). A number, never the page text.
Never a cookie, a request or response header, a token, local storage, session storage or IndexedDB: none is read, saved or
printed. The session token never leaves the browser.

Logged out: login_needed with the owner's login command (LOGIN_COMMAND): the page still showed its Login button
LOGGED_OUT_AFTER_S after it loaded with no scan request started, the scan request answered 401, or 403 while the page shows its
Login button, or the page left www.scanner.net. A 403 without the Login button is not_read (access_refused), never a login
prompt. A 402 (Scanner's INSUFFICIENT_CREDITS: the account's monthly scans are used up) is not_read (out_of_scans), with no
scan spent. Signed in (no Login button) but no scan request within START_GRACE_S: not_read (scan_not_started; a click may
be needed, and this lane never clicks).

Scans: a cached result (the stream starts with cache_hit and no "refreshed" save marker follows its complete event) spends
none of the account's scans; otherwise the page's scan spent 1 (Scanner: a token scan costs 1; failed scans refund). One page
load, so at most 1 scan per DLMM scan. The file records which, also when the answer could not be read. A fresh scan's answer
streams every step and sends the groups twice (a progress bundle_groups event and complete); normalize_answer keeps only the
final complete event and the scan time for the parser (live 2026-11-05).

Statuses (browser_status): ok, login_needed, not_read (profile_in_use, out_of_scans, access_refused, scan_not_started,
scan_not_finished, scan_failed, page_shape_changed, answer_without_complete, response_too_large, page_left, browser_failed, camoufox_missing, page_not_loaded), not_needed, skipped.
Collector: scanner_browser.py <MINT> --out <RUN> writes <RUN>/followup/scanner_browser.json and prints one line; exit 0
whenever the file was saved, exit 2 for a bad mint or --out. The file has solscanner.json's fields (groups, scan time, stale
flag, reason, source scanner_browser, cache_hit, scans_spent; it validates as a --solscanner-json input). PRESENTATION ONLY,
like every follow-up lane: --present <RUN> (offline) prints the one Scanner line with the scan's own corroboration note, which
the synthesis copies into the SolScanner block; never passed to assess, never counted toward NO_ALARM, never changes a FLAG
or verdict. Corroboration only, as the keyless read. Needs camoufox 0.5.x (the holder-tools Python, as the Bubblemaps map and
fomo_browser); Python >= 3.10.

--login (owner-run only, never part of a scan, never while a scan runs): the profile lock is tested first (in use: one line,
exit 3, nothing opened or deleted); else the profile folder is made only when missing and ONE VISIBLE Camoufox window opens on
https://www.scanner.net/sol/scanner, kept until the owner closes the last window or quits the browser (then it exits by
itself: it waits through Playwright, which sees the window close, the context close and the browser disconnect; a plain sleep
would not, live 2026-11-05; an hour at most, then the window is closed for the owner). The owner clicks Login and signs in;
this script never types or clicks, never reads a cookie, storage or the page, and never deletes, moves or edits a lock file.
"""

from __future__ import annotations

import argparse
import datetime as dt
import io
import json
import re
import sys
import time
from pathlib import Path
from typing import Any, Callable

if str(Path(__file__).resolve().parent) not in sys.path:  # python3 -I leaves the script's folder off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import fomo_browser as fb  # noqa: E402  (the profile lock test, never touching a lock, and the address parsing, by import)
import solscanner_scan as ss  # noqa: E402  (the event-stream parser, its field checks and the source wording)

PAGE_HOST = "www.scanner.net"
PAGE_URL = "https://www.scanner.net/sol/scanner/{mint}"
LOGIN_URL = "https://www.scanner.net/sol/scanner"
SCAN_HOSTS = frozenset({"api.scanner.net", "api.solscanner.app"})
SCAN_PATH = "/contracts/{mint}/scan/stream"
PROFILE_DIR = Path.home() / ".local/share/camoufox-stealth/profiles/solscanner"
LOGIN_COMMAND = ("\"${HOLDER_PYTHON:-python3}\" -I "
                 "skills/dlmm-scan/scripts/scanner_browser.py --login")
LOGIN_TEXT = "Login"
HARD_LIMIT_S = 90.0              # launch + page load + the page's scan, wall clock; the close comes after
LAUNCH_TIMEOUT_S = 30.0          # the launch's own share of it at most
POLL_MS = 250
LOGGED_OUT_AFTER_S = 15.0        # no scan request and the Login button still shown this long after the page loaded
START_GRACE_S = 30.0             # signed in (no Login button) but no scan request this long after the page loaded
MAX_REQUESTS_KEPT = 30           # the page's other requests to Scanner's hosts, kept as method / status / kind only
OUT_DIR, OUT_FILE = "followup", "scanner_browser.json"
KEYLESS_FILE = "solscanner.json"
SCHEMA = "dlmm-scan-scanner-browser/1"
STATUSES = ("ok", "login_needed", "not_read", "not_needed", "skipped")
MAX_ANSWER_BYTES = 8 * 1024 * 1024  # the page's whole answer; a fresh scan streams every step (live 2026-11-05: 0.52 MiB)
SHAPE_EVENTS_MAX, SHAPE_KEYS_MAX = 30, 40  # the answer's shape when it could not be read: event and key NAMES only, never a value
_EVENT_NAME = re.compile(r"[a-z_]{1,32}")
_KEY_NAME = re.compile(r"[A-Za-z0-9_]{1,40}")
NOTE = ("read-only: one page load in the owner's logged-in scanner.net profile, no click, no typing, never a login; only the "
        "answer the page itself received for its token-scan request is read; no cookie, header, token or storage value is read, "
        "saved or printed; corroboration only, as the free keyless read")
CANNOT_SEE = ("Scanner's labels and its cluster method are its own (undocumented); about the top 100 holders; a cached scan can be "
              "hours old; a fresh scan spends 1 of the account's scans (30 a month on the free plan); the page can change")
REASON_WORDS = {
    "profile_in_use": "profile in use",
    "profile_missing": "scanner.net profile folder missing (never logged in)",
    "login_button": "scanner.net profile logged out (the page shows its Login button)",
    "signed_out": "scanner.net profile logged out (the page's scan request was refused)",
    "page_left": "scanner.net profile logged out or the page changed (the page left www.scanner.net)",
    "scan_not_started": f"signed in, but the page started no scan within {START_GRACE_S:.0f} s (a click may be needed; this lane never clicks)",
    "scan_not_finished": f"the page's scan did not finish within {HARD_LIMIT_S:.0f} s",
    "scan_failed": "the page's scan request failed",
    "page_shape_changed": "page shape changed: the scan answer had no readable bundle groups",
    "answer_without_complete": "the page's scan answer ended before its complete event (the scan did not finish)",
    "response_too_large": f"the scan answer was larger than {MAX_ANSWER_BYTES // (1024 * 1024)} MiB",
    "out_of_scans": "the scanner.net account has no scans left this month",
    "access_refused": "the page's scan request was refused (HTTP 403) and the page shows no Login button",
    "browser_failed": "browser failed",
    "camoufox_missing": "camoufox not installed in this Python; run it with the holder-tools Python",
    "page_not_loaded": "the page did not load",
}
LOGGED_OUT = ("login_button", "signed_out", "page_left", "profile_missing")


# ----------------------------------------------------------------------------- the run folder


def keyless_state(run: Path, mint: str) -> tuple[str, str | None]:
    """solscanner.json as this lane reads it: ("needs_browser", reason), ("ok", None) when the keyless read got the scan,
    ("missing", None), ("no_browser", reason) for a failure the browser cannot help, ("unreadable", None) for a damaged or
    foreign file."""
    path = run / KEYLESS_FILE
    if not path.exists():
        return "missing", None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return "unreadable", None
    if not isinstance(data, dict) or data.get("mint") != mint:
        return "unreadable", None
    reason = ss._code_text(data.get("keyless_reason") or data.get("reason")) if (data.get("keyless_reason") or data.get("reason")) else None
    if data.get("needs_browser") is True:
        return "needs_browser", reason
    if data.get("source") == "legacy_keyless":
        return "ok", None
    return "no_browser", reason


# ----------------------------------------------------------------------------- the page's own scan request (untrusted answer)


class _Body:
    """The page's captured event stream, handed to solscanner_scan's parser as if it had read it itself."""

    status = 200

    def __init__(self, body: bytes) -> None:
        self._io = io.BytesIO(body)
        self.headers = {"Content-Type": "text/event-stream"}

    def read(self, size: int = -1) -> bytes:
        return self._io.read(size)

    def __enter__(self) -> "_Body":
        return self

    def __exit__(self, *args: Any) -> bool:
        return False


class _BodyOpener:
    def __init__(self, body: bytes) -> None:
        self.body = body

    def open(self, request: Any, timeout: Any = None) -> _Body:
        return _Body(self.body)


class Tap:
    """Listens to the page's requests to Scanner's hosts: whether the token-scan request started, and, once it finished,
    its status and body. Of the other requests to those hosts only the method, the status and the kind of path are kept.
    Never a header."""

    def __init__(self, mint: str) -> None:
        self.scan_path = SCAN_PATH.format(mint=mint)
        self.token_prefix = f"/contracts/{mint}/"
        self.started = 0
        self._new: list[Any] = []
        self.answers: list[tuple[int | None, bytes | None]] = []
        self.others: list[dict[str, Any]] = []

    def _scanner(self, request: Any) -> tuple[str, str] | None:
        host, path = fb._host_path(request.url)
        return (host, path) if host in SCAN_HOSTS else None

    def request(self, request: Any) -> None:
        try:
            where = self._scanner(request)
        except Exception:  # noqa: BLE001 - a listener never raises into the browser
            return
        if where and where[1] == self.scan_path:
            self.started += 1

    def finished(self, request: Any) -> None:
        try:
            if self._scanner(request):
                self._new.append(request)
        except Exception:  # noqa: BLE001
            return

    def poll(self) -> None:
        while self._new:
            request = self._new.pop(0)
            try:
                host, path = self._scanner(request) or ("", "")
                response = request.response()
                status = response.status if response is not None else None
                if path == self.scan_path:
                    body = response.body() if response is not None and status == 200 else None
                    self.answers.append((status, body))
                elif len(self.others) < MAX_REQUESTS_KEPT:
                    kind = path[len(self.token_prefix) - 1:] if path.startswith(self.token_prefix) else "other"
                    self.others.append({"method": request.method if isinstance(request.method, str) else None, "host": host,
                                        "path": f"/contracts/<MINT>{kind}" if kind != "other" else "other", "status": status})
            except Exception:  # noqa: BLE001 - an unreadable answer counts as nothing
                continue


def camoufox_launcher(profile: Path, timeout_ms: float) -> Any:
    from camoufox.sync_api import Camoufox  # lazy: the tests and the not-needed path never import a browser
    return Camoufox(persistent_context=True, user_data_dir=str(profile), headless=True, humanize=True, block_webrtc=True, timeout=timeout_ms)


def _login_button(page: Any) -> bool | None:
    """The one read of the rendered page: whether an element shows exactly the text "Login" (a number compared to 0, never the
    page text). None when it cannot be told."""
    try:
        return page.get_by_text(LOGIN_TEXT, exact=True).count() > 0
    except Exception:  # noqa: BLE001 - unknown
        return None


def _went(url: Any) -> str | None:
    if str(url) in ("", "about:blank"):
        return None
    host, _ = fb._host_path(url)
    return None if host == PAGE_HOST else "other_host"


def read_page(mint: str, profile: Path, *, launcher: Callable[[Path, float], Any] | None = None,
              clock: Callable[[], float] = time.monotonic) -> dict[str, Any]:
    """One load of the token's scanner page in the profile, read-only, within HARD_LIMIT_S from before the launch. It stops
    once the page's scan answer finished, the page left www.scanner.net, the Login button was still shown LOGGED_OUT_AFTER_S
    after the load with no scan request, or no scan request started within START_GRACE_S. Never raises; the browser is
    closed by the launcher's context manager, on errors too."""
    start = clock()
    deadline = start + HARD_LIMIT_S
    tap = Tap(mint)
    facts: dict[str, Any] = {"launched": False, "page_loads": 0, "went": None, "error": None, "timed_out": False, "tap": tap,
                             "login_button": None, "not_started": False}

    def left_ms() -> float:
        return max(1.0, (deadline - clock()) * 1000.0)

    try:
        with (launcher or camoufox_launcher)(profile, min(LAUNCH_TIMEOUT_S * 1000.0, left_ms())) as context:
            facts["launched"] = True
            pages = list(context.pages)
            page = pages[0] if pages else context.new_page()
            page.on("request", tap.request)
            page.on("requestfinished", tap.finished)
            facts["page_loads"] = 1
            try:
                page.goto(PAGE_URL.format(mint=mint), wait_until="commit", timeout=left_ms())
            except Exception as err:  # noqa: BLE001 - a slow load still gets the rest of the time; a failed one ends here
                if "timeout" not in type(err).__name__.lower():
                    facts["error"] = "page_not_loaded"
            loaded = clock()
            while facts["error"] is None:
                tap.poll()
                if tap.answers:
                    break
                facts["went"] = facts["went"] or _went(page.url)
                if facts["went"]:
                    break
                waited = clock() - loaded
                if not tap.started and waited >= LOGGED_OUT_AFTER_S:
                    facts["login_button"] = _login_button(page)
                    if facts["login_button"]:
                        break
                    if facts["login_button"] is False and waited >= START_GRACE_S:
                        facts["not_started"] = True
                        break
                if clock() >= deadline:
                    facts["timed_out"] = True
                    break
                page.wait_for_timeout(min(float(POLL_MS), left_ms()))
            if tap.answers and tap.answers[0][0] == 403 and facts["login_button"] is None:
                facts["login_button"] = _login_button(page)  # a 403 is a logout only when the page also shows its Login button
    except ModuleNotFoundError:
        facts["error"] = "camoufox_missing"
    except Exception:  # noqa: BLE001 - never a traceback (it could carry page details); a fixed code
        facts["error"] = facts["error"] or "browser_failed"
    facts["seconds"] = round(clock() - start, 1)
    return facts


# ----------------------------------------------------------------------------- collect


def _iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _base(mint: str, fetched_at: str, keyless: tuple[str, str | None]) -> dict[str, Any]:
    result = ss._empty(mint, fetched_at, "not_attempted")
    result.update({
        "schema": SCHEMA, "collector": "scanner_browser", "source": None, "browser_status": "not_read", "browser_reason": None,
        "keyless_state": keyless[0], "keyless_status": "failed" if keyless[0] in ("needs_browser", "no_browser") else None,
        "keyless_reason": "not_run" if keyless[0] == "missing" else keyless[1], "cache_hit": None, "needs_browser": False, "scans_spent": None, "captured_at": None,
        "page": {"url": PAGE_URL.format(mint=mint), "browser_launched": False, "page_loads": 0, "clicks": 0, "typed": 0, "went": None,
                 "login_button_seen": None, "scan_requests_started": 0, "scan_answer_status": None, "scan_answer_bytes": None,
                 "scan_answer_reason": None, "scan_answer_shape": None, "scanner_requests": [],
                 "hard_limit_s": HARD_LIMIT_S, "seconds": None},
        "corroboration_only": True, "note": NOTE, "cannot_see": CANNOT_SEE,
    })
    return result


def _fail(result: dict[str, Any], status: str, reason: str) -> dict[str, Any]:
    result.update(browser_status=status, browser_reason=reason, reason=reason)
    return result


def collect_scanner_browser(mint: str, run: Path, *, profile: Path | None = None, launcher: Callable[[Path, float], Any] | None = None,
                            clock: Callable[[], float] = time.monotonic, now: Callable[[], float] = time.time) -> dict[str, Any]:
    """The scanner_browser.json result. Launches the browser only when solscanner.json says needs_browser or is missing."""
    profile = PROFILE_DIR if profile is None else profile
    keyless = keyless_state(run, mint)
    result = _base(mint, _iso(now()), keyless)
    if keyless[0] == "ok":
        return _fail(result, "not_needed", "keyless_ok")
    if keyless[0] in ("unreadable", "no_browser"):
        return _fail(result, "skipped", f"keyless_{keyless[0]}")
    if not profile.is_dir():
        return _fail(result, "login_needed", "profile_missing")
    if fb.profile_in_use(profile):
        return _fail(result, "not_read", "profile_in_use")
    facts = read_page(mint, profile, launcher=launcher, clock=clock)
    tap: Tap = facts["tap"]
    answer_status = tap.answers[0][0] if tap.answers else None
    result["page"].update(browser_launched=facts["launched"], page_loads=facts["page_loads"], went=facts["went"] or ("scanner_page" if facts["launched"] else None),
                          login_button_seen=facts["login_button"], scan_requests_started=tap.started, scan_answer_status=answer_status,
                          scanner_requests=tap.others, seconds=facts["seconds"])
    if facts["error"] == "browser_failed" and fb.profile_in_use(profile):
        facts["error"] = "profile_in_use"  # another browser took the profile while this one started
    if facts["error"]:
        return _fail(result, "not_read", facts["error"])
    if tap.answers:
        status, body = tap.answers[0]
        if status == 401:
            return _fail(result, "login_needed", "signed_out")
        if status == 402:  # Scanner's INSUFFICIENT_CREDITS (provider-docs current/scanner/fulldocs.pages/docs/api/keys.md): nothing charged
            result.update(scans_spent=0)
            return _fail(result, "not_read", "out_of_scans")
        if status == 403:
            return _fail(result, "login_needed", "login_button") if facts["login_button"] else _fail(result, "not_read", "access_refused")
        if status != 200 or body is None:
            return _fail(result, "not_read", "scan_failed")
        result["page"]["scan_answer_bytes"] = len(body)
        if len(body) > MAX_ANSWER_BYTES:
            return _fail(result, "not_read", "response_too_large")
        # the page's scan ran (status 200): what it cost is known from the stream itself, read or not
        reduced, shape = normalize_answer(body)
        result.update(cache_hit=shape["cached"], scans_spent=0 if shape["cached"] else 1)
        result["page"].update(scan_answer_events=shape["events"], scan_answer_complete_events=shape["complete_events"],
                              scan_answer_progress_group_events=shape["progress_bundle_groups_events"])
        if not shape["complete_events"]:
            result["page"].update(scan_answer_shape=answer_shape(body))
            return _fail(result, "not_read", "answer_without_complete")
        parsed = ss.collect_solscanner(mint, opener=_BodyOpener(reduced), now=lambda: dt.datetime.fromtimestamp(now(), dt.timezone.utc))
        if not ss._usable(parsed):
            result["page"].update(scan_answer_reason=ss._code_text(parsed.get("reason")), scan_answer_shape=answer_shape(body))
            return _fail(result, "not_read", "page_shape_changed")
        result.update(parsed)
        result.update(source="scanner_browser", browser_status="ok", browser_reason=None, cache_hit=shape["cached"], scans_spent=0 if shape["cached"] else 1,
                      captured_at=parsed.get("fetched_at"))
        return result
    if facts["went"]:
        return _fail(result, "login_needed", "page_left")
    if facts["login_button"]:
        return _fail(result, "login_needed", "login_button")
    if facts["not_started"]:
        return _fail(result, "not_read", "scan_not_started")
    return _fail(result, "not_read", "scan_not_finished" if tap.started else "scan_not_started")


def split_events(body: bytes) -> list[tuple[str | None, str]]:
    """The answer's server-sent events in order: (event name or None, the data text). No value is interpreted here."""
    events: list[tuple[str | None, str]] = []
    event, data = None, []
    for raw in body.split(b"\n") + [b""]:
        line = raw.rstrip(b"\r").decode("utf-8", "replace")
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
        elif not line and (event is not None or data):
            events.append((event, "\n".join(data)))
            event, data = None, []
    return events


def _refreshed(data: str) -> bool:
    try:
        payload = json.loads(data)
    except (ValueError, RecursionError):
        return False
    return isinstance(payload, dict) and payload.get("refreshed") is True


def normalize_answer(body: bytes) -> tuple[bytes, dict[str, Any]]:
    """The page's answer reduced to what solscanner_scan's parser reads, plus what it cost. Live 2026-11-05 (a token Scanner
    had not cached): a fresh scan streams every step (token_metadata, holders, status, entry/transfer/funding analysis,
    bundle_detection, a progress bundle_groups with the groups, proxy_detection, ...), then complete with the same groups as
    bundleGroups, then a cache_hit that marks the new scan saved (refreshed: true; it carries the scan time). A cached
    answer is cache_hit first, then complete (as the keyless endpoint sends it). The parser (the twin copy, unchanged)
    refuses a second set of groups, so the reduced stream keeps only the last complete event and one cache_hit: the one after
    it when there is one, else the leading one. Cost: none only when the answer starts with cache_hit and no refreshed
    marker follows complete; otherwise the page's scan spent 1 of the account's scans."""
    events = split_events(body)
    names = [n for n, _ in events]
    last = max((i for i, n in enumerate(names) if n == "complete"), default=None)
    trailing = [d for n, d in events[last + 1:] if n == "cache_hit"] if last is not None else []
    leading = events[0][1] if events and events[0][0] == "cache_hit" else None
    refreshed = any(_refreshed(d) for d in trailing)
    facts = {"events": len(events), "complete_events": names.count("complete"), "progress_bundle_groups_events": names.count("bundle_groups"),
             "cached": leading is not None and not refreshed, "fresh_scan_saved": refreshed}
    if last is None:
        return b"", facts  # no complete event: the scan did not finish; its progress groups are not read as the scan
    out = b""
    if not trailing and leading is not None:
        out += f"event: cache_hit\ndata: {leading}\n\n".encode()
    if '"bundleGroups"' not in events[last][1]:  # the older shape: the groups only in a bundle_groups event before complete
        older = [d for n, d in events[:last] if n == "bundle_groups"]
        if older:
            out += f"event: bundle_groups\ndata: {older[-1]}\n\n".encode()
    out += f"event: complete\ndata: {events[last][1]}\n\n".encode()
    if trailing:
        out += f"event: cache_hit\ndata: {trailing[-1]}\n\n".encode()
    return out, facts


def answer_shape(body: bytes) -> list[dict[str, Any]]:
    """The structure of a scan answer that could not be read, for the record: per event (at most SHAPE_EVENTS_MAX) its name,
    the JSON type of its data and, for an object, its top-level key NAMES (at most SHAPE_KEYS_MAX) and the length of any list
    under them. Never a value: names outside a plain pattern read "other"."""
    shape: list[dict[str, Any]] = []
    event, data = None, []
    for raw in body.split(b"\n") + [b""]:
        line = raw.rstrip(b"\r").decode("utf-8", "replace")
        if line.startswith("event:"):
            event = line[6:].strip()
        elif line.startswith("data:"):
            data.append(line[5:].lstrip(" "))
        elif not line and (event is not None or data):
            row: dict[str, Any] = {"event": event if isinstance(event, str) and _EVENT_NAME.fullmatch(event) else ("none" if event is None else "other")}
            try:
                payload = json.loads("\n".join(data)) if data else None
            except (ValueError, RecursionError):
                payload = ...
            row["data"] = "none" if payload is None else "not_json" if payload is ... else type(payload).__name__
            if isinstance(payload, dict):
                keys = sorted(payload)[:SHAPE_KEYS_MAX]
                row["keys"] = [k if _KEY_NAME.fullmatch(k) else "other" for k in keys]
                row["list_lengths"] = {k: len(payload[k]) for k in keys if _KEY_NAME.fullmatch(k) and isinstance(payload[k], list)}
            shape.append(row)
            event, data = None, []
            if len(shape) >= SHAPE_EVENTS_MAX:
                break
    return shape


def _cost(result: dict[str, Any]) -> str:
    if result.get("cache_hit") is True:
        return "cached, no scan spent"
    if result.get("scans_spent") == 1:
        return "spent 1 of the account's scans"
    return "scans spent not known"


def _plural(n: int) -> str:
    return f"{n} bundle group{'' if n == 1 else 's'}"


def status_line(result: dict[str, Any]) -> str:
    status, reason = result.get("browser_status"), result.get("browser_reason")
    if status == "ok":
        page = result["page"]
        return (f"ok ({_plural(len(result.get('groups') or []))} read from the logged-in scanner.net page; free endpoint not read: "
                f"{ss._code_text(result.get('keyless_reason'))}; {_cost(result)}; {page['page_loads']} page load, {page['seconds']} s; no click, no typing)")
    if status == "login_needed":
        return f"login_needed ({REASON_WORDS.get(reason, 'scanner.net profile logged out')}; to log in once, run: {LOGIN_COMMAND})"
    if status == "not_needed":
        return "not needed (the free keyless endpoint read the scan; no browser launched)"
    if status == "skipped":
        return (f"skipped (solscanner.json {'unreadable' if reason == 'keyless_unreadable' else 'says the free read failed in a way a browser cannot help'}; "
                "no browser launched)")
    if reason == "out_of_scans":
        return f"not read ({REASON_WORDS[reason]}; free endpoint not read: {ss._code_text(result.get('keyless_reason'))}; no scan spent)"
    spent = "; the page's scan spent 1 of the account's scans" if result.get("scans_spent") == 1 else "; the page's answer was cached, no scan spent" \
        if result.get("scans_spent") == 0 else ""
    return f"not read ({REASON_WORDS.get(reason, reason or 'unknown')}{spent})"


# ----------------------------------------------------------------------------- --present (offline)


def present(run: Path) -> list[str]:
    """The one Scanner line of the synthesis (offline: reads only followup/scanner_browser.json; no network, no key)."""
    head = "Scanner (formerly SolScanner)"
    path = run / OUT_DIR / OUT_FILE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return [f"{head}: logged-in page lane not run yet"]
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return [f"{head}: logged-in page lane file unreadable"]
    if not isinstance(data, dict) or data.get("schema") != SCHEMA or data.get("browser_status") not in STATUSES:
        return [f"{head}: logged-in page lane file unreadable"]
    status, reason = data["browser_status"], data.get("browser_reason")
    why = ss._code_text(data.get("keyless_reason"))
    if status == "ok":
        note = ss.solscanner_finding(data).get("note") or ""
        return [f"{head}: read from the logged-in scanner.net page; free endpoint not read: {why}; {_cost(data)}; {note} (presentation only: "
                "read after the forensics verdict, never in it)"]
    if status == "login_needed":
        return [f"{head}: not read (free endpoint not read: {why}; scanner.net profile logged out — to log in once, run: {LOGIN_COMMAND})",
                f"  {LOGIN_COMMAND}"]
    if status == "not_needed":
        return [f"{head}: read by the free keyless endpoint (no browser launched)"]
    if status == "skipped":
        return [f"{head}: not read (free endpoint not read: {why}; the logged-in page was not tried)"]
    if reason == "out_of_scans":
        return [f"{head}: not read ({REASON_WORDS[reason]}; free endpoint not read: {why}; no scan spent)"]
    words = REASON_WORDS.get(reason, ss._code_text(reason))
    spent = "; its scan spent 1 of the account's scans" if data.get("scans_spent") == 1 else ""
    return [f"{head}: not read (free endpoint not read: {why}; logged-in page not read: {words}{spent})"]


# ----------------------------------------------------------------------------- --login (owner-run only, never part of a scan)


LOGIN_POLL_S = fb.LOGIN_POLL_S
LOGIN_MAX_S = fb.LOGIN_MAX_S  # a safety net only: the window is closed for the owner after an hour
LOGIN_IN_USE = ("the scanner.net profile is in use by another browser (or a running scan): close it and run this again (close every "
                "Camoufox/Firefox window, or wait for the scan to finish; if a crashed browser left it locked, restart the computer). "
                "Nothing was opened, deleted or changed.")
LOGIN_STEPS = ("1) Click Login on scanner.net and sign in the way you usually do (Google, e-mail or wallet).",
               "2) When the page shows you are signed in, close the browser window.")
LOGIN_DONE = "Browser closed. Session stayed in the profile directory."
LOGIN_FAILED = "browser failed (no detail printed): close every Camoufox/Firefox window and run this again"
LOGIN_TIME_UP = fb.LOGIN_TIME_UP


def login_launcher(profile: Path) -> Any:
    from camoufox.sync_api import Camoufox  # lazy, as camoufox_launcher; VISIBLE
    return Camoufox(persistent_context=True, user_data_dir=str(profile), headless=False, humanize=True, block_webrtc=True)


def login(profile: Path | None = None, *, launcher: Callable[[Path], Any] | None = None, clock: Callable[[], float] = time.monotonic) -> int:
    """The owner's login window: the lock is tested first (in use: LOGIN_IN_USE, exit 3, nothing opened or deleted); else the
    profile folder is made only when missing and one visible window opens on scanner.net, kept until the owner closes the
    last window or quits the browser (exit 0; after LOGIN_MAX_S it is closed for the owner). It never types, never clicks,
    never reads a cookie, storage or the page, and never touches a lock file."""
    profile = PROFILE_DIR if profile is None else profile
    if fb.profile_in_use(profile):
        print(LOGIN_IN_USE)
        return 3
    try:
        profile.mkdir(parents=True, exist_ok=True)  # only when missing; nothing in it is touched
    except OSError:
        print("not opened (the profile folder could not be made)")
        return 1
    print(f"Profile: {profile}")
    print(f"Opening: {LOGIN_URL}")
    for step in LOGIN_STEPS:
        print(step)
    how = None
    try:
        with (launcher or login_launcher)(profile) as context:
            pages = list(context.pages)
            page = pages[0] if pages else context.new_page()
            page.goto(LOGIN_URL, wait_until="domcontentloaded")
            how = fb.wait_until_closed(context, clock=clock)  # the shared wait (Amendment A2: fomo_browser --login uses it too)
    except ModuleNotFoundError:
        print(f"not opened ({REASON_WORDS['camoufox_missing']})")
        return 1
    except Exception:  # noqa: BLE001 - never a traceback (it could carry a sign-in address); a fixed line
        if how is None:
            if fb.profile_in_use(profile):
                print(LOGIN_IN_USE)  # another browser took the profile while this one started
                return 3
            print(LOGIN_FAILED)
            return 1
        # the window was already closed: an error while the browser shuts down does not undo the login
    print(LOGIN_TIME_UP if how == "time_limit" else LOGIN_DONE)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read a Solana token's Scanner (formerly SolScanner) scan from the owner's logged-in scanner.net "
                                                 f"page when the free keyless endpoint could not (one headless page load, read-only, hard "
                                                 f"{HARD_LIMIT_S:.0f} s; at most 1 of the account's scans), and save {OUT_DIR}/{OUT_FILE}; it launches "
                                                 "no browser when solscanner.json read the scan. Or --present RUN (offline): the one Scanner line. "
                                                 "Or --login (owner only, never while a scan runs): a visible window to sign in, refused while the "
                                                 "profile is in use. Corroboration only.")
    parser.add_argument("mint", nargs="?")
    parser.add_argument("--out", metavar="RUN_DIR", help="run folder: reads solscanner.json, writes followup/scanner_browser.json")
    parser.add_argument("--present", metavar="RUN_DIR", help="offline: print the Scanner line from a saved run folder (no network, no browser)")
    parser.add_argument("--login", action="store_true", help="owner only, never while a scan runs: open a visible window on the profile to sign "
                                                              "in to scanner.net; refused (exit 3) while another browser or a scan holds it")
    parser.add_argument("--profile", metavar="DIR", help="another Camoufox profile folder (default: the owner's scanner.net profile)")
    args = parser.parse_args(argv)
    profile = Path(args.profile) if args.profile else None
    if args.login:
        if args.mint or args.out or args.present:
            print("error: --login takes only --profile", file=sys.stderr)
            return 2
        return login(profile)
    if args.present is not None:
        if args.mint or args.out or args.profile:
            print("error: --present takes only the run folder", file=sys.stderr)
            return 2
        run = Path(args.present)
        if not run.is_dir():
            print("error: --present is not a run folder", file=sys.stderr)
            return 2
        for line in present(run):
            print(line)
        return 0
    if not isinstance(args.mint, str) or not 32 <= len(args.mint) <= 44 or any(c not in ss._BASE58 for c in args.mint):
        print("error: mint is not a valid base58 Solana address", file=sys.stderr)
        return 2
    if not args.out:
        print("error: --out is required", file=sys.stderr)
        return 2
    run = Path(args.out)
    try:
        (run / OUT_DIR).mkdir(parents=True, exist_ok=True)
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    try:
        result = collect_scanner_browser(args.mint, run, profile=profile)
    except Exception:  # noqa: BLE001 - never a traceback
        result = _fail(_base(args.mint, _iso(time.time()), keyless_state(run, args.mint)), "not_read", "browser_failed")
    try:
        (run / OUT_DIR / OUT_FILE).write_text(json.dumps(result, indent=1), encoding="utf-8")
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    print(status_line(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
