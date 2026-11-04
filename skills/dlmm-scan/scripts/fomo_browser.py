#!/usr/bin/env python3
"""Fomo theses read from the owner's logged-in fomo.family page, for dlmm-scan (follow-up-wave collector `fomo_browser`,
DS-FOMO-BROWSER-T1): the browser fallback of the `fomo_theses` collector when Fomo API cannot read the theses.

Owner decision (AskUserQuestion, 2026-10-25 ~14:55 WIB), "API first, browser fallback (Recommended)": "Use the API; if it's
out of credits, rate-limited or returns a partial list, read fomo.family in the logged-in Camoufox profile instead. If that
profile is logged out, the scan prints the one login command for you."

When it reads (it reads <RUN>/fomo_theses.json, a first-wave file, so it is a follow-up lane):
- fomo_theses.json status ok: nothing to do; fomo_browser.json says not_needed and NO browser is launched.
- status needs_fallback (HTTP 402 credits_exhausted, a 429 after the retry rate_limited, available:false not_available,
  partial:true partial), or no fomo_theses.json at all (the API lane did not run): one read of the token page.
- status unavailable (no key, 401, a timeout, a renamed field) or an unreadable file: skipped, no browser (the owner's
  decision names out of credits, rate limited and partial).

The read: Camoufox, headless, a persistent context on the owner's logged-in profile (PROFILE_DIR), ONE page load of
https://fomo.family/tokens/solana/<MINT>: no click, no typing, no scrolling; nothing is posted, liked, followed or changed.
A hard 60 s wall-clock limit (HARD_LIMIT_S) counts from before the launch; every browser step gets only what is left of it,
and the browser is always closed, on errors too (the close comes after, about 1 s). Only two things of the page are read:
the page's own address (where the page went), and finished requests to the page's API host prod-api.fomo.family on two
paths only: the thesis feed (THESIS_PATH: {success, responseObject: {items, count, hasNextPage}}) and the signed-in user's
profile (USER_PATH: only whether it answered for a signed-in user; its body is never saved or printed). Never a cookie, a
header, a token, local storage or the page text: none of them is read, saved or printed.

The profile is never deleted, moved or edited by this script (the browser itself keeps its own files, as any visit does, and
Firefox creates its own .parentlock while it runs). The lock files (parent.lock, .parentlock, lock) are only tested, never
deleted (the older lp-research-companion scripts delete them; this one never does): a regular lock file is opened
read-only and given a non-blocking shared test lock that is released at once (it fails while another Firefox holds the
profile), a symlink lock names the process that holds it (checked without sending a signal). In use: not_read
(profile_in_use), no launch.

Logged out: login_needed, no thesis data, and the owner's login command (fomo_theses.LOGIN_COMMAND). Seen live on
2026-10-25: a logged-out session (a fresh one, and the owner's profile, whose session had expired) loads the token page,
never calls the app's API, and about 1 s later the app sends the browser to the landing page "/". So: the page went to the
landing page or a sign-in page, left fomo.family, or the profile request answered 401 or 403. A logged-in page stays on the
token page and calls USER_PATH and THESIS_PATH (the owner's saved logged-in captures of 2026-08/09).

Each thesis is saved in fomo_theses.json's per-thesis shape (id, handle, name, userId, equity, tradeUsd, isDev, likes,
replies, ts, text); the text goes through fomo_theses.clean_text (the same rules: links, invisible characters, verdict
words, 280 characters), handles and names through fomoapi.safe_label. Page fields (the saved captures): item id,
userHandle, displayName, userId, equity, authorTrade.usdValue (Fomo API's tradeUsd: 0 once the position is closed, on
both), isDev, numReplies, createdAt, tokenAddress, and comment.comment (the text), comment.numLikes, comment.tokenAddress;
responseObject.count is Fomo's own count. A thesis about another token is dropped and counted; a feed without a text field
is not_read (page_shape_changed), never "no theses".

Statuses: ok, login_needed, not_read (profile_in_use, page_shape_changed, no_thesis_data, browser_failed,
camoufox_missing, page_not_loaded, token_page_left), not_needed, skipped. Collector: fomo_browser.py <MINT> --out <RUN> writes
<RUN>/followup/fomo_browser.json and prints one line; exit 0 whenever the file was saved, exit 2 for a bad mint or --out.
--check-login: one headless load of a reference token page (CHECK_MINT) in the same profile, the same signals; prints only
"logged in" (exit 0), "logged out" (exit 2) or "profile in use" (exit 3), or "not read (<reason>)" (exit 1) when it cannot
tell; it writes nothing. PRESENTATION ONLY: fomo_theses.py --present prints the theses with the label "(read from the
logged-in fomo.family page; API not read: <reason>)"; never an engine input, never passed to assess, never counted toward
NO_ALARM; it never changes a FLAG, verdict or threshold. Needs camoufox 0.5.x (the holder-tools Python, as the Bubblemaps
map); Python >= 3.10.

--login [--start google|fomo] (DS-FOMO-LOGIN-T1; owner-run only, never part of a scan, never while a scan runs): the owner's
login window, and the command fomo_theses.LOGIN_COMMAND prints (owner decision, AskUserQuestion 2026-10-27 ~07:44 WIB: a
login mode in this file instead of the older script). The profile lock is tested first (profile_in_use, the same test as a
scan): while another browser or a running scan holds the profile it prints one line (LOGIN_IN_USE: close it and run this
again, or restart the computer if a crashed browser left it locked; it never suggests deleting a lock) and exits 3, opening
and deleting nothing. Else it makes the profile folder only when it is missing and opens ONE VISIBLE Camoufox window on the
profile with the older lp-research-companion login script's options and printed steps (persistent context, humanize,
WebRTC blocked; https://accounts.google.com/ by default, https://fomo.family/ with --start fomo), stays up until the last
window is closed and prints "Browser closed. Session stayed in the profile directory." (exit 0). The owner signs in; this
script never types or clicks, never reads a cookie, storage or the page, and never deletes, moves or edits a lock file (the
older script deletes them first; it is no longer suggested). Camoufox missing or a browser error: one fixed line, exit 1.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import json
import os
import re
import sys
import time
import urllib.parse
from pathlib import Path
from typing import Any, Callable

if str(Path(__file__).resolve().parent) not in sys.path:  # python3 -I leaves the script's folder off sys.path
    sys.path.insert(0, str(Path(__file__).resolve().parent))

import fomo_theses as ft  # noqa: E402  (the shared thesis cleaner, the per-thesis rules and the login command)
import fomoapi as fa  # noqa: E402  (inert labels, numbers, ISO times; no key is read here)

PAGE_HOST = "fomo.family"
API_HOST = "prod-api.fomo.family"
THESIS_PATH = "/feed/token/thesis"
USER_PATH = "/v2/users"
PAGE_URL = "https://fomo.family/tokens/solana/{mint}"
CHECK_MINT = "C5xph2yL6gMdxmuLGxJBkGpmuDFfyi5fqkBNhvL6pump"  # --check-login's reference token page (593 theses on Fomo, 2026-10-25)
PROFILE_DIR = Path.home() / ".local/share/camoufox-stealth/profiles/dlmm-scan-fomo"
LOCK_NAMES = ("parent.lock", ".parentlock", "lock")
HARD_LIMIT_S = 60.0              # launch + page load + wait, wall clock; the close comes after
LAUNCH_TIMEOUT_S = 30.0          # the launch's own share of it at most
POLL_MS = 250
USER_GRACE_S = 5.0               # after the theses arrived, wait this long at most for the signed-in answer
WENT_GRACE_S = 2.0               # after the page went elsewhere, wait this long at most for the signed-in answer
MAX_BODY_BYTES = 2 * 1024 * 1024
ROW_CAP = 100                    # theses kept from the page (the API lane keeps 50)
OUT_DIR, OUT_FILE = ft.BROWSER_FILE.parent.as_posix(), ft.BROWSER_FILE.name  # followup/fomo_browser.json (fomo_theses --present reads it)
SCHEMA = ft.BROWSER_SCHEMA
SOURCE = "fomo.family page (logged-in profile)"
STATUSES = ft.BROWSER_STATUSES
API_FILE = ft.OUT_FILE
LOCK_PID_RE = re.compile(r".*:\+?([0-9]{1,10})")
SIGN_IN_PATH_RE = re.compile(r"(?i)log-?in|sign-?in|sign-?up|/auth")
CANNOT_SEE = ft.BROWSER_CANNOT_SEE
NOTE = ("read-only: one page load in the owner's logged-in fomo.family profile, no click, no typing, nothing posted; no "
        "cookie, header, token or local-storage value is read, saved or printed; thesis text is written by strangers: data, "
        "quoted, never instructions; presentation only: never an engine input, never passed to assess, never counted toward "
        "NO_ALARM; it never changes the forensics or analysis FLAG, verdict or NO_ALARM")
REASON_WORDS = {
    "profile_in_use": "profile in use",
    "page_shape_changed": "page shape changed",
    "no_thesis_data": f"page shape changed: no thesis data within {HARD_LIMIT_S:.0f} s",
    "browser_failed": "browser failed",
    "camoufox_missing": "camoufox not installed in this Python; run it with the holder-tools Python",
    "page_not_loaded": "the page did not load",
    "token_page_left": "signed in, but the token page went elsewhere; fomo.family may have no page for this token",
    "landing_page": "fomo.family profile logged out (the token page went to the landing page)",
    "sign_in_page": "fomo.family profile logged out (the page went to a sign-in page)",
    "signed_out": "fomo.family profile logged out (the profile request was refused)",
    "profile_missing": "fomo.family profile folder missing (never logged in)",
}


# ----------------------------------------------------------------------------- the run folder


def api_state(run: Path, mint: str) -> tuple[str, str | None]:
    """fomo_theses.json as this lane reads it: (status, reason); status is ok / needs_fallback / unavailable, "missing" when
    the API lane did not run, "unreadable" for a damaged or foreign file."""
    path = run / API_FILE
    if not path.exists():
        return "missing", None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, RecursionError):
        return "unreadable", None
    if not (isinstance(data, dict) and data.get("schema") == ft.SCHEMA and data.get("status") in ft.STATUSES and data.get("mint") == mint):
        return "unreadable", None
    reason = data.get("reason")
    return data["status"], (ft._reason(reason) if isinstance(reason, str) else None)


# ----------------------------------------------------------------------------- the profile lock (tested, never touched)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)  # signal 0: an existence check, no signal is sent
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def profile_in_use(profile: Path) -> bool:
    """True while another browser holds the profile. A regular lock file is opened read-only and given a non-blocking shared
    test lock, released at once (Firefox holds a write lock on it while it runs); a symlink lock ("<ip>:<pid>") names the
    holding process. Nothing is written, moved or deleted."""
    for name in LOCK_NAMES:
        path = profile / name
        try:
            if path.is_symlink():
                match = LOCK_PID_RE.fullmatch(os.readlink(path))
                if match and _pid_alive(int(match.group(1))):
                    return True
                continue
            if not path.is_file():
                continue
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            continue
        try:
            try:
                fcntl.lockf(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except OSError as err:
                if err.errno in (errno.EACCES, errno.EAGAIN):
                    return True
                continue
            fcntl.lockf(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
    return False


# ----------------------------------------------------------------------------- the page's thesis feed (untrusted)


def _host_path(url: Any) -> tuple[str, str]:
    try:
        parsed = urllib.parse.urlsplit(str(url))
        return (parsed.hostname or "").lower(), parsed.path
    except ValueError:
        return "", ""


def where_page_went(url: Any, wanted_path: str) -> str | None:
    """Where the page is now, judged from its address only: None while it is still on the page asked for (or blank), else
    "other_host" (left fomo.family), "sign_in" (a sign-in path) or "landing" (fomo.family's landing page "/")."""
    if str(url) in ("", "about:blank"):
        return None
    host, path = _host_path(url)
    if host != PAGE_HOST and not host.endswith("." + PAGE_HOST):
        return "other_host"
    if SIGN_IN_PATH_RE.search(path):
        return "sign_in"
    if path in ("", "/") and wanted_path not in ("", "/"):
        return "landing"
    return None


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def parse_feed(payload: Any, mint: str, now_ts: float) -> dict[str, Any]:
    """One thesis-feed answer of the page: {success, message, responseObject: {items: [...], hasNextPage, count}, statusCode}.
    Returns {status: ok, total, has_next_page, rows, dropped, other_token} or {status: not_read, reason: page_shape_changed}
    (no item list, success not true, or rows of which none has a text field). A thesis about another token is dropped and
    counted, never shown as this token's."""
    body = _dict(payload)
    feed = _dict(body.get("responseObject"))
    items = feed.get("items")
    if body.get("success") is not True or not isinstance(items, list):
        return {"status": "not_read", "reason": "page_shape_changed"}
    if items and not any("comment" in _dict(_dict(i).get("comment")) for i in items):
        return {"status": "not_read", "reason": "page_shape_changed"}
    rows: list[dict[str, Any]] = []
    dropped = other = 0
    for item in items:
        if not isinstance(item, dict) or not isinstance(item.get("comment"), dict):
            dropped += 1
            continue
        comment = item["comment"]
        tokens = [v for v in (item.get("tokenAddress"), comment.get("tokenAddress")) if isinstance(v, str)]
        if any(t != mint for t in tokens):
            other += 1  # a thesis about another token: never shown as this token's
            continue
        text = ft.clean_text(comment.get("comment"))
        rows.append({
            "id": ft._id(item.get("id"), None), "handle": fa.safe_label(item.get("userHandle")), "name": fa.safe_label(item.get("displayName")),
            "userId": ft._id(item.get("userId"), None), "equity": ft._number(item.get("equity"), 0.0, 1e12),
            "tradeUsd": ft._number(_dict(item.get("authorTrade")).get("usdValue"), -1e12, 1e12),
            "isDev": item.get("isDev") if isinstance(item.get("isDev"), bool) else None, "likes": ft._count(comment.get("numLikes")),
            "replies": ft._count(item.get("numReplies")), "ts": ft._ts(item.get("createdAt"), now_ts), "text": text if isinstance(text, str) else None,
        })
    return {"status": "ok", "total": ft._count(feed.get("count")),
            "has_next_page": feed.get("hasNextPage") if isinstance(feed.get("hasNextPage"), bool) else None,
            "rows": rows, "dropped": dropped, "other_token": other}


# ----------------------------------------------------------------------------- the browser (one page load)


class Tap:
    """Listens to the page's finished requests and keeps only the two allowed kinds on the API host (nothing else of the
    page, never a header). Bodies are read later, in poll(), from finished requests only (no wait on a body)."""

    def __init__(self, mint: str | None, now: Callable[[], float]) -> None:
        self.mint, self.now = mint, now
        self._new: list[tuple[Any, str, float]] = []
        self.feeds: list[tuple[dict[str, Any], float]] = []   # parsed thesis feeds of this mint, with the capture time
        self.bad_feeds = 0                                     # thesis answers that did not parse (page shape changed)
        self.user: str | None = None                           # "signed_in" / "signed_out" / None (not answered)
        self.first_feed_at: float | None = None

    def finished(self, request: Any) -> None:
        try:
            host, path = _host_path(request.url)
        except Exception:  # noqa: BLE001 - a listener never raises into the browser
            return
        if host == API_HOST and path in (THESIS_PATH, USER_PATH):
            self._new.append((request, path, self.now()))

    def poll(self, clock: Callable[[], float]) -> None:
        while self._new:
            request, path, when = self._new.pop(0)
            try:
                response = request.response()
                status = response.status if response is not None else None
                body = response.body() if response is not None and status == 200 else b""
            except Exception:  # noqa: BLE001 - an unreadable answer counts as nothing
                continue
            if path == USER_PATH:
                self._user(status, body)
                continue
            if self.mint is None:
                continue
            if self.first_feed_at is None:
                self.first_feed_at = clock()
            parsed = parse_feed(fa._decode(body), self.mint, self.now()) if status == 200 and len(body) <= MAX_BODY_BYTES else None
            if parsed is None or parsed["status"] != "ok":
                self.bad_feeds += 1
            elif parsed["rows"] or not parsed["other_token"]:
                self.feeds.append((parsed, when))

    def _user(self, status: int | None, body: bytes) -> None:
        """Only whether the profile request answered for a signed-in user; the body is dropped right here."""
        if status in (401, 403):
            self.user = self.user or "signed_out"
            return
        if status != 200 or len(body) > MAX_BODY_BYTES:
            return
        data = _dict(fa._decode(body))
        if data.get("success") is True and isinstance(data.get("responseObject"), dict) and data["responseObject"].get("id"):
            self.user = "signed_in"


def camoufox_launcher(profile: Path, timeout_ms: float) -> Any:
    from camoufox.sync_api import Camoufox  # lazy: the tests and the not-needed path never import a browser
    return Camoufox(persistent_context=True, user_data_dir=str(profile), headless=True, humanize=True, block_webrtc=True, timeout=timeout_ms)


def read_page(mint: str, profile: Path, *, want_theses: bool, launcher: Callable[[Path, float], Any] | None = None,
              clock: Callable[[], float] = time.monotonic, now: Callable[[], float] = time.time) -> dict[str, Any]:
    """One load of the token page in the profile, read-only, within HARD_LIMIT_S from before the launch. It stops as soon as
    the page went to the landing or a sign-in page, or the profile request was refused; else, with want_theses, once this
    token's thesis feed arrived (and the signed-in answer, or USER_GRACE_S after the feed); without, once the signed-in answer
    came (--check-login). Never raises; the browser is closed by the launcher's context manager, on errors too."""
    start = clock()
    deadline = start + HARD_LIMIT_S
    wanted_path = _host_path(PAGE_URL.format(mint=mint))[1]
    tap = Tap(mint if want_theses else None, now)
    facts: dict[str, Any] = {"launched": False, "page_loads": 0, "went": None, "error": None, "timed_out": False, "tap": tap}
    went_at = [0.0]

    def left_ms() -> float:
        return max(1.0, (deadline - clock()) * 1000.0)

    def done() -> bool:
        if tap.user == "signed_out" or (facts["went"] and (tap.user is not None or clock() - went_at[0] >= WENT_GRACE_S)):
            return True
        if not want_theses:
            return tap.user == "signed_in"
        if tap.first_feed_at is not None:
            return tap.user == "signed_in" or clock() - tap.first_feed_at >= USER_GRACE_S
        return False

    try:
        with (launcher or camoufox_launcher)(profile, min(LAUNCH_TIMEOUT_S * 1000.0, left_ms())) as context:
            facts["launched"] = True
            pages = list(context.pages)
            page = pages[0] if pages else context.new_page()
            page.on("requestfinished", tap.finished)
            facts["page_loads"] = 1
            try:
                page.goto(PAGE_URL.format(mint=mint), wait_until="commit", timeout=left_ms())
            except Exception as err:  # noqa: BLE001 - a slow load still gets the rest of the time; a failed one ends here
                if "timeout" not in type(err).__name__.lower():
                    facts["error"] = "page_not_loaded"
            while facts["error"] is None:
                tap.poll(clock)
                if facts["went"] is None:
                    facts["went"] = where_page_went(page.url, wanted_path)
                    went_at[0] = clock()
                if done():
                    break
                if clock() >= deadline:
                    facts["timed_out"] = True
                    break
                page.wait_for_timeout(min(float(POLL_MS), left_ms()))
    except ModuleNotFoundError:
        facts["error"] = "camoufox_missing"
    except Exception:  # noqa: BLE001 - never a traceback (it could carry page details); a fixed code
        facts["error"] = facts["error"] or "browser_failed"
    facts["seconds"] = round(clock() - start, 1)
    return facts


def logged_out_reason(facts: dict[str, Any]) -> str | None:
    """The logged-out signal of one read, or None: the profile request was refused (401 / 403), or the page went to the
    landing page, a sign-in page or another site with no signed-in answer seen (signed in, a page that went elsewhere is
    not a logout: fomo.family may have no page for that token)."""
    went, user = facts["went"], facts["tap"].user
    if user == "signed_out":
        return "signed_out"
    if user == "signed_in":
        return None
    if went == "landing":
        return "landing_page"
    if went in ("sign_in", "other_host"):
        return "sign_in_page"
    return None


# ----------------------------------------------------------------------------- collect


def _base(mint: str, fetched_at: str, api: tuple[str, str | None]) -> dict[str, Any]:
    return {
        "schema": SCHEMA, "collector": "fomo_browser", "source": SOURCE, "mint": mint, "status": "not_read", "reason": None,
        "api_status": api[0], "api_reason": api[1], "fetched_at": fetched_at, "captured_at": None,
        "page": {"url": PAGE_URL.format(mint=mint), "browser_launched": False, "page_loads": 0, "clicks": 0, "typed": 0, "went": None,
                 "signed_in_answer": None, "hard_limit_s": HARD_LIMIT_S, "seconds": None},
        "rows_read": 0, "total_available": None, "has_next_page": None, "equity_reported": False,
        "rows_dropped": 0, "rows_dropped_key_echo": 0, "rows_other_token": 0, "rows_beyond_cap": 0, "theses": [],
        "untrusted_text": True, "presentation_only": True, "note": NOTE, "cannot_see": CANNOT_SEE,
    }


def _merge(feeds: list[tuple[dict[str, Any], float]]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Every thesis feed answer of this mint, merged in arrival order (a thesis seen twice kept once, by its id)."""
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    facts: dict[str, Any] = {"rows_read": 0, "dropped": 0, "other": 0, "total": None, "next": None, "at": None}
    for parsed, when in feeds:
        facts["rows_read"] += len(parsed["rows"]) + parsed["dropped"] + parsed["other_token"]
        facts["dropped"] += parsed["dropped"]
        facts["other"] += parsed["other_token"]
        facts["total"] = parsed["total"] if parsed["total"] is not None else facts["total"]
        facts["next"] = parsed["has_next_page"] if parsed["has_next_page"] is not None else facts["next"]
        facts["at"] = facts["at"] or when
        for row in parsed["rows"]:
            if row["id"] is not None and row["id"] in seen:
                continue
            if row["id"] is not None:
                seen.add(row["id"])
            rows.append(row)
    return rows, facts


def collect_fomo_browser(mint: str, run: Path, *, profile: Path | None = None, launcher: Callable[[Path, float], Any] | None = None,
                         clock: Callable[[], float] = time.monotonic, now: Callable[[], float] = time.time) -> dict[str, Any]:
    """The fomo_browser.json result. Launches the browser only when fomo_theses.json says needs_fallback or is missing."""
    profile = PROFILE_DIR if profile is None else profile
    api = api_state(run, mint)
    result = _base(mint, fa._iso(now()), api)
    if api[0] == "ok":
        result.update(status="not_needed", reason="api_ok")
        return result
    if api[0] in ("unavailable", "unreadable"):
        result.update(status="skipped", reason=f"api_{api[0]}")
        return result
    if not profile.is_dir():
        result.update(status="login_needed", reason="profile_missing")
        return result
    if profile_in_use(profile):
        result.update(status="not_read", reason="profile_in_use")
        return result
    facts = read_page(mint, profile, want_theses=True, launcher=launcher, clock=clock, now=now)
    tap: Tap = facts["tap"]
    result["page"].update(browser_launched=facts["launched"], page_loads=facts["page_loads"], went=facts["went"] or ("token_page" if facts["launched"] else None),
                          signed_in_answer={"signed_in": True, "signed_out": False}.get(tap.user), seconds=facts["seconds"])
    if facts["error"] == "browser_failed" and profile_in_use(profile):
        facts["error"] = "profile_in_use"  # another browser took the profile while this one started
    if facts["error"]:
        result.update(status="not_read", reason=facts["error"])
        return result
    logged_out = logged_out_reason(facts)
    if logged_out:
        result.update(status="login_needed", reason=logged_out)
        return result
    if not tap.feeds:
        reason = "page_shape_changed" if tap.bad_feeds else "token_page_left" if facts["went"] else "no_thesis_data"
        result.update(status="not_read", reason=reason)
        return result
    rows, merged = _merge(tap.feeds)
    kept = rows[:ROW_CAP]
    result.update(status="ok", reason=None, captured_at=fa._iso(merged["at"]), rows_read=merged["rows_read"], total_available=merged["total"],
                  has_next_page=merged["next"], equity_reported=any(r["equity"] not in (None, 0.0) for r in kept), rows_dropped=merged["dropped"],
                  rows_other_token=merged["other"], rows_beyond_cap=len(rows) - len(kept), theses=kept)
    return result


def status_line(result: dict[str, Any]) -> str:
    status, reason = result["status"], result.get("reason")
    if status == "ok":
        total = result.get("total_available")
        page = result["page"]
        return (f"ok ({ft._plural(len(result['theses']), 'thesis', 'theses')} read from the logged-in fomo.family page"
                + (f", Fomo counts {total}" if total is not None else "") + f"; {page['page_loads']} page load, {page['seconds']} s; no click, no typing)")
    if status == "login_needed":
        return f"login_needed ({REASON_WORDS.get(reason, 'fomo.family profile logged out')}; to log in once, run: {ft.LOGIN_COMMAND})"
    if status == "not_needed":
        return "not needed (Fomo API read ok; no browser launched)"
    if status == "skipped":
        return (f"skipped (fomo_theses.json {'unreadable' if reason == 'api_unreadable' else 'says unavailable'}: the fallback runs only for "
                "out of credits, rate limited, not available, partial or a missing file; no browser launched)")
    return f"not read ({REASON_WORDS.get(reason, reason or 'unknown')})"


def check_login(profile: Path | None = None, *, launcher: Callable[[Path, float], Any] | None = None,
                clock: Callable[[], float] = time.monotonic) -> tuple[str, int]:
    """One headless load of the reference token page in the profile: ("logged in", 0), ("logged out", 2),
    ("profile in use", 3) or ("not read (<reason>)", 1)."""
    profile = PROFILE_DIR if profile is None else profile
    if not profile.is_dir():
        return "logged out", 2
    if profile_in_use(profile):
        return "profile in use", 3
    facts = read_page(CHECK_MINT, profile, want_theses=False, launcher=launcher, clock=clock)
    if facts["error"] == "browser_failed" and profile_in_use(profile):
        return "profile in use", 3
    if facts["error"]:
        return f"not read ({REASON_WORDS.get(facts['error'], facts['error'])})", 1
    if logged_out_reason(facts):
        return "logged out", 2
    if facts["tap"].user == "signed_in":
        return "logged in", 0
    if facts["went"]:
        return "not read (the reference token page went elsewhere)", 1
    return f"not read (no sign-in answer within {HARD_LIMIT_S:.0f} s; the page may have changed)", 1


# ----------------------------------------------------------------------------- --login (owner-run only, never part of a scan)


LOGIN_URLS = {"google": "https://accounts.google.com/", "fomo": "https://fomo.family/"}  # --start google (default) or fomo
LOGIN_POLL_S = 1.0
LOGIN_IN_USE = ("the fomo.family profile is in use by another browser (or a running scan): close it and run this again (close every "
                "Camoufox/Firefox window, or wait for the scan to finish; if a crashed browser left it locked, restart the computer). "
                "Nothing was opened, deleted or changed.")
LOGIN_STEPS = ("1) Sign into Google in this window.", "2) After Google is in, go to https://fomo.family/ and Start trading.",
               "3) Close the browser when both sessions are saved.")
LOGIN_DONE = "Browser closed. Session stayed in the profile directory."
LOGIN_FAILED = "browser failed (no detail printed): close every Camoufox/Firefox window and run this again"


def login_launcher(profile: Path) -> Any:
    from camoufox.sync_api import Camoufox  # lazy, as camoufox_launcher; VISIBLE, the older login script's options
    return Camoufox(persistent_context=True, user_data_dir=str(profile), headless=False, humanize=True, block_webrtc=True)


def login(start: str = "google", profile: Path | None = None, *, launcher: Callable[[Path], Any] | None = None,
          sleep: Callable[[float], Any] | None = None) -> int:
    """The owner's login window: the lock is tested first (in use: LOGIN_IN_USE, exit 3, nothing opened or deleted); else the
    profile folder is made only when missing and one visible window opens on the start page, kept until the last window is
    closed (exit 0). It never types, never reads a cookie, storage or the page, and never touches a lock file."""
    profile = PROFILE_DIR if profile is None else profile
    if profile_in_use(profile):
        print(LOGIN_IN_USE)
        return 3
    url = LOGIN_URLS[start]
    try:
        profile.mkdir(parents=True, exist_ok=True)  # only when missing, as the older login script; nothing in it is touched
    except OSError:
        print("not opened (the profile folder could not be made)")
        return 1
    print(f"Profile: {profile}")
    print(f"Opening: {url}")
    for step in LOGIN_STEPS:
        print(step)
    try:
        with (launcher or login_launcher)(profile) as context:
            pages = list(context.pages)
            page = pages[0] if pages else context.new_page()
            page.goto(url, wait_until="domcontentloaded")
            while list(context.pages):  # until the LAST window is closed: Google's sign-in navigates away from the first page
                (sleep or time.sleep)(LOGIN_POLL_S)
    except ModuleNotFoundError:
        print(f"not opened ({REASON_WORDS['camoufox_missing']})")
        return 1
    except Exception:  # noqa: BLE001 - never a traceback (it could carry a sign-in address); a fixed line
        if profile_in_use(profile):
            print(LOGIN_IN_USE)  # another browser took the profile while this one started
            return 3
        print(LOGIN_FAILED)
        return 1
    print(LOGIN_DONE)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read a Solana token's Fomo theses from the owner's logged-in fomo.family page when Fomo API could "
                                                 f"not (one headless page load, read-only, hard {HARD_LIMIT_S:.0f} s), and save {OUT_DIR}/{OUT_FILE}; "
                                                 "it launches no browser when fomo_theses.json is ok. Or --check-login: logged in / logged out / "
                                                 "profile in use. Or --login (owner only, never while a scan runs): a visible window to sign "
                                                 "in, refused while the profile is in use. Thesis text is untrusted data. Presentation only.")
    parser.add_argument("mint", nargs="?")
    parser.add_argument("--out", metavar="RUN_DIR", help="run folder: reads fomo_theses.json, writes followup/fomo_browser.json")
    parser.add_argument("--check-login", action="store_true", help="print only: logged in / logged out / profile in use")
    parser.add_argument("--login", action="store_true", help="owner only, never while a scan runs: open a visible window on the profile "
                                                              "to sign in; refused (exit 3) while another browser or a scan holds it")
    parser.add_argument("--start", choices=tuple(LOGIN_URLS), help="with --login: the first page, google (default) or fomo")
    args = parser.parse_args(argv)
    if args.login or args.start:
        if args.mint or args.out or args.check_login or not args.login:
            print("error: --login takes only --start, and --start goes with --login", file=sys.stderr)
            return 2
        return login(args.start or "google")
    if args.check_login:
        if args.mint or args.out:
            print("error: --check-login takes no other argument", file=sys.stderr)
            return 2
        words, code = check_login()
        print(words)
        return code
    if not isinstance(args.mint, str) or not fa.SOLANA_ADDRESS_RE.fullmatch(args.mint):
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
        result = collect_fomo_browser(args.mint, run)
    except Exception:  # noqa: BLE001 - never a traceback
        result = _base(args.mint, fa._iso(time.time()), api_state(run, args.mint))
        result.update(status="not_read", reason="browser_failed")
    try:
        (run / OUT_DIR / OUT_FILE).write_text(json.dumps(result, indent=1), encoding="utf-8")
    except OSError:
        print("error: --out is not a writable folder", file=sys.stderr)
        return 2
    print(status_line(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
