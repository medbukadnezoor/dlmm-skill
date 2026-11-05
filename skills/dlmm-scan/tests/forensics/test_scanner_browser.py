"""DS-SCANNER-FREE-T1: the follow-up-wave collector `scanner_browser` (the Scanner token scan read from the owner's
logged-in scanner.net page when the free keyless endpoint could not read the token) and its --login and --present.
Offline: the browser is a fake (no Camoufox, no network: sockets blocked), a fake clock, temp profile folders. The page's
scan answer is the cached stream Scanner served on 2026-11-04 (fixtures/solscanner/mamesuke-scanner-net.json); a fresh scan
is the same stream without its cache_hit event. The logged-out page is replayed as seen live on 2026-11-04 (an empty
profile, and the owner's profile before the owner logged in): the scanner page loads, calls /contracts/<MINT>/detect and
other non-scan paths, never starts the token-scan request, and shows its Login button where the scan would be.

Covers the ticket's offline cases: a held lock (profile in use, lock files untouched), logged out (the Login button, a refused
scan request, the page leaving scanner.net; the exact login command), ok from the page's own network answer (cached: no scan
spent; fresh: 1 scan), the hard time limits (no scan started, a scan that never finishes), a changed page shape, never a
cookie / storage / header / script / click / typing call (a fake that records any), never a lock file deleted, --login
refused while in use, and the keyless file deciding whether a browser runs at all. The rendered page is read only for one
number (how many elements show exactly "Login"); the scan result itself is read from the page's network answer only (no
reader of the rendered result exists)."""

from __future__ import annotations

import ast
import contextlib
import copy
import datetime as dt
import io
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
import scanner_browser as sb  # noqa: E402
import solscanner_scan as ss  # noqa: E402
from test_fomo_browser import Clock, lock_held, lock_state, no_network  # noqa: E402
from test_scanner_keyless import MAMESUKE, Recorder, http_error, mamesuke_stream, not_cached_body  # noqa: E402
from test_solscanner_scan import block  # noqa: E402

NOW = dt.datetime(2026, 11, 4, 15, 30, tzinfo=dt.timezone.utc).timestamp()
SCAN_URL = f"https://api.scanner.net/contracts/{MAMESUKE}/scan/stream"
FAKE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.fAkEsIgNaTuReOnLyFoRtEsTs00"
FAKE_COOKIE = "privy-token=fake-cookie-value-7f3a9c2e1b"
FAKE_STORAGE = "privy:token-fake-local-storage-a1b2c3"
FAKES = (FAKE_JWT, FAKE_COOKIE, FAKE_STORAGE, "fake-cookie-value-7f3a9c2e1b", "owner@example.com")
FORBIDDEN = {"cookies", "add_cookies", "clear_cookies", "storage_state", "evaluate", "evaluate_handle", "inner_text", "inner_html", "text_content",
             "content", "click", "dblclick", "fill", "type", "press", "check", "tap", "keyboard", "mouse", "touchscreen", "set_input_files",
             "dispatch_event", "screenshot", "route", "set_extra_http_headers", "add_init_script", "expose_function", "all_headers", "headers",
             "header_value", "headers_array", "post_data", "locator", "query_selector", "query_selector_all", "frames", "main_frame"}
LOGIN_COMMAND = ("\"${HOLDER_PYTHON:-python3}\" -I "
                 "skills/dlmm-scan/scripts/scanner_browser.py --login")


FRESH = json.loads((Path(__file__).resolve().parent / "fixtures" / "solscanner" / "scanner-browser-fresh-stream.json").read_text(encoding="utf-8"))
FRESH_MINT = FRESH["mint"]
FRESH_NOW = dt.datetime(2026, 11, 4, 23, 53, 30, tzinfo=dt.timezone.utc).timestamp()


def live_fresh_stream(groups: list | None = None, events: list | None = None) -> bytes:
    """The page's real fresh-scan answer of 2026-11-05 (the fixture: every event in order, small fields), optionally with other
    groups in both the progress bundle_groups event and complete."""
    out = b""
    for name, payload in copy.deepcopy(events if events is not None else FRESH["events"]):
        if groups is not None and name == "bundle_groups":
            payload.update(count=len(groups), groups=groups)
        if groups is not None and name == "complete":
            payload["bundleGroups"] = groups
        out += block(name, payload)
    return out


def fresh_stream() -> bytes:
    """A fresh scan: the same stream without the cache_hit event (Scanner ran the scan for this request)."""
    data = json.loads((Path(__file__).resolve().parent / "fixtures" / "solscanner" / "mamesuke-scanner-net.json").read_text(encoding="utf-8"))
    complete = dict(data["complete"], scannedAt="2026-11-04T15:29:40.000Z", isStale=False)
    return block("progress", {"step": "holders"}) + block("complete", complete)


class FakeResponse:
    def __init__(self, status: int, body: bytes):
        self.status, self._body = status, body
        self.forbidden: list[str] = []

    def body(self) -> bytes:
        return self._body

    def __getattr__(self, name):
        self.__dict__.setdefault("forbidden", []).append(name)
        return lambda *a, **k: {"set-cookie": FAKE_COOKIE, "authorization": f"Bearer {FAKE_JWT}"}


class FakeRequest:
    def __init__(self, url: str, status: int = 200, body: bytes = b"", method: str = "GET"):
        self.url, self.method = url, method
        self._response = FakeResponse(status, body)
        self.forbidden: list[str] = []

    def response(self) -> FakeResponse:
        return self._response

    def __getattr__(self, name):
        self.__dict__.setdefault("forbidden", []).append(name)
        return lambda *a, **k: {"authorization": f"Bearer {FAKE_JWT}", "cookie": FAKE_COOKIE}


class Count:
    def __init__(self, page, n: int):
        self.page, self.n = page, n

    def count(self) -> int:
        self.page.login_counts += 1
        return self.n


class FakePage:
    """A page that never touches the network: goto commits the address; each wait advances the fake clock and fires the
    scripted events (seconds after goto): ("start", request) for a request the page starts, ("finish", request) when it
    finished; an optional move of the page's address; the Login button shown or not."""

    def __init__(self, clock: Clock, events=(), *, login_button: bool = False, move=None, goto_error: Exception | None = None,
                 wait_error_at: float | None = None):
        self.clock, self.events = clock, sorted(events, key=lambda e: e[0])
        self.login_button, self.move = login_button, move
        self.goto_error, self.wait_error_at = goto_error, wait_error_at
        self.url = "about:blank"
        self.handlers: dict = {}
        self.gotos: list = []
        self.waits = 0
        self.login_counts = 0
        self.text_asked: list = []
        self.forbidden: list[str] = []
        self.t0 = None

    def on(self, event, handler):
        assert event in ("request", "requestfinished"), event
        self.handlers[event] = handler

    def goto(self, url, wait_until=None, timeout=None):
        self.gotos.append((url, wait_until, timeout))
        if self.goto_error is not None:
            raise self.goto_error
        self.url, self.t0 = url, self.clock.t

    def wait_for_timeout(self, ms):
        self.waits += 1
        self.clock.t += ms / 1000.0
        if self.t0 is None:
            return
        if self.wait_error_at is not None and self.clock.t - self.t0 >= self.wait_error_at:
            raise RuntimeError("Target page, context or browser has been closed")
        while self.events and self.t0 + self.events[0][0] <= self.clock.t:
            _, kind, request = self.events.pop(0)
            self.handlers["request" if kind == "start" else "requestfinished"](request)
        if self.move and self.t0 + self.move[0] <= self.clock.t:
            self.url = self.move[1]

    def get_by_text(self, text, exact=False):
        self.text_asked.append((text, exact))
        return Count(self, 1 if self.login_button else 0)

    def __getattr__(self, name):
        self.__dict__.setdefault("forbidden", []).append(name)
        return lambda *a, **k: FAKE_STORAGE


class FakeContext:
    def __init__(self, page: FakePage):
        self._page = page
        self.forbidden: list[str] = []

    @property
    def pages(self):
        return [self._page]

    def __getattr__(self, name):
        self.__dict__.setdefault("forbidden", []).append(name)
        return lambda *a, **k: [{"name": "privy-token", "value": FAKE_JWT}]


class Launcher:
    def __init__(self, page: FakePage | None = None, enter_cost: float = 0.0, enter_error: Exception | None = None):
        self.page, self.enter_cost, self.enter_error = page, enter_cost, enter_error
        self.calls: list = []
        self.entered = self.closed = 0
        self.context = FakeContext(page) if page is not None else None

    def __call__(self, profile, timeout_ms):
        self.calls.append((Path(profile), timeout_ms))
        return self

    def __enter__(self):
        self.entered += 1
        if self.page is not None:
            self.page.clock.t += self.enter_cost
        if self.enter_error is not None:
            raise self.enter_error
        return self.context

    def __exit__(self, *exc):
        self.closed += 1
        return False


def refuse_launch(*_a, **_k):
    raise AssertionError("a browser was launched")


def scan_request(status: int = 200, body: bytes | None = None, host: str = "api.scanner.net") -> FakeRequest:
    return FakeRequest(f"https://{host}/contracts/{MAMESUKE}/scan/stream?mode=holders", status, mamesuke_stream() if body is None else body)


def other_requests() -> list:
    """The page's other calls, as seen live on 2026-11-04 (logged out): the token detection and the KOL widgets."""
    return [(1.0, "finish", FakeRequest(f"https://api.scanner.net/contracts/{MAMESUKE}/detect", 200, b'{"type":"token"}')),
            (1.5, "finish", FakeRequest("https://api.scanner.net/kol/wallets", 200, b"[]")),
            (2.0, "finish", FakeRequest("https://api.scanner.net/events", 204, b"", method="POST")),
            (2.1, "finish", FakeRequest("https://www.scanner.net/sol/scanner", 200, b"page"))]


def signed_in_page(clock: Clock, request: FakeRequest | None = None, start_at: float = 3.0, finish_at: float = 9.0, **kw) -> FakePage:
    request = request or scan_request()
    return FakePage(clock, other_requests() + [(start_at, "start", request), (finish_at, "finish", request)], **kw)


def logged_out_page(clock: Clock) -> FakePage:
    return FakePage(clock, other_requests(), login_button=True)


class TempRun(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.profile = self.tmp / "profile"
        self.profile.mkdir()
        self.run_dir = self.tmp / "run"
        self.run_dir.mkdir()
        self._net = no_network()
        self._net.__enter__()

    def tearDown(self):
        self._net.__exit__(None, None, None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def keyless_file(self, kind: str = "not_cached", mint: str = MAMESUKE) -> dict:
        """solscanner.json of the run, written by the real keyless collector with a fake opener (no network)."""
        from test_solscanner_scan import Response

        answer = {"not_cached": lambda: http_error(401, not_cached_body()), "ok": lambda: Response(mamesuke_stream()), "timeout": TimeoutError}[kind]()
        res = ss.collect_keyless(mint, opener=Recorder(answer), now=lambda: dt.datetime.fromtimestamp(NOW, dt.timezone.utc))
        (self.run_dir / sb.KEYLESS_FILE).write_text(json.dumps(res, indent=1))
        return res

    def collect(self, page: FakePage | None, clock: Clock | None = None, **kw) -> tuple[dict, Launcher]:
        launcher = Launcher(page, **kw)
        clock = clock or (page.clock if page is not None else Clock())
        res = sb.collect_scanner_browser(MAMESUKE, self.run_dir, profile=self.profile, launcher=launcher, clock=clock, now=lambda: NOW)
        return res, launcher

    def save(self, res: dict) -> Path:
        (self.run_dir / sb.OUT_DIR).mkdir(exist_ok=True)
        path = self.run_dir / sb.OUT_DIR / sb.OUT_FILE
        path.write_text(json.dumps(res, indent=1))
        return path

    def assert_clean_browser(self, launcher: Launcher):
        page = launcher.page
        self.assertEqual((page.forbidden, launcher.context.forbidden), ([], []), "no cookie, storage, header, script, click or typing call")
        self.assertTrue(set(page.handlers) <= {"request", "requestfinished"})
        self.assertTrue(all(t == (sb.LOGIN_TEXT, True) for t in page.text_asked), "the only page read: the exact Login text, counted")


# ----------------------------------------------------------------------------- when a browser runs at all


class WhenItRunsTests(TempRun):
    def test_a_keyless_read_launches_no_browser(self):
        self.keyless_file("ok")
        res = sb.collect_scanner_browser(MAMESUKE, self.run_dir, profile=self.profile, launcher=refuse_launch, clock=Clock(), now=lambda: NOW)
        self.assertEqual((res["browser_status"], res["browser_reason"], res["page"]["browser_launched"]), ("not_needed", "keyless_ok", False))
        self.assertEqual(sb.status_line(res), "not needed (the free keyless endpoint read the scan; no browser launched)")

    def test_an_unreadable_or_foreign_file_or_a_failure_a_browser_cannot_help_launches_nothing(self):
        for content, reason in (("{bad json", "keyless_unreadable"), (json.dumps({"mint": "x"}), "keyless_unreadable"),
                                (json.dumps({"mint": MAMESUKE, "source": None, "needs_browser": False, "reason": "invalid_mint"}), "keyless_no_browser")):
            with self.subTest(reason):
                (self.run_dir / sb.KEYLESS_FILE).write_text(content)
                res = sb.collect_scanner_browser(MAMESUKE, self.run_dir, profile=self.profile, launcher=refuse_launch, clock=Clock(), now=lambda: NOW)
                self.assertEqual((res["browser_status"], res["browser_reason"]), ("skipped", reason))

    def test_needs_browser_or_a_missing_file_make_exactly_one_page_load(self):
        for kind in ("not_cached", "timeout", None):
            with self.subTest(kind):
                (self.run_dir / sb.KEYLESS_FILE).unlink(missing_ok=True)
                if kind:
                    self.keyless_file(kind)
                page = signed_in_page(Clock())
                res, launcher = self.collect(page)
                self.assertEqual((res["browser_status"], len(launcher.calls), launcher.closed, len(page.gotos)), ("ok", 1, 1, 1))
                self.assertEqual(page.gotos[0][:2], (f"https://www.scanner.net/sol/scanner/{MAMESUKE}", "commit"))
                self.assertEqual((res["page"]["page_loads"], res["page"]["clicks"], res["page"]["typed"]), (1, 0, 0))
                self.assertEqual(res["keyless_reason"], {"not_cached": "not_cached_needs_login", "timeout": "timeout", None: "not_run"}[kind])
                self.assert_clean_browser(launcher)

    def test_a_missing_profile_folder_is_a_login_case_without_a_launch(self):
        self.keyless_file()
        shutil.rmtree(self.profile)
        res = sb.collect_scanner_browser(MAMESUKE, self.run_dir, profile=self.profile, launcher=refuse_launch, clock=Clock(), now=lambda: NOW)
        self.assertEqual((res["browser_status"], res["browser_reason"]), ("login_needed", "profile_missing"))
        self.assertFalse(self.profile.exists(), "a scan never makes the profile folder")
        self.assertIn(LOGIN_COMMAND, sb.status_line(res))


# ----------------------------------------------------------------------------- ok from the page's own network answer


class LiveFreshStreamTests(TempRun):
    """The page's own answer for a token Scanner had not cached (live 2026-11-05): 349 events, the groups sent twice (a progress
    bundle_groups event and complete), then a cache_hit marking the new scan saved. The first version read it as a broken
    stream and called the trailing cache_hit a cached result; both are fixed."""

    def collect_fresh(self, body: bytes) -> dict:
        (self.run_dir / sb.KEYLESS_FILE).unlink(missing_ok=True)
        request = FakeRequest(f"https://api.scanner.net/contracts/{FRESH_MINT}/scan/stream", 200, body)
        page = FakePage(Clock(), [(3.0, "start", request), (21.0, "finish", request)])
        return sb.collect_scanner_browser(FRESH_MINT, self.run_dir, profile=self.profile, launcher=Launcher(page), clock=page.clock, now=lambda: FRESH_NOW)

    def test_the_live_fresh_stream_with_bundle_groups_is_read_and_counts_one_scan(self):
        res = self.collect_fresh(live_fresh_stream())
        self.assertEqual((res["browser_status"], res["source"], res["cache_hit"], res["scans_spent"]), ("ok", "scanner_browser", False, 1))
        self.assertEqual((len(res["groups"]), res["reason"], res["scanned_at"], res["is_stale"], res["scan_complete"]), (20, None, "2026-11-04T23:53:29Z", False, True))
        self.assertEqual((res["page"]["scan_answer_events"], res["page"]["scan_answer_complete_events"], res["page"]["scan_answer_progress_group_events"]), (349, 1, 1))
        biggest = max(res["groups"], key=lambda g: sum(w["share_pct"] for w in g["wallets"]))
        self.assertEqual((len(biggest["wallets"]), round(sum(w["share_pct"] for w in biggest["wallets"]), 1), biggest["risk_score"], biggest["confidence"]), (6, 77.7, 38, "low"))
        self.assertIn("spent 1 of the account's scans", sb.status_line(res))
        hf.validate_solscanner_result(json.loads(json.dumps(res)))
        note = ss.solscanner_finding(res, dt.datetime.fromtimestamp(FRESH_NOW, dt.timezone.utc))["note"]
        self.assertEqual(note, "20 bundle groups, largest 77.7% (risk 38); scan 0m old; not an all-clear")

    def test_a_live_fresh_stream_with_no_bundle_group_is_an_honest_zero_not_a_changed_page(self):
        res = self.collect_fresh(live_fresh_stream(groups=[]))
        self.assertEqual((res["browser_status"], res["groups"], res["scans_spent"], res["reason"]), ("ok", [], 1, None))
        self.assertTrue(sb.status_line(res).startswith("ok (0 bundle groups read from the logged-in scanner.net page"))
        self.save(res)
        with mock.patch.object(ss, "utc_now", return_value=dt.datetime.fromtimestamp(FRESH_NOW, dt.timezone.utc)):
            self.assertIn("no bundle groups listed, scan 0m old; not an all-clear", sb.present(self.run_dir)[0])

    def test_groups_sent_twice_or_two_complete_events_read_the_last_complete(self):
        events = copy.deepcopy(FRESH["events"])
        last = max(i for i, (n, _) in enumerate(events) if n == "complete")
        first_complete = ["complete", dict(events[last][1], bundleGroups=events[last][1]["bundleGroups"][:3])]
        events.insert(last, first_complete)  # an earlier complete with 3 groups, then the final one with 20
        res = self.collect_fresh(live_fresh_stream(events=events))
        self.assertEqual((res["browser_status"], len(res["groups"]), res["page"]["scan_answer_complete_events"]), ("ok", 20, 2))

    def test_a_fresh_stream_cut_off_before_complete_is_not_read_but_still_counts_the_scan(self):
        events = [e for e in FRESH["events"] if e[0] not in ("complete", "cache_hit")]
        res = self.collect_fresh(live_fresh_stream(events=events))
        self.assertEqual((res["browser_status"], res["browser_reason"], res["scans_spent"], res["groups"]), ("not_read", "answer_without_complete", 1, []))
        self.assertEqual(sb.status_line(res), "not read (the page's scan answer ended before its complete event (the scan did not finish); "
                                              "the page's scan spent 1 of the account's scans)")
        self.assertEqual([r["event"] for r in res["page"]["scan_answer_shape"]][:3], ["token_metadata", "holders", "status"])

    def test_the_older_shape_with_the_groups_only_in_bundle_groups_is_still_read(self):
        events = copy.deepcopy(FRESH["events"])
        for name, payload in events:
            if name == "complete":
                payload.pop("bundleGroups")
        res = self.collect_fresh(live_fresh_stream(events=events))
        self.assertEqual((res["browser_status"], len(res["groups"])), ("ok", 20))

    def test_the_cost_rule(self):
        cached_first = block("cache_hit", {"scannedAt": "2026-11-04T23:53:29Z", "isStale": False, "history": []})
        complete = [e for e in FRESH["events"] if e[0] == "complete"][0]
        saved = block("cache_hit", {"scannedAt": "2026-11-04T23:53:29Z", "isStale": False, "refreshed": True, "updatedExisting": True})
        for name, body, cached in (("cached: cache_hit first", cached_first + block(*complete), True),
                                   ("fresh: the save marker after complete", live_fresh_stream(), False),
                                   ("a cached answer then a refresh", cached_first + block(*complete) + saved, False),
                                   ("no cache_hit at all", block(*complete), False)):
            with self.subTest(name):
                _, facts = sb.normalize_answer(body)
                self.assertEqual(facts["cached"], cached)

    def test_the_answer_cap_is_8_mib_and_the_reduced_stream_still_fits_the_parser(self):
        self.assertEqual(sb.MAX_ANSWER_BYTES, 8 * 1024 * 1024)
        padding = b"".join(block("entry_analysis", {"analyzed": i, "total": 100, "pad": "x" * 2000}) for i in range(700))  # about 1.4 MiB of steps
        self.assertGreater(len(padding), ss.MAX_BYTES)
        res = self.collect_fresh(padding + live_fresh_stream())
        self.assertEqual((res["browser_status"], len(res["groups"])), ("ok", 20))
        res = self.collect_fresh(b"x" * (sb.MAX_ANSWER_BYTES + 1))
        self.assertEqual((res["browser_status"], res["browser_reason"]), ("not_read", "response_too_large"))
        self.assertEqual(sb.status_line(res), "not read (the scan answer was larger than 8 MiB)", "R1: the words name the cap the check uses")


class NetworkAnswerTests(TempRun):
    def test_a_cached_answer_is_read_and_spends_no_scan(self):
        self.keyless_file()
        page = signed_in_page(Clock())
        res, launcher = self.collect(page)
        self.assertEqual((res["browser_status"], res["source"], res["cache_hit"], res["scans_spent"], len(res["groups"])), ("ok", "scanner_browser", True, 0, 11))
        self.assertEqual((res["reason"], res["is_stale"], res["needs_browser"], res["keyless_status"]), ("provider_stale", True, False, "failed"))
        self.assertEqual((res["page"]["scan_requests_started"], res["page"]["scan_answer_status"], res["page"]["login_button_seen"]), (1, 200, None))
        self.assertEqual(res["page"]["scanner_requests"], [{"method": "GET", "host": "api.scanner.net", "path": "/contracts/<MINT>/detect", "status": 200},
                                                           {"method": "GET", "host": "api.scanner.net", "path": "other", "status": 200},
                                                           {"method": "POST", "host": "api.scanner.net", "path": "other", "status": 204}])
        self.assertLess(res["page"]["seconds"], 10.0, "it stops once the page's scan answer finished")
        self.assertEqual(sb.status_line(res), "ok (11 bundle groups read from the logged-in scanner.net page; free endpoint not read: not_cached_needs_login; "
                                              f"cached, no scan spent; 1 page load, {res['page']['seconds']} s; no click, no typing)")
        self.assertEqual(page.login_counts, 0, "with a scan request started, the page is not read at all")
        self.assert_clean_browser(launcher)

    def test_a_fresh_answer_spends_one_scan_and_the_legacy_host_is_read_too(self):
        self.keyless_file()
        res, _ = self.collect(signed_in_page(Clock(), scan_request(body=fresh_stream(), host="api.solscanner.app")))
        self.assertEqual((res["browser_status"], res["cache_hit"], res["scans_spent"], res["reason"], res["is_stale"]), ("ok", False, 1, None, False))
        self.assertIn("spent 1 of the account's scans", sb.status_line(res))

    def test_the_saved_file_would_validate_as_an_assess_input_and_its_source_line_is_display_only(self):
        """The lane is presentation only (the synthesis never passes it to assess: no follow-up file is an assess input), but its
        file keeps the keyless file's shape, so it validates the same way and its source line changes no verdict."""
        from test_verdict_gating import holders_dict

        self.keyless_file()
        res, _ = self.collect(signed_in_page(Clock()))
        path = self.save(res)
        saved = json.loads(path.read_text())
        hf.validate_solscanner_result(saved)
        args = types.SimpleNamespace(solscanner_json=str(path), solscanner=False)
        self.assertEqual(hf.load_solscanner(args, MAMESUKE), saved)
        line = "source: read from the logged-in scanner.net page; free endpoint not read: not_cached_needs_login; cached, no scan spent"
        self.assertEqual(ss.source_text(saved), line)
        bare = {k: saved[k] for k in ss._empty(MAMESUKE, "x", "x")}
        now = dt.datetime.fromtimestamp(NOW, dt.timezone.utc)
        a = hf.assess(holders_dict(), None, [hf.solscanner_finding_for(saved, now)], solscanner=saved)
        b = hf.assess(holders_dict(), None, [hf.solscanner_finding_for(bare, now)], solscanner=bare)
        self.assertEqual((a["verdict"], a["flag"], a["findings"]), (b["verdict"], b["flag"], b["findings"]))
        self.assertEqual(next(s for s in a["sources"] if s["key"] == "solscanner")["lines"][-1], line)

    def test_a_changed_page_shape_or_a_failed_scan_is_not_read(self):
        cases = (("no bundle groups", scan_request(body=block("complete", {"mint": MAMESUKE, "bundleGroupsV2": []})), "page_shape_changed"),
                 ("another token", scan_request(body=block("complete", {"mint": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", "bundleGroups": []})), "page_shape_changed"),
                 ("server error", scan_request(status=500, body=b""), "scan_failed"),
                 ("a complete event too large for the parser", scan_request(body=block("complete", {"mint": MAMESUKE, "bundleGroups": [], "pad": "x" * ss.MAX_BYTES})),
                  "page_shape_changed"),
                 ("no event at all", scan_request(body=b"x" * 1000), "answer_without_complete"))
        for name, request, reason in cases:
            with self.subTest(name):
                self.keyless_file()
                res, launcher = self.collect(signed_in_page(Clock(), request))
                answered = request.response().status == 200
                self.assertEqual((res["browser_status"], res["browser_reason"], res["source"], res["groups"]), ("not_read", reason, None, []))
                # live 2026-11-05: the page's fresh scan ran and could not be read; what it cost is still recorded
                self.assertEqual((res["cache_hit"], res["scans_spent"]), (False, 1) if answered else (None, None))
                self.assertEqual(launcher.closed, 1)
                line = sb.status_line(res)
                self.assertTrue(line.startswith("not read ("))
                self.assertEqual(line.endswith("; the page's scan spent 1 of the account's scans)"), answered)

    def test_an_unreadable_answer_records_its_shape_names_only_never_a_value(self):
        self.keyless_file()
        body = (block("progress", {"step": "holders", "secretValue": "VALUE-NEVER-KEPT-123", "wallets": ["W1", "W2"]})
                + block("bundle_groups", {"groups": [{"wallets": []}], "note": "VALUE-NEVER-KEPT-456"})
                + block("complete", {"mint": MAMESUKE, "scanComplete": True, "bundleGroups": [{"wallets": "VALUE-NEVER-KEPT-789"}]})
                + b"event: Weird Name!\ndata: not json VALUE-NEVER-KEPT-000\n\n")
        res, _ = self.collect(signed_in_page(Clock(), scan_request(body=body)))
        self.assertEqual((res["browser_status"], res["browser_reason"], res["page"]["scan_answer_reason"]), ("not_read", "page_shape_changed", "malformed_sse"))
        self.assertEqual(res["page"]["scan_answer_shape"], [
            {"event": "progress", "data": "dict", "keys": ["secretValue", "step", "wallets"], "list_lengths": {"wallets": 2}},
            {"event": "bundle_groups", "data": "dict", "keys": ["groups", "note"], "list_lengths": {"groups": 1}},
            {"event": "complete", "data": "dict", "keys": ["bundleGroups", "mint", "scanComplete"], "list_lengths": {"bundleGroups": 1}},
            {"event": "other", "data": "not_json"}])
        self.assertEqual((res["page"]["scan_answer_bytes"], res["scans_spent"]), (len(body), 1))
        self.assertNotIn("VALUE-NEVER-KEPT", json.dumps(res))

    def test_no_cookie_header_token_or_storage_value_is_saved_or_printed(self):
        self.keyless_file()
        page = signed_in_page(Clock())
        res, launcher = self.collect(page)
        out = io.StringIO()
        path = self.save(res)
        with contextlib.redirect_stdout(out):
            sb.main(["--present", str(self.run_dir)])
        text = path.read_text() + out.getvalue() + sb.status_line(res)
        for fake in FAKES:
            self.assertNotIn(fake, text)
        self.assert_clean_browser(launcher)

    def test_the_code_reads_no_cookie_storage_header_or_script_and_never_clicks_or_types(self):
        tree = ast.parse((SCRIPTS / "scanner_browser.py").read_text(encoding="utf-8"))
        stand_in = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "_Body")  # hands the captured body to the parser
        inside = {id(n) for n in ast.walk(stand_in)}
        used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute) and id(n) not in inside}
        self.assertEqual(sorted(used & FORBIDDEN), [])
        self.assertEqual({n.attr for n in ast.walk(stand_in) if isinstance(n, ast.Attribute)} & FORBIDDEN, {"headers"}, "only its own Content-Type")
        self.assertTrue({"response", "body", "status", "goto", "wait_for_timeout", "on", "url", "get_by_text", "count"} <= used)
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "get_by_text"]
        self.assertEqual([ast.unparse(c) for c in calls], ["page.get_by_text(LOGIN_TEXT, exact=True)"], "the one page read")
        text = (SCRIPTS / "scanner_browser.py").read_text(encoding="utf-8")
        for word in ("localStorage", "sessionStorage", "indexedDB", "document.cookie", "privy:token", "Authorization", "Bearer "):
            self.assertNotIn(word, text.replace("never reads a cookie, storage or the page", ""), word)


# ----------------------------------------------------------------------------- logged out


class LoggedOutTests(TempRun):
    def test_the_login_button_seen_live_reads_login_needed_with_the_command(self):
        self.keyless_file()
        page = logged_out_page(Clock())
        res, launcher = self.collect(page)
        self.assertEqual((res["browser_status"], res["browser_reason"], res["source"], res["scans_spent"]), ("login_needed", "login_button", None, None))
        self.assertEqual((res["page"]["login_button_seen"], res["page"]["scan_requests_started"]), (True, 0))
        self.assertGreaterEqual(res["page"]["seconds"], sb.LOGGED_OUT_AFTER_S)
        self.assertLess(res["page"]["seconds"], sb.LOGGED_OUT_AFTER_S + 1.0, "it stops as soon as the Login button is seen after the wait")
        self.assertEqual(sb.status_line(res), f"login_needed (scanner.net profile logged out (the page shows its Login button); to log in once, run: {LOGIN_COMMAND})")
        self.assertEqual(sb.LOGIN_COMMAND, LOGIN_COMMAND)
        self.assert_clean_browser(launcher)

    def test_other_logged_out_signs(self):
        for name, page_kw, reason in (("refused scan request", dict(request=scan_request(status=401, body=b"")), "signed_out"),
                                      ("403 while the page shows its Login button", dict(request=scan_request(status=403, body=b""), login_button=True), "login_button"),
                                      ("left the site", dict(move=(2.5, "https://auth.privy.io/login")), "page_left")):
            with self.subTest(name):
                self.keyless_file()
                res, _ = self.collect(signed_in_page(Clock(), **page_kw))
                self.assertEqual((res["browser_status"], res["browser_reason"]), ("login_needed", reason))
                self.assertIn(LOGIN_COMMAND, sb.status_line(res))

    def test_a_403_without_the_login_button_is_access_refused_never_a_login_prompt(self):
        """R1: a 403 alone does not prove a logout; the login command is printed only when the page also shows its Login button."""
        self.keyless_file()
        page = signed_in_page(Clock(), scan_request(status=403, body=b""))
        res, launcher = self.collect(page)
        self.assertEqual((res["browser_status"], res["browser_reason"], res["page"]["login_button_seen"], res["scans_spent"]), ("not_read", "access_refused", False, None))
        self.assertEqual(page.login_counts, 1, "the Login button is looked at once, after the 403")
        line = sb.status_line(res)
        self.assertEqual(line, "not read (the page's scan request was refused (HTTP 403) and the page shows no Login button)")
        self.save(res)
        printed = "\n".join(sb.present(self.run_dir))
        for text in (line, printed):
            self.assertNotIn("--login", text)
            self.assertNotIn("logged out", text)
        self.assert_clean_browser(launcher)

    def test_out_of_scans_is_its_own_reason_with_no_scan_spent(self):
        """R1: the page's scan request answering 402 (Scanner's INSUFFICIENT_CREDITS: the account's monthly scans are used up) is
        neither a logout nor a generic failure, and nothing was charged."""
        self.keyless_file()
        res, launcher = self.collect(signed_in_page(Clock(), scan_request(status=402, body=b'{"error":"x","code":"INSUFFICIENT_CREDITS"}')))
        self.assertEqual((res["browser_status"], res["browser_reason"], res["scans_spent"], res["cache_hit"], res["source"], res["groups"]),
                         ("not_read", "out_of_scans", 0, None, None, []))
        self.assertEqual(res["page"]["scan_answer_status"], 402)
        self.assertEqual(sb.status_line(res), "not read (the scanner.net account has no scans left this month; free endpoint not read: not_cached_needs_login; no scan spent)")
        self.save(res)
        self.assertEqual(sb.present(self.run_dir), ["Scanner (formerly SolScanner): not read (the scanner.net account has no scans left this month; "
                                                    "free endpoint not read: not_cached_needs_login; no scan spent)"])
        self.assertNotIn("--login", sb.status_line(res))
        self.assertNotIn("INSUFFICIENT_CREDITS", json.dumps(res), "the answer body is never kept")
        self.assert_clean_browser(launcher)

    def test_present_prints_the_exact_login_command(self):
        self.keyless_file()
        res, _ = self.collect(logged_out_page(Clock()))
        self.save(res)
        self.assertEqual(sb.present(self.run_dir), [
            f"Scanner (formerly SolScanner): not read (free endpoint not read: not_cached_needs_login; scanner.net profile logged out — to log in once, run: {LOGIN_COMMAND})",
            f"  {LOGIN_COMMAND}"])


# ----------------------------------------------------------------------------- the profile lock (tested, never touched)


class ProfileLockTests(TempRun):
    def test_a_held_lock_reads_profile_in_use_and_no_lock_file_is_touched(self):
        self.keyless_file()
        lock = self.profile / ".parentlock"
        lock.write_bytes(b"")
        (self.profile / "parent.lock").write_bytes(b"older-lock-content")
        before = lock_state(self.profile)
        with lock_held(lock):
            res, launcher = self.collect(None)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                code = sb.login(self.profile, launcher=refuse_launch)
        self.assertEqual((res["browser_status"], res["browser_reason"], launcher.calls, res["page"]["browser_launched"]), ("not_read", "profile_in_use", [], False))
        self.assertEqual(sb.status_line(res), "not read (profile in use)")
        self.assertEqual((code, out.getvalue()), (3, sb.LOGIN_IN_USE + "\n"))
        self.assertNotIn("delete", sb.LOGIN_IN_USE.replace("Nothing was opened, deleted or changed", ""))
        self.assertEqual(lock_state(self.profile), before, "the lock files keep their content, inode and time")
        self.assertEqual(sorted(p.name for p in self.profile.iterdir()), [".parentlock", "parent.lock"])

    def test_a_stale_unheld_lock_is_not_in_use_and_stays_untouched(self):
        self.keyless_file()
        (self.profile / ".parentlock").write_bytes(b"")
        before = lock_state(self.profile)
        res, launcher = self.collect(signed_in_page(Clock()))
        self.assertEqual((res["browser_status"], len(launcher.calls)), ("ok", 1))
        self.assertEqual(lock_state(self.profile), before)

    def test_a_launch_that_fails_while_another_browser_took_the_profile_reads_in_use(self):
        self.keyless_file()
        lock = self.profile / ".parentlock"
        lock.write_bytes(b"")
        state = {"held": None}

        class Racing(Launcher):
            def __enter__(inner):
                state["held"] = lock_held(lock)
                state["held"].__enter__()
                raise RuntimeError("browser exited: profile already in use")

        try:
            res = sb.collect_scanner_browser(MAMESUKE, self.run_dir, profile=self.profile, launcher=Racing(), clock=Clock(), now=lambda: NOW)
        finally:
            state["held"].__exit__(None, None, None)
        self.assertEqual((res["browser_status"], res["browser_reason"]), ("not_read", "profile_in_use"))

    def test_the_code_never_deletes_moves_or_writes_in_the_profile(self):
        code = (SCRIPTS / "scanner_browser.py").read_text(encoding="utf-8")
        tree = ast.parse(code)
        names = {n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "") for n in ast.walk(tree) if isinstance(n, ast.Call)}
        for never in ("unlink", "remove", "rmdir", "rmtree", "rename", "move", "copy", "copyfile", "copytree", "symlink", "link", "chmod",
                      "truncate", "write_bytes", "touch", "open", "system", "popen", "kill"):
            self.assertNotIn(never, names, never)
        replaces = [n for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "replace"]
        self.assertTrue(all(len(c.args) == 2 and all(isinstance(a, ast.Constant) and isinstance(a.value, str) for a in c.args) for c in replaces),
                        "only str.replace of written-out text, never Path.replace")
        self.assertNotIn("shutil", code)
        self.assertNotIn("os.", code)
        makers = {f.name: ast.unparse(n.func.value) for f in ast.walk(tree) if isinstance(f, ast.FunctionDef) for n in ast.walk(f)
                  if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "mkdir"}
        self.assertEqual(makers, {"main": "run / OUT_DIR", "login": "profile"}, "the only folders made: <RUN>/followup, and the missing profile by --login")
        self.assertEqual(code.count(".write_text("), 1, "the only file written is <RUN>/followup/scanner_browser.json")
        self.assertIn("fb.profile_in_use(", code, "the lock test is fomo_browser's (opened read-only, never deleted), by import")


# ----------------------------------------------------------------------------- the time limits, always closed


class LimitTests(TempRun):
    def test_signed_in_but_no_scan_started_stops_at_the_start_grace(self):
        self.keyless_file()
        page = FakePage(Clock(), other_requests(), login_button=False)
        res, launcher = self.collect(page)
        self.assertEqual((res["browser_status"], res["browser_reason"], res["page"]["login_button_seen"]), ("not_read", "scan_not_started", False))
        self.assertGreaterEqual(res["page"]["seconds"], sb.START_GRACE_S)
        self.assertLess(res["page"]["seconds"], sb.START_GRACE_S + 1.0)
        self.assertIn("this lane never clicks", sb.status_line(res))
        self.assertEqual(launcher.closed, 1)

    def test_a_scan_that_never_finishes_stops_at_the_hard_limit_counted_from_before_the_launch(self):
        self.keyless_file()
        request = scan_request()
        page = FakePage(Clock(), other_requests() + [(3.0, "start", request)])
        res, launcher = self.collect(page, enter_cost=9.0)
        self.assertEqual((res["browser_status"], res["browser_reason"], res["page"]["scan_requests_started"]), ("not_read", "scan_not_finished", 1))
        self.assertLessEqual(res["page"]["seconds"], sb.HARD_LIMIT_S + sb.POLL_MS / 1000.0)
        self.assertGreaterEqual(res["page"]["seconds"], sb.HARD_LIMIT_S)
        self.assertLessEqual(launcher.calls[0][1], sb.LAUNCH_TIMEOUT_S * 1000.0)
        self.assertLessEqual(page.gotos[0][2], (sb.HARD_LIMIT_S - 9.0) * 1000.0 + 1, "the page load gets only what the launch left")
        self.assertEqual(launcher.closed, 1)

    def test_errors_still_close_the_browser(self):
        cases = (("page load failed", dict(goto_error=RuntimeError("NS_ERROR_UNKNOWN_HOST")), "page_not_loaded"),
                 ("browser died", dict(wait_error_at=2.0), "browser_failed"))
        for name, kw, reason in cases:
            with self.subTest(name):
                self.keyless_file()
                res, launcher = self.collect(FakePage(Clock(), [], **kw))
                self.assertEqual((res["browser_status"], res["browser_reason"], launcher.closed), ("not_read", reason, 1))
        self.keyless_file()
        res, _ = self.collect(FakePage(Clock(), []), enter_error=RuntimeError("launch failed"))
        self.assertEqual((res["browser_status"], res["browser_reason"]), ("not_read", "browser_failed"))
        res, _ = self.collect(FakePage(Clock(), []), enter_error=ModuleNotFoundError("No module named 'camoufox'"))
        self.assertEqual((res["browser_status"], res["browser_reason"]), ("not_read", "camoufox_missing"))
        self.assertIn("holder-tools", sb.status_line(res))

    def test_main_never_prints_a_traceback_and_bad_arguments_exit_2_without_a_browser(self):
        self.keyless_file()

        def explode(*_a, **_k):
            raise ValueError(f"secret detail {FAKE_JWT}")

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sb, "collect_scanner_browser", explode), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sb.main([MAMESUKE, "--out", str(self.run_dir)])
        self.assertEqual((code, out.getvalue(), err.getvalue()), (0, "not read (browser failed)\n", ""))
        self.assertNotIn(FAKE_JWT, (self.run_dir / "followup" / "scanner_browser.json").read_text())
        for argv in (["not-a-mint", "--out", str(self.run_dir)], [MAMESUKE], ["--login", MAMESUKE], ["--present", str(self.run_dir), MAMESUKE]):
            with self.subTest(argv):
                with mock.patch.object(sb, "camoufox_launcher", refuse_launch), mock.patch.object(sb, "login_launcher", refuse_launch), \
                     contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(sb.main(argv), 2)


# ----------------------------------------------------------------------------- --login (owner-run only)


class LoginPage:
    """A visible login page: each wait advances the fake clock and runs the scripted action at that wait (the owner closing
    the window, the browser quitting, an event); anything else it is asked for is recorded as forbidden."""

    def __init__(self, ctx: "LoginContext", actions: dict | None = None):
        self.ctx, self.actions = ctx, dict(actions or {})
        self.closed = False
        self.gone = False  # the browser process is gone, but no event told the script (is_closed() stays False)
        self.waits = 0
        self.gotos: list = []
        self.forbidden: list[str] = []

    def goto(self, url, wait_until=None, timeout=None):
        self.gotos.append((url, wait_until))

    def is_closed(self) -> bool:
        return self.closed

    def wait_for_timeout(self, ms):
        if self.closed or self.gone:
            raise RuntimeError("Target page, context or browser has been closed")
        self.waits += 1
        self.ctx.clock.t += ms / 1000.0
        action = self.actions.pop(self.waits, None)
        if action:
            action(self)

    def __getattr__(self, name):
        self.__dict__.setdefault("forbidden", []).append(name)
        return lambda *a, **k: FAKE_STORAGE


class LoginBrowser:
    def __init__(self):
        self.handlers: dict = {}

    def on(self, event, handler):
        self.handlers[event] = handler


class LoginContext:
    def __init__(self, clock: Clock, n_pages: int = 1, actions: dict | None = None):
        self.clock = clock
        self.handlers: dict = {}
        self.browser = LoginBrowser()
        self.page_list = [LoginPage(self, actions if i == 0 else None) for i in range(n_pages)]
        self.forbidden: list[str] = []

    @property
    def pages(self):
        return list(self.page_list)

    def on(self, event, handler):
        self.handlers[event] = handler

    def __getattr__(self, name):
        self.__dict__.setdefault("forbidden", []).append(name)
        return lambda *a, **k: [{"name": "privy-token", "value": FAKE_JWT}]


class LoginLauncher:
    def __init__(self, ctx: LoginContext, exit_error: Exception | None = None):
        self.ctx, self.exit_error = ctx, exit_error
        self.calls: list = []
        self.closed = 0

    def __call__(self, profile):
        self.calls.append(Path(profile))
        return self

    def __enter__(self):
        return self.ctx

    def __exit__(self, *exc):
        self.closed += 1
        if self.exit_error is not None and exc[0] is None:
            raise self.exit_error
        return False


def owner_closes(page):  # the owner closes the window: the page closes and leaves the context
    page.closed = True
    page.ctx.page_list.remove(page)


def browser_quits_silently(page):  # the whole browser exits; no page close event reaches the script (the 2026-11-05 hang)
    page.gone = True


def browser_disconnects(page):
    page.ctx.browser.handlers["disconnected"](page.ctx.browser)


def context_closes(page):
    page.ctx.handlers["close"](page.ctx)


class LoginTests(TempRun):
    def run_login(self, ctx: LoginContext, **kw) -> tuple[int, str, LoginLauncher]:
        """sb.login in a worker thread with a 10 s bound, so a login that waits forever (the 2026-11-05 hang) fails the test
        instead of hanging the suite."""
        import threading

        launcher = LoginLauncher(ctx, **kw)
        out = io.StringIO()
        result: list = []

        def go():
            with contextlib.redirect_stdout(out):
                result.append(sb.login(self.profile, launcher=launcher, clock=ctx.clock))

        worker = threading.Thread(target=go, daemon=True)
        worker.start()
        worker.join(10)
        self.assertFalse(worker.is_alive(), "--login kept waiting after the browser was closed or gone")
        return result[0], out.getvalue(), launcher

    def test_login_opens_one_visible_window_on_scanner_net_and_exits_when_the_owner_closes_it(self):
        before = lock_state(self.profile)
        ctx = LoginContext(Clock(), actions={3: owner_closes})
        code, printed, launcher = self.run_login(ctx)
        self.assertEqual((code, launcher.calls, launcher.closed), (0, [self.profile], 1))
        page = launcher.ctx.page_list[0] if launcher.ctx.page_list else None
        self.assertIsNone(page, "the owner closed the only window")
        for line in (f"Profile: {self.profile}", f"Opening: {sb.LOGIN_URL}", *sb.LOGIN_STEPS, sb.LOGIN_DONE):
            self.assertIn(line, printed)
        self.assertEqual(sb.LOGIN_URL, "https://www.scanner.net/sol/scanner")
        self.assertEqual(lock_state(self.profile), before)

    def test_it_exits_when_the_browser_quits_without_any_page_close_event(self):
        """The live hang of 2026-11-05: the owner closed the window, Camoufox exited, no close event arrived and the old
        time.sleep loop kept waiting. Now the next wait fails and the script ends by itself."""
        ctx = LoginContext(Clock(), actions={2: browser_quits_silently})
        code, printed, _ = self.run_login(ctx)
        self.assertEqual(code, 0)
        self.assertTrue(printed.rstrip().endswith(sb.LOGIN_DONE))
        self.assertEqual((len(ctx.page_list), ctx.page_list[0].is_closed()), (1, False), "the page was never reported closed")
        self.assertLessEqual(ctx.page_list[0].waits, 3)

    def test_it_exits_on_the_browser_disconnected_or_the_context_close_event(self):
        for name, action in (("disconnected", browser_disconnects), ("context close", context_closes)):
            with self.subTest(name):
                ctx = LoginContext(Clock(), actions={4: action})
                code, printed, _ = self.run_login(ctx)
                self.assertEqual((code, ctx.page_list[0].waits), (0, 4))
                self.assertIn(sb.LOGIN_DONE, printed)
                self.assertEqual(set(ctx.handlers), {"close"})
                self.assertEqual(set(ctx.browser.handlers), {"disconnected"})

    def test_a_sign_in_window_left_open_keeps_it_waiting_until_that_one_closes_too(self):
        ctx = LoginContext(Clock(), n_pages=2, actions={2: owner_closes})
        popup = ctx.page_list[1]
        popup.actions = {3: owner_closes}
        code, printed, _ = self.run_login(ctx)
        self.assertEqual((code, popup.waits, ctx.page_list), (0, 3, []))
        self.assertIn(sb.LOGIN_DONE, printed)

    def test_a_window_left_open_is_closed_for_the_owner_after_the_hour(self):
        ctx = LoginContext(Clock())
        code, printed, launcher = self.run_login(ctx)
        self.assertEqual((code, launcher.closed), (0, 1))
        self.assertIn(sb.LOGIN_TIME_UP, printed)
        self.assertLessEqual(ctx.page_list[0].waits, int(sb.LOGIN_MAX_S / sb.LOGIN_POLL_S) + 1)

    def test_an_error_while_the_closed_browser_shuts_down_still_reports_done(self):
        ctx = LoginContext(Clock(), actions={1: browser_quits_silently})
        code, printed, _ = self.run_login(ctx, exit_error=RuntimeError("Connection closed"))
        self.assertEqual(code, 0)
        self.assertIn(sb.LOGIN_DONE, printed)
        self.assertNotIn("browser failed", printed)

    def test_it_never_types_clicks_or_reads_the_page_and_never_sleeps_outside_the_browser(self):
        ctx = LoginContext(Clock(), actions={2: owner_closes})
        page = ctx.page_list[0]
        self.run_login(ctx)
        self.assertEqual((page.forbidden, ctx.forbidden), ([], []))
        tree = ast.parse((SCRIPTS / "scanner_browser.py").read_text(encoding="utf-8"))
        called = {n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "") for n in ast.walk(tree) if isinstance(n, ast.Call)}
        self.assertNotIn("sleep", called, "a plain sleep never sees the browser's events (the 2026-11-05 hang)")

    def test_the_real_login_launcher_is_visible_and_the_scan_launcher_headless(self):
        captured = []
        fake = types.ModuleType("camoufox.sync_api")
        fake.Camoufox = lambda **kw: captured.append(kw) or "ctx"
        with mock.patch.dict(sys.modules, {"camoufox": types.ModuleType("camoufox"), "camoufox.sync_api": fake}):
            sb.login_launcher(self.profile)
            sb.camoufox_launcher(self.profile, 1000.0)
        self.assertEqual((captured[0]["headless"], captured[0]["persistent_context"], captured[0]["user_data_dir"]), (False, True, str(self.profile)))
        self.assertEqual((captured[1]["headless"], captured[1]["persistent_context"], captured[1]["user_data_dir"]), (True, True, str(self.profile)))

    def test_the_profile_is_the_owners_scanner_profile_built_from_home(self):
        self.assertEqual(sb.PROFILE_DIR, Path.home() / ".local/share/camoufox-stealth/profiles/solscanner")
        code = (SCRIPTS / "scanner_browser.py").read_text(encoding="utf-8")
        self.assertNotIn("/Users/", code)
        self.assertNotIn("login(", code.split("def collect_scanner_browser(", 1)[1].split("\ndef status_line", 1)[0], "a scan never logs in")


# ----------------------------------------------------------------------------- --present


class PresentTests(TempRun):
    def test_each_state_prints_one_scanner_line(self):
        self.assertEqual(sb.present(self.run_dir), ["Scanner (formerly SolScanner): logged-in page lane not run yet"])
        self.keyless_file()
        res, _ = self.collect(signed_in_page(Clock()))
        self.save(res)
        with mock.patch.object(ss, "utc_now", return_value=dt.datetime.fromtimestamp(NOW, dt.timezone.utc)):
            lines = sb.present(self.run_dir)
        self.assertEqual(lines, ["Scanner (formerly SolScanner): read from the logged-in scanner.net page; free endpoint not read: not_cached_needs_login; "
                                 "cached, no scan spent; 11 bundle groups, largest 4.5% (risk 84); scan 13.9h old (stale); not an all-clear "
                                 "(presentation only: read after the forensics verdict, never in it)"])
        self.keyless_file("ok")
        res = sb.collect_scanner_browser(MAMESUKE, self.run_dir, profile=self.profile, launcher=refuse_launch, clock=Clock(), now=lambda: NOW)
        self.save(res)
        self.assertEqual(sb.present(self.run_dir), ["Scanner (formerly SolScanner): read by the free keyless endpoint (no browser launched)"])
        self.keyless_file()
        res, _ = self.collect(FakePage(Clock(), other_requests()))
        self.save(res)
        self.assertEqual(sb.present(self.run_dir), ["Scanner (formerly SolScanner): not read (free endpoint not read: not_cached_needs_login; logged-in page not read: "
                                                    f"signed in, but the page started no scan within {sb.START_GRACE_S:.0f} s (a click may be needed; this lane never clicks))"])
        (self.run_dir / sb.OUT_DIR / sb.OUT_FILE).write_text("{bad")
        self.assertEqual(sb.present(self.run_dir), ["Scanner (formerly SolScanner): logged-in page lane file unreadable"])


if __name__ == "__main__":
    unittest.main()
