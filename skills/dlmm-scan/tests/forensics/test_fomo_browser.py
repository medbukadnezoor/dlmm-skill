"""DS-FOMO-BROWSER-T1: the follow-up-wave collector `fomo_browser` (the Fomo theses read from the owner's logged-in
fomo.family page when Fomo API could not read them) and the `fomo_theses.py --present` wording that shows them. Offline: the
browser is a fake (no Camoufox, no network: sockets blocked), a fake clock, temp profile folders; the page's thesis feed is
the owner's saved logged-in capture of 2026-09-20 (tests/forensics/fixtures/fomo_browser/, the thesis feed JSON only,
redacted: avatar and token-image links, the viewer's own like state and share-tracking values removed; the capture's older
script had already replaced every token address with "[redacted]", so the tests put a token address back where they need
one). The logged-out page is replayed as seen live on 2026-10-25: the token page loads, the app never calls its API, and
about 1 s later it sends the browser to the landing page "/".

Covers the ticket's acceptance criteria: (1) API ok -> no browser launch (a launcher that fails if called); (2) a locked
profile -> "profile in use", the lock files untouched (temp lock files held by another process, hashes, inodes and times);
(3) a logged-out page -> login_needed, and --present prints the exact login command; (4) the rows go through
fomo_theses.clean_text, and no cookie, header, token or local-storage value is saved or printed (fake tokens everywhere the
browser could hand them over); (5) the hard 60 s limit, and the browser always closed, also on errors; (6) the fallback rows
print with the "(read from the logged-in fomo.family page; ...)" label and "not read" never becomes "no chatter"; (7) assess
is byte-identical with and without followup/fomo_browser.json, and the engines never name it.

DS-FOMO-LOGIN-T1 (section 8): fomo_browser.py --login, the owner's login window. A profile held by another process (a regular
lock held with fcntl, or a symlink lock naming a live process) refuses with one line, exit 3, no launch, every lock file
unchanged; otherwise the real launcher hands a fake Camoufox the older login script's options (visible), the start page is
Google or fomo.family, the window stays until the last one is closed, and nothing in the profile is written or deleted. No
real browser and no real profile: temp folders and a fake camoufox module only."""

from __future__ import annotations

import ast
import contextlib
import copy
import datetime as dt
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import types
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import fomo_browser as fb  # noqa: E402
import fomo_theses as ft  # noqa: E402
from test_assess import _map, _run, case_negative_space_inu, run_assess  # noqa: E402
from test_fomo_theses import RUNS, answer, collect, fixture, http_error, payload  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures" / "fomo_browser"
CAPTURE = "page_thesis_feed_capture_20260920.json"
BTC = "C5xph2yL6gMdxmuLGxJBkGpmuDFfyi5fqkBNhvL6pump"
MARK = "[for the executive summary] "
CAPTURED_AT = dt.datetime(2026, 9, 20, 11, 50, tzinfo=dt.timezone.utc).timestamp()
CREDITS_WHY = "credits_exhausted: out of Fomo API credits, HTTP 402"
LABEL = f"read from the logged-in fomo.family page; API not read: {CREDITS_WHY}"
FAKE_JWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmYWtlLXVzZXIifQ.fAkEsIgNaTuReOnLyFoRtEsTs00"
FAKE_COOKIE = "privy-token=fake-cookie-value-7f3a9c2e1b"
FAKE_SESSION = "privy-session-fake-77c1d0aa9b3e"
FAKE_STORAGE = "local-storage-refresh-fake-a1b2c3d4e5"
FAKES = (FAKE_JWT, FAKE_COOKIE, FAKE_SESSION, FAKE_STORAGE, "fake-cookie-value-7f3a9c2e1b", "owner@example.com", "0xFAKEOWNERWALLET")
FORBIDDEN = {"cookies", "add_cookies", "clear_cookies", "storage_state", "evaluate", "evaluate_handle", "inner_text", "inner_html", "text_content",
             "content", "click", "dblclick", "fill", "type", "press", "check", "tap", "keyboard", "mouse", "touchscreen", "set_input_files",
             "dispatch_event", "screenshot", "route", "set_extra_http_headers", "add_init_script", "expose_function", "all_headers", "headers"}
LOGIN_COMMAND = ("\"${HOLDER_PYTHON:-python3}\" -I "  # DS-FOMO-LOGIN-T1 pin update: fomo_browser.py --login
                 "skills/dlmm-scan/scripts/fomo_browser.py --login")
OLD_LOGIN_SCRIPT = "open-fomo-profile.py"


def capture(mint: str | None = BTC) -> dict:
    """The saved page answer; with a mint, its token addresses put back (the capture holds "[redacted]" there)."""
    data = json.loads((FIX / CAPTURE).read_text(encoding="utf-8"))
    if mint is not None:
        for item in data["responseObject"]["items"]:
            item["tokenAddress"] = mint
            item["comment"]["tokenAddress"] = mint
    return data


def user_body(**extra) -> bytes:
    """The signed-in profile answer, carrying private values that must never be kept."""
    return json.dumps({"success": True, "message": "ok", "statusCode": 200, "responseObject": {
        "id": "me-0001", "address": "0xFAKEOWNERWALLET", "email": "owner@example.com", "privyToken": FAKE_JWT, **extra}}).encode()


class Clock:
    def __init__(self, start: float = 5000.0):
        self.t = start

    def __call__(self) -> float:
        return self.t


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
    def __init__(self, url: str, status: int = 200, body: bytes = b""):
        self.url = url
        self._response = FakeResponse(status, body)

    def response(self) -> FakeResponse:
        return self._response


def api(path: str) -> str:
    return f"https://{fb.API_HOST}{path}"


class FakePage:
    """A page that never touches the network: goto commits the address; each wait advances the fake clock and fires the
    scripted finished requests (seconds after goto) and an optional move of the page's address."""

    def __init__(self, clock: Clock, events=(), move=None, goto_error: Exception | None = None, wait_error_at: float | None = None):
        self.clock, self.events, self.move = clock, sorted(events, key=lambda e: e[0]), move
        self.goto_error, self.wait_error_at = goto_error, wait_error_at
        self.url = "about:blank"
        self.handlers: dict = {}
        self.gotos: list = []
        self.waits = 0
        self.forbidden: list[str] = []
        self.t0 = None

    def on(self, event, handler):
        assert event == "requestfinished", event
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
            self.handlers["requestfinished"](self.events.pop(0)[1])
        if self.move and self.t0 + self.move[0] <= self.clock.t:
            self.url = self.move[1]

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
        return lambda *a, **k: [{"name": "privy-token", "value": FAKE_JWT}, {"name": "session", "value": FAKE_SESSION}]


class Launcher:
    """A launcher (callable returning a context manager) that counts launches and closes."""

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


def signed_in_page(clock: Clock, feed: dict | None = None, user_at: float = 0.6, feed_at: float = 1.5, **kw) -> FakePage:
    events = [(user_at, FakeRequest(api(fb.USER_PATH), 200, user_body()))]
    if feed is not None:
        events.append((feed_at, FakeRequest(api(fb.THESIS_PATH), 200, json.dumps(feed).encode())))
    return FakePage(clock, events, **kw)


def logged_out_page(clock: Clock) -> FakePage:
    """As seen live on 2026-10-25 (a fresh session, and the owner's expired profile): no call to the app's API, then the
    app sends the browser to the landing page about 1 s after the token page loaded."""
    return FakePage(clock, [], move=(1.0, "https://fomo.family/"))


def lock_state(profile: Path) -> dict:
    out = {}
    for name in fb.LOCK_NAMES:
        p = profile / name
        if p.is_symlink():
            out[name] = ("symlink", os.readlink(p), os.lstat(p).st_ino, os.lstat(p).st_mtime_ns)
        elif p.exists():
            st = p.stat()
            out[name] = ("file", hashlib.sha256(p.read_bytes()).hexdigest(), st.st_ino, st.st_mtime_ns, st.st_size)
    return out


@contextlib.contextmanager
def lock_held(path: Path):
    """Another process holds a write lock on `path`, as a running Firefox holds .parentlock."""
    code = ("import fcntl, os, sys\nfd = os.open(sys.argv[1], os.O_RDWR)\nfcntl.lockf(fd, fcntl.LOCK_EX)\n"
            "print('locked', flush=True)\nsys.stdin.read()\n")
    proc = subprocess.Popen([sys.executable, "-I", "-c", code, str(path)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout.readline().strip() == "locked"
        yield proc
    finally:
        proc.stdin.close()
        proc.wait(timeout=10)


@contextlib.contextmanager
def no_network():
    def refuse(*_a, **_k):
        raise AssertionError("network access in a test")
    with mock.patch.object(socket, "create_connection", refuse), mock.patch.object(socket.socket, "connect", refuse), \
         mock.patch.object(urllib.request, "urlopen", refuse):
        yield


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

    def api_file(self, kind: str = "credits_exhausted", mint: str = BTC, run: Path | None = None) -> dict:
        """fomo_theses.json of the run, written by the real collector with a fake opener (no network, a dummy key)."""
        run = run or self.run_dir
        if kind == "ok":
            res, _ = collect([answer(payload(RUNS["btc"][1]))], mint=mint, now=RUNS["btc"][2])
        elif kind == "partial":
            data = payload(RUNS["btc"][1])
            data["partial"] = True
            res, _ = collect([answer(data)], mint=mint, now=RUNS["btc"][2])
        elif kind == "unavailable":
            res, _ = collect([http_error(401)], mint=mint)
        elif kind == "not_available":  # Fomo's own available:false answer (as saved live, without the other mint's key)
            data = json.loads(fixture(RUNS["unavailable"][1]))
            data.pop("key", None)
            res, _ = collect([answer(data, cost="0")], mint=mint)
        else:
            res, _ = collect([http_error(402, {"x-credits-cost": "0", "x-credits-remaining": "0"})], mint=mint)
        (run / ft.OUT_FILE).write_text(json.dumps(res, indent=1))
        return res

    def collect(self, page: FakePage | None, clock: Clock | None = None, **kw) -> tuple[dict, Launcher]:
        launcher = Launcher(page, **kw)
        clock = clock or (page.clock if page is not None else Clock())
        res = fb.collect_fomo_browser(BTC, self.run_dir, profile=self.profile, launcher=launcher, clock=clock, now=lambda: CAPTURED_AT)
        return res, launcher

    def save(self, res: dict, run: Path | None = None) -> Path:
        run = run or self.run_dir
        (run / fb.OUT_DIR).mkdir(exist_ok=True)
        (run / fb.OUT_DIR / fb.OUT_FILE).write_text(json.dumps(res, indent=1))
        return run

    def assert_clean_browser(self, launcher: Launcher):
        page = launcher.page
        self.assertEqual((page.forbidden, launcher.context.forbidden), ([], []), "no cookie, storage, header, script, click or typing call")
        for event in page.handlers:
            self.assertEqual(event, "requestfinished")


# ----------------------------------------------------------------------------- 1: no browser when the API was read


class WhenItRunsTests(TempRun):
    def test_api_ok_launches_no_browser(self):
        self.api_file("ok")
        with mock.patch.object(fb, "camoufox_launcher", refuse_launch), mock.patch.object(fb, "profile_in_use", side_effect=AssertionError("profile touched")):
            res = fb.collect_fomo_browser(BTC, self.run_dir, profile=self.profile, launcher=refuse_launch)
            res_default = fb.collect_fomo_browser(BTC, self.run_dir, profile=self.profile)
        for r in (res, res_default):
            self.assertEqual((r["status"], r["reason"], r["api_status"], r["page"]["browser_launched"], r["page"]["page_loads"]), ("not_needed", "api_ok", "ok", False, 0))
        self.assertEqual(fb.status_line(res), "not needed (Fomo API read ok; no browser launched)")
        self.assertNotIn("camoufox", sys.modules, "the browser library is never even imported")

    def test_api_ok_through_main_writes_the_file_and_launches_nothing(self):
        self.api_file("ok")
        out = io.StringIO()
        with mock.patch.object(fb, "camoufox_launcher", refuse_launch), mock.patch.object(fb, "PROFILE_DIR", self.profile), contextlib.redirect_stdout(out):
            code = fb.main([BTC, "--out", str(self.run_dir)])
        self.assertEqual((code, out.getvalue()), (0, "not needed (Fomo API read ok; no browser launched)\n"))
        saved = json.loads((self.run_dir / "followup" / "fomo_browser.json").read_text())
        self.assertEqual((saved["status"], saved["schema"], saved["source"]), ("not_needed", "holder-scan-fomo-browser/1", "fomo.family page (logged-in profile)"))

    def test_unavailable_or_unreadable_api_files_are_skipped_without_a_browser(self):
        for kind, reason in (("unavailable", "api_unavailable"), ("junk", "api_unreadable"), ("foreign", "api_unreadable")):
            with self.subTest(kind):
                if kind == "unavailable":
                    self.api_file("unavailable")
                elif kind == "junk":
                    (self.run_dir / ft.OUT_FILE).write_text("{not json")
                else:
                    self.api_file(mint=RUNS["fresh"][0])
                res = fb.collect_fomo_browser(BTC, self.run_dir, profile=self.profile, launcher=refuse_launch)
                self.assertEqual((res["status"], res["reason"], res["page"]["browser_launched"]), ("skipped", reason, False))
                self.assertIn("no browser launched", fb.status_line(res))

    def test_needs_fallback_and_a_missing_file_launch_exactly_one_page_load(self):
        for kind in ("credits_exhausted", "rate_limited", "not_available", "partial", "missing"):
            with self.subTest(kind):
                for p in self.run_dir.iterdir():
                    if p.is_file():
                        p.unlink()
                if kind == "rate_limited":
                    res, _ = collect([http_error(429, {"Retry-After": "1"}), http_error(429, {"Retry-After": "1"})], mint=BTC)
                    (self.run_dir / ft.OUT_FILE).write_text(json.dumps(res))
                elif kind != "missing":
                    self.api_file(kind)
                clock = Clock()
                page = signed_in_page(clock, capture())
                res, launcher = self.collect(page)
                self.assertEqual((res["status"], res["api_status"], len(launcher.calls), launcher.entered, launcher.closed, len(page.gotos)),
                                 ("ok", "missing" if kind == "missing" else "needs_fallback", 1, 1, 1, 1))
                self.assertEqual(page.gotos[0][:2], (f"https://fomo.family/tokens/solana/{BTC}", "commit"))
                self.assertEqual(launcher.calls[0][0], self.profile)
                self.assertEqual((res["page"]["page_loads"], res["page"]["clicks"], res["page"]["typed"]), (1, 0, 0))
                self.assert_clean_browser(launcher)


# ----------------------------------------------------------------------------- 2: a profile in use, lock files untouched


# The static write test (DS-FOMO-LOGIN-T1, extended by DS-TEST-HARDEN-T1): every way the script could write, copy, move,
# link or delete a file. profile_write_problems reads a source text, so the ticket's mutation check could hand it altered
# copies of fomo_browser.py; WRITES are found when added to the code, READS are not.
NEVER_CALLED = ("unlink", "remove", "rmtree", "rename", "replace", "rmdir", "chmod", "utime", "truncate", "write_bytes", "symlink",
                "touch", "link", "hardlink_to", "symlink_to", "makedirs",
                "copy", "copy_into", "move", "move_into")  # Path.copy, Path.copy_into, Path.move, Path.move_into: Python 3.14+
OS_OPEN_FLAGS = ("O_RDONLY", "O_NOFOLLOW", "O_CLOEXEC")  # the only os.open flags allowed: none creates, empties or appends
WRITES = ('open(path, "w")', 'open(path, "a")', 'open(path, "x")', 'open(path, "r+")', 'open(path, mode="wb")', "open(path, mode)",
          'path.open("w")', 'path.open(mode="a")', 'path.open("r+")', 'io.open(path, "w")', "opener = open",
          "path.touch()", "os.link(path, other)", "path.hardlink_to(other)", "path.symlink_to(other)", "os.makedirs(path)",
          '(path / "a").copy(path / "b")', '(path / "a").copy_into(path)', '(path / "a").move(path / "b")', '(path / "a").move_into(path)',
          "import shutil", "import shutil as sh", "from shutil import move", "shutil.copy(path, other)", "shutil.copy2(path, other)",
          "shutil.copyfile(path, other)", "shutil.copytree(path, other)", "shutil.move(path, other)",
          "os.open(path, os.O_RDONLY | os.O_CREAT)", "os.open(path, os.O_RDONLY | os.O_TRUNC)", "os.open(path, os.O_RDONLY | os.O_APPEND)",
          "os.open(path, flags)", "os.open(path, 0o1000)", "os.open(path, os.O_RDONLY | getattr(os, 'O_CREAT', 0))",
          "os.replace(path, other)", "os.rename(path, other)", "os.remove(path)", "os.unlink(path)")
READS = ("open(path)", 'open(path, "rb")', "path.open()", 'path.open("r", encoding="utf-8")', "os.open(path, os.O_RDONLY | os.O_CLOEXEC)")


def _read_only_flags(node: ast.AST) -> bool:
    """An os.open flags expression made only of OS_OPEN_FLAGS (os.O_X, or getattr(os, "O_X", 0)) joined by "|"."""
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
        return _read_only_flags(node.left) and _read_only_flags(node.right)
    if isinstance(node, ast.Attribute):
        return ast.unparse(node.value) == "os" and node.attr in OS_OPEN_FLAGS
    return (isinstance(node, ast.Call) and ast.unparse(node.func) == "getattr" and len(node.args) == 3 and not node.keywords
            and ast.unparse(node.args[0]) == "os" and isinstance(node.args[1], ast.Constant) and node.args[1].value in OS_OPEN_FLAGS
            and isinstance(node.args[2], ast.Constant) and node.args[2].value == 0)


def _read_only_mode(call: ast.Call) -> bool:
    """A builtin open() or a .open() whose mode is written out and holds none of w, a, x or + (no mode at all reads "r").
    The mode is looked for in every place it can sit: the second argument of open(), the first or second of a .open()
    (Path.open takes it first, io.open second) and mode=; anything there that is not written out (a name, *args, **kwargs)
    leaves it unknown, so the call counts as a write."""
    if any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
        return False
    places = (1,) if isinstance(call.func, ast.Name) else (0, 1)
    modes = [call.args[i] for i in places if i < len(call.args)] + [k.value for k in call.keywords if k.arg == "mode"]
    return all(isinstance(m, ast.Constant) and not (isinstance(m.value, str) and set(m.value) & set("wax+")) for m in modes)


def profile_write_problems(code: str) -> list[str]:
    """Every way the source `code` could write, copy, move, link or delete a file; [] when there is none."""
    tree = ast.parse(code)
    nodes = list(ast.walk(tree))
    calls = [n for n in nodes if isinstance(n, ast.Call)]
    names = {n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "") for n in calls}
    problems = [f"calls {name}" for name in NEVER_CALLED if name in names]
    # DS-FOMO-LOGIN-T1: the folders made are <RUN>/followup (main) and, by --login only, the profile folder when it is missing
    makers = {f.name: ast.unparse(n.func.value) for f in nodes if isinstance(f, ast.FunctionDef) for n in ast.walk(f)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "mkdir"}
    if code.count(".mkdir(") != 2 or makers != {"main": "run / OUT_DIR", "login": "profile"}:
        problems.append(f"the only folders made are <RUN>/followup and the missing profile folder: {makers}")
    if code.count(".write_text(") != 1:
        problems.append("the only file written is <RUN>/followup/fomo_browser.json")
    # any shutil use (copy, copy2, copyfile, copytree, move, ...): imported, named, or named in a string (__import__("shutil"))
    if [n for n in nodes if isinstance(n, ast.Import) and any(a.name.split(".")[0] == "shutil" for a in n.names)
            or isinstance(n, ast.ImportFrom) and (n.module or "").split(".")[0] == "shutil"
            or isinstance(n, ast.Name) and n.id == "shutil" or isinstance(n, ast.Constant) and n.value == "shutil"]:
        problems.append("uses shutil")
    called = set()
    for call in calls:
        func = call.func
        if isinstance(func, ast.Attribute) and func.attr == "open" and ast.unparse(func.value) == "os":
            called.add(id(func))
            flags = call.args[1] if len(call.args) > 1 else next((k.value for k in call.keywords if k.arg == "flags"), None)
            if flags is None or not _read_only_flags(flags):
                problems.append(f"os.open with flags other than {', '.join(OS_OPEN_FLAGS)}: {ast.unparse(call)}")
        elif isinstance(func, ast.Name) and func.id == "open" or isinstance(func, ast.Attribute) and func.attr == "open":
            called.add(id(func))
            if not _read_only_mode(call):
                problems.append(f"opens a file with no written read-only mode: {ast.unparse(call)}")
    problems += [f"refers to open without calling it: {ast.unparse(n)}" for n in nodes
                 if (isinstance(n, ast.Name) and n.id == "open" or isinstance(n, ast.Attribute) and n.attr == "open") and id(n) not in called]
    # the flag names as text too (a flag kept in a variable): only the read-only one appears
    if "os.O_RDONLY" not in code:
        problems.append("os.O_RDONLY is not used")
    problems += [f"names {flag}" for flag in ("O_RDWR", "O_WRONLY", "O_CREAT", "O_TRUNC", "O_APPEND") if flag in code]
    return problems


class ProfileLockTests(TempRun):
    def test_a_held_lock_reads_profile_in_use_and_no_lock_file_is_touched(self):
        self.api_file()
        lock = self.profile / ".parentlock"
        lock.write_bytes(b"")
        (self.profile / "parent.lock").write_bytes(b"older-lock-content")
        before = lock_state(self.profile)
        with lock_held(lock):
            res, launcher = self.collect(None)
            words = fb.check_login(self.profile, launcher=refuse_launch)
            out = io.StringIO()
            with mock.patch.object(fb, "PROFILE_DIR", self.profile), mock.patch.object(fb, "camoufox_launcher", refuse_launch), contextlib.redirect_stdout(out):
                code = fb.main(["--check-login"])
        self.assertEqual((res["status"], res["reason"], launcher.calls, res["page"]["browser_launched"]), ("not_read", "profile_in_use", [], False))
        self.assertEqual(fb.status_line(res), "not read (profile in use)")
        self.assertEqual(words, ("profile in use", 3))
        self.assertEqual((code, out.getvalue()), (3, "profile in use\n"))
        self.assertEqual(lock_state(self.profile), before, "the lock files keep their content, inode and time")
        self.assertEqual(sorted(p.name for p in self.profile.iterdir()), [".parentlock", "parent.lock"])

    def test_a_stale_unheld_lock_is_not_in_use_and_stays_untouched(self):
        self.api_file()
        (self.profile / ".parentlock").write_bytes(b"")
        before = lock_state(self.profile)
        res, launcher = self.collect(signed_in_page(Clock(), capture()))
        self.assertEqual((res["status"], len(launcher.calls)), ("ok", 1))
        self.assertEqual(lock_state(self.profile), before)

    def test_a_symlink_lock_names_the_holding_process(self):
        self.api_file()
        live = subprocess.Popen([sys.executable, "-I", "-c", "import sys; sys.stdin.read()"], stdin=subprocess.PIPE)
        try:
            os.symlink(f"127.0.0.1:+{live.pid}", self.profile / "lock")
            before = lock_state(self.profile)
            self.assertTrue(fb.profile_in_use(self.profile))
            res, launcher = self.collect(None)
            self.assertEqual((res["status"], res["reason"], launcher.calls), ("not_read", "profile_in_use", []))
            self.assertEqual(lock_state(self.profile), before)
        finally:
            live.stdin.close()
            live.wait(timeout=10)
        dead = subprocess.Popen([sys.executable, "-I", "-c", "pass"])
        dead.wait()
        (self.profile / "lock").unlink()
        os.symlink(f"127.0.0.1:+{dead.pid}", self.profile / "lock")
        self.assertFalse(fb.profile_in_use(self.profile), "a lock left by a process that ended is not in use")

    def test_a_launch_that_fails_while_another_browser_took_the_profile_reads_in_use(self):
        self.api_file()
        lock = self.profile / ".parentlock"
        lock.write_bytes(b"")
        state = {"held": None}

        class Racing(Launcher):
            def __enter__(inner):
                state["held"] = lock_held(lock)
                state["held"].__enter__()
                raise RuntimeError("browser exited: profile already in use")

        launcher = Racing()
        try:
            res = fb.collect_fomo_browser(BTC, self.run_dir, profile=self.profile, launcher=launcher, clock=Clock(), now=lambda: CAPTURED_AT)
        finally:
            state["held"].__exit__(None, None, None)
        self.assertEqual((res["status"], res["reason"]), ("not_read", "profile_in_use"))

    def test_the_code_never_deletes_moves_or_writes_in_the_profile(self):
        code = (SCRIPTS / "fomo_browser.py").read_text(encoding="utf-8")
        self.assertEqual(profile_write_problems(code), [])
        for added in WRITES:  # DS-TEST-HARDEN-T1: each way of writing is found once it is in the code; reading is not
            with self.subTest(added):
                self.assertNotEqual(profile_write_problems(f"{code}\n{added}\n"), [], added)
        for added in READS:
            with self.subTest(added):
                self.assertEqual(profile_write_problems(f"{code}\n{added}\n"), [], added)


# ----------------------------------------------------------------------------- 3: logged out


class LoggedOutTests(TempRun):
    def test_the_landing_page_redirect_seen_live_reads_login_needed_fast(self):
        self.api_file()
        page = logged_out_page(Clock())
        res, launcher = self.collect(page)
        self.assertEqual((res["status"], res["reason"], res["theses"], res["page"]["went"], res["page"]["signed_in_answer"]),
                         ("login_needed", "landing_page", [], "landing", None))
        self.assertLess(res["page"]["seconds"], 5.0, "it stops soon after the redirect, never waiting the whole 60 s")
        self.assertEqual(fb.status_line(res), "login_needed (fomo.family profile logged out (the token page went to the landing page); "
                                              f"to log in once, run: {LOGIN_COMMAND})")
        self.assertEqual(launcher.closed, 1)
        self.assert_clean_browser(launcher)

    def test_other_logged_out_signs(self):
        cases = (("refused", FakePage(Clock(), [(0.5, FakeRequest(api(fb.USER_PATH), 401))]), "signed_out"),
                 ("forbidden", FakePage(Clock(), [(0.5, FakeRequest(api(fb.USER_PATH), 403))]), "signed_out"),
                 ("sign-in path", FakePage(Clock(), [], move=(1.0, "https://fomo.family/login?next=x")), "sign_in_page"),
                 ("another site", FakePage(Clock(), [], move=(1.0, "https://accounts.example/signin")), "sign_in_page"))
        for name, page, reason in cases:
            with self.subTest(name):
                self.api_file()
                res, _ = self.collect(page)
                self.assertEqual((res["status"], res["reason"]), ("login_needed", reason))
        shutil.rmtree(self.profile)
        res, launcher = self.collect(None)
        self.assertEqual((res["status"], res["reason"], launcher.calls), ("login_needed", "profile_missing", []))
        self.assertFalse(self.profile.exists(), "a missing profile folder is never created")

    def test_signed_in_a_page_that_goes_elsewhere_is_not_a_logout(self):
        self.api_file()
        page = FakePage(Clock(), [(0.4, FakeRequest(api(fb.USER_PATH), 200, user_body()))], move=(1.0, "https://fomo.family/"))
        res, _ = self.collect(page)
        self.assertEqual((res["status"], res["reason"]), ("not_read", "token_page_left"))

    def test_check_login_prints_only_the_three_words(self):
        cases = ((logged_out_page(Clock()), ("logged out", 2)), (signed_in_page(Clock()), ("logged in", 0)),
                 (FakePage(Clock(), [(0.5, FakeRequest(api(fb.USER_PATH), 401))]), ("logged out", 2)))
        for page, expected in cases:
            with self.subTest(expected):
                launcher = Launcher(page)
                self.assertEqual(fb.check_login(self.profile, launcher=launcher, clock=page.clock), expected)
                self.assertEqual(page.gotos[0][0], f"https://fomo.family/tokens/solana/{fb.CHECK_MINT}")
                self.assertEqual((len(launcher.calls), launcher.closed), (1, 1))
                self.assert_clean_browser(launcher)
        silent = FakePage(Clock(), [])
        words, code = fb.check_login(self.profile, launcher=Launcher(silent), clock=silent.clock)
        self.assertEqual((words, code), ("not read (no sign-in answer within 60 s; the page may have changed)", 1))
        self.assertEqual(fb.check_login(self.tmp / "no-profile", launcher=refuse_launch), ("logged out", 2))
        refused = FakePage(Clock(), [(0.0, FakeRequest(api(fb.USER_PATH), 401))])
        for page, line, rc in ((refused, "logged out\n", 2), (signed_in_page(Clock(), user_at=0.0), "logged in\n", 0)):
            out = io.StringIO()  # main() runs on the real clock: answers due at once, so no real wait
            with mock.patch.object(fb, "PROFILE_DIR", self.profile), mock.patch.object(fb, "camoufox_launcher", Launcher(page)), contextlib.redirect_stdout(out):
                self.assertEqual(fb.main(["--check-login"]), rc)
            self.assertEqual(out.getvalue(), line)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(fb.main(["--check-login", BTC]), 2)

    def test_present_prints_the_exact_login_command(self):
        self.assertEqual(ft.LOGIN_COMMAND, LOGIN_COMMAND)
        self.api_file()
        res, _ = self.collect(logged_out_page(Clock()))
        lines = ft.present(self.save(res))
        self.assertEqual(lines[0], f"{MARK}Fomo chatter: not read ({CREDITS_WHY}; fomo.family profile logged out — to log in once, run: {LOGIN_COMMAND})")
        self.assertEqual(lines[1], f"{ft.TITLE}: not read ({CREDITS_WHY}; fomo.family profile logged out)")
        self.assertEqual(lines[2], "  to log in once (a browser window opens: sign in with Google, then close the window), run:")
        self.assertEqual(lines[3], f"  {LOGIN_COMMAND}", "the command on its own line")
        self.assertTrue(lines[4].startswith("  credits: 1 Fomo API call"))
        for line in lines:
            self.assertNotIn("no chatter", line)
            self.assertNotIn("0 theses", line)

    def test_logged_out_with_a_partial_api_list_keeps_the_list_and_prints_the_command(self):
        self.api_file("partial")
        res, _ = self.collect(logged_out_page(Clock()))
        lines = ft.present(self.save(res))
        self.assertTrue(lines[0].startswith(f"{MARK}Fomo chatter (presentation only): 25 theses read (partial; Fomo counts 593)"), lines[0])
        self.assertTrue(lines[0].endswith(f" (browser fallback: fomo.family profile logged out — to log in once, run: {LOGIN_COMMAND})."), lines[0])
        at = lines.index("  partial: Fomo was still fetching older theses; the list below is what it had (browser fallback: fomo.family profile logged out)")
        self.assertEqual(lines[at + 2], f"  {LOGIN_COMMAND}")

    def test_api_file_missing_and_logged_out(self):
        res, _ = self.collect(logged_out_page(Clock()))
        self.assertEqual(res["api_status"], "missing")
        lines = ft.present(self.save(res))
        self.assertEqual(lines[0], f"{MARK}Fomo chatter: not read (fomo_theses.json missing; the fomo_theses collector did not run; "
                                   f"fomo.family profile logged out — to log in once, run: {LOGIN_COMMAND})")
        self.assertEqual(lines[3], f"  {LOGIN_COMMAND}")


# ----------------------------------------------------------------------------- 4: cleaned rows, nothing private kept


class RowsAndPrivacyTests(TempRun):
    def test_the_saved_capture_parses_in_the_api_shape_through_clean_text(self):
        feed = capture()
        with mock.patch.object(ft, "clean_text", wraps=ft.clean_text) as cleaner:
            parsed = fb.parse_feed(feed, BTC, CAPTURED_AT)
        items = feed["responseObject"]["items"]
        self.assertEqual((parsed["status"], len(parsed["rows"]), parsed["total"], parsed["has_next_page"], parsed["dropped"], parsed["other_token"]),
                         ("ok", 25, 262, False, 0, 0))
        self.assertEqual([c.args[0] for c in cleaner.call_args_list], [i["comment"]["comment"] for i in items], "every text through the shared cleaner")
        for row, item in zip(parsed["rows"], items):
            self.assertEqual(set(row), {"id", "handle", "name", "userId", "equity", "tradeUsd", "isDev", "likes", "replies", "ts", "text"})
            self.assertEqual(row["text"], ft.clean_text(item["comment"]["comment"]))
            self.assertEqual((row["likes"], row["replies"], row["isDev"], row["equity"]), (item["comment"]["numLikes"], item["numReplies"], item["isDev"], 0.0))
            self.assertEqual(row["tradeUsd"], float(item["authorTrade"]["usdValue"]), "Fomo API's tradeUsd is the page's authorTrade.usdValue")
            self.assertTrue(row["ts"].endswith("Z"))
            self.assertNotIn("\n", row["text"])
            self.assertNotIn("x.com", row["text"])
        self.assertTrue(any("[link]" in r["text"] for r in parsed["rows"]))
        closed = [r for r, i in zip(parsed["rows"], items) if i["authorTrade"]["closedAt"]]
        self.assertTrue(closed and all(abs(r["tradeUsd"]) < 0.01 for r in closed), "a closed position reads about $0, as Fomo API's tradeUsd")

    def test_as_captured_the_redacted_token_addresses_are_another_token(self):
        parsed = fb.parse_feed(capture(None), BTC, CAPTURED_AT)
        self.assertEqual((parsed["status"], parsed["rows"], parsed["other_token"]), ("ok", [], 25))

    def test_a_changed_page_shape_is_not_read_never_no_theses(self):
        feed = capture()
        for name, damage in (("no success", lambda d: d.update(success=False)), ("no items", lambda d: d["responseObject"].pop("items")),
                             ("renamed text", lambda d: [i["comment"].update(body=i["comment"].pop("comment")) for i in d["responseObject"]["items"]]),
                             ("not a dict", lambda d: d.clear())):
            with self.subTest(name):
                data = copy.deepcopy(feed)
                damage(data)
                self.assertEqual(fb.parse_feed(data, BTC, CAPTURED_AT), {"status": "not_read", "reason": "page_shape_changed"})
                self.api_file()
                page = signed_in_page(Clock(), data)
                res, _ = self.collect(page)
                self.assertEqual((res["status"], res["reason"], fb.status_line(res)), ("not_read", "page_shape_changed", "not read (page shape changed)"))
                lines = ft.present(self.save(res))
                self.assertEqual(lines[0], f"{MARK}Fomo chatter: not read ({CREDITS_WHY}; browser fallback not read: page shape changed)")

    def test_no_cookie_header_token_or_storage_value_is_saved_or_printed(self):
        feed = capture()
        for item in feed["responseObject"]["items"]:
            item.update(accessToken=FAKE_JWT, session=FAKE_SESSION, privy={"refresh": FAKE_STORAGE})
        feed["authToken"] = FAKE_JWT
        self.api_file()
        page = signed_in_page(Clock(), feed)
        res, launcher = self.collect(page)
        self.assertEqual(res["status"], "ok")
        self.assert_clean_browser(launcher)
        saved = json.dumps(res)
        printed = "\n".join([fb.status_line(res), *ft.present(self.save(res))])
        for fake in FAKES:
            self.assertNotIn(fake, saved, fake)
            self.assertNotIn(fake, printed, fake)
        for word in ("cookie", "privy", "authorization", "Bearer", "localStorage", "accessToken", "authToken"):
            self.assertNotIn(word, saved.replace("no cookie, header, token or local-storage value", ""), word)
        self.assertFalse([r for r in page.events], "every scripted answer was delivered")

    def test_only_the_two_api_paths_are_kept_and_their_headers_never_read(self):
        clock = Clock()
        other = [(0.2, FakeRequest(f"https://fomo.family/_root.data?x={FAKE_JWT}", 200, json.dumps({"token": FAKE_JWT}).encode())),
                 (0.3, FakeRequest(f"https://auth.privy.io/api/v1/sessions", 200, json.dumps({"token": FAKE_JWT, "refresh_token": FAKE_STORAGE}).encode())),
                 (0.4, FakeRequest(api("/feed/token"), 200, json.dumps({"success": True, "responseObject": {"items": [{"text": FAKE_SESSION}]}}).encode()))]
        page = signed_in_page(clock, capture())
        page.events = sorted(page.events + other, key=lambda e: e[0])
        responses = [e[1]._response for e in page.events]
        self.api_file()
        res, launcher = self.collect(page)
        self.assertEqual((res["status"], len(res["theses"])), ("ok", 25))
        self.assertEqual([r.forbidden for r in responses], [[]] * len(responses), "no response header is ever read")
        self.assertEqual(launcher.page.forbidden, [])
        for fake in FAKES:
            self.assertNotIn(fake, json.dumps(res))

    def test_the_code_reads_no_cookie_storage_header_or_page_text_and_never_clicks_or_types(self):
        tree = ast.parse((SCRIPTS / "fomo_browser.py").read_text(encoding="utf-8"))
        used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        self.assertEqual(sorted(used & FORBIDDEN), [])
        self.assertTrue({"response", "body", "status", "goto", "wait_for_timeout", "on", "url"} <= used)


# ----------------------------------------------------------------------------- 5: the hard 60 s limit, always closed


class LimitTests(TempRun):
    def test_a_page_that_never_answers_stops_at_60_s_counted_from_before_the_launch(self):
        self.api_file()
        page = FakePage(Clock(), [(0.5, FakeRequest(api(fb.USER_PATH), 200, user_body()))])
        res, launcher = self.collect(page, enter_cost=9.0)
        self.assertEqual((res["status"], res["reason"], fb.status_line(res)), ("not_read", "no_thesis_data", "not read (page shape changed: no thesis data within 60 s)"))
        self.assertLessEqual(res["page"]["seconds"], 60.0 + fb.POLL_MS / 1000.0)
        self.assertGreaterEqual(res["page"]["seconds"], 60.0)
        self.assertLessEqual(page.waits, int(60.0 / (fb.POLL_MS / 1000.0)) + 1)
        self.assertEqual(launcher.closed, 1)
        self.assertLessEqual(launcher.calls[0][1], fb.LAUNCH_TIMEOUT_S * 1000.0)
        self.assertLessEqual(page.gotos[0][2], (60.0 - 9.0) * 1000.0 + 1, "the page load gets only what the launch left")

    def test_a_long_launch_leaves_less_time_and_still_ends_by_60_s(self):
        self.api_file()
        page = FakePage(Clock(), [])
        res, launcher = self.collect(page, enter_cost=45.0)
        self.assertLessEqual(res["page"]["seconds"], 60.0 + fb.POLL_MS / 1000.0)
        self.assertEqual(launcher.closed, 1)

    def test_errors_still_close_the_browser(self):
        cases = (("page load failed", dict(goto_error=RuntimeError("NS_ERROR_UNKNOWN_HOST")), "page_not_loaded", 1),
                 ("browser died", dict(wait_error_at=2.0), "browser_failed", 1),
                 ("slow page load", dict(goto_error=type("TimeoutError", (Exception,), {})("Timeout 51000ms exceeded")), "no_thesis_data", 1))
        for name, kw, reason, closed in cases:
            with self.subTest(name):
                self.api_file()
                page = FakePage(Clock(), [], **kw)
                res, launcher = self.collect(page)
                self.assertEqual((res["status"], res["reason"], launcher.closed), ("not_read", reason, closed))
        self.api_file()
        res, launcher = self.collect(FakePage(Clock(), []), enter_error=RuntimeError("launch failed"))
        self.assertEqual((res["status"], res["reason"]), ("not_read", "browser_failed"))
        res, _ = self.collect(FakePage(Clock(), []), enter_error=ModuleNotFoundError("No module named 'camoufox'"))
        self.assertEqual((res["status"], res["reason"]), ("not_read", "camoufox_missing"))
        self.assertIn("holder-tools", fb.status_line(res))

    def test_main_never_prints_a_traceback(self):
        self.api_file()

        def explode(*_a, **_k):
            raise ValueError(f"secret detail {FAKE_JWT}")

        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(fb, "collect_fomo_browser", explode), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = fb.main([BTC, "--out", str(self.run_dir)])
        self.assertEqual((code, out.getvalue(), err.getvalue()), (0, "not read (browser failed)\n", ""))
        self.assertNotIn(FAKE_JWT, (self.run_dir / "followup" / "fomo_browser.json").read_text())

    def test_bad_arguments_exit_2_without_a_browser(self):
        for argv in (["not-a-mint", "--out", str(self.run_dir)], [BTC]):
            err = io.StringIO()
            with mock.patch.object(fb, "camoufox_launcher", refuse_launch), contextlib.redirect_stderr(err):
                self.assertEqual(fb.main(argv), 2)


# ----------------------------------------------------------------------------- 6: the fallback in the Fomo chatter line and block


class PresentTests(TempRun):
    def ok_run(self, kind: str = "credits_exhausted") -> tuple[dict, Path]:
        if kind != "missing":
            self.api_file(kind)
        res, _ = self.collect(signed_in_page(Clock(), capture()))
        return res, self.save(res)

    def test_the_fallback_rows_print_with_the_label(self):
        res, run = self.ok_run()
        self.assertEqual(fb.status_line(res), "ok (25 theses read from the logged-in fomo.family page, Fomo counts 262; 1 page load, 1.5 s; no click, no typing)")
        lines = ft.present(run)
        self.assertTrue(lines[0].startswith(f"{MARK}Fomo chatter (presentation only): 25 theses read (Fomo counts 262), "), lines[0])
        self.assertTrue(lines[0].endswith(f"; most liked: @vascodicaprio (38 likes, position not read, $13,619 trade) ({LABEL})."), lines[0])
        self.assertIn("14 authors, dev thesis: no, newest 2m ago", lines[0])
        self.assertEqual(lines[1], f"Fomo theses ({LABEL}; untrusted text, quoted; presentation only)")
        self.assertTrue(lines[2].startswith("  coverage: captured 2026-09-20 11:50 UTC = 2026-09-20 18:50 WIB (when the page loaded its thesis feed); "), lines[2])
        self.assertIn("25 rows read, 25 kept; Fomo counts 262; more pages: no", lines[2])
        self.assertEqual(lines[3], "  browser: 1 page load of the token page on fomo.family in the owner's logged-in profile (headless, read-only: no click, "
                                   "no typing; 1.5 s); no cookie, header, token or local-storage value read or saved; no Fomo API credits used")
        self.assertTrue(lines[4].startswith(f"  Fomo API: not read ({CREDITS_WHY}); credits: 1 Fomo API call"), lines[4])
        self.assertIn("  positions: not read: the fomo.family page reported 0 for every position on the theses read; each thesis shows its trade "
                      "size (Fomo's tradeUsd) instead, never as a position", lines)
        self.assertIn("  dev thesis: none among the theses read (not proof the dev wrote none)", lines)
        top = lines[lines.index("  top 5 by likes:") + 1]
        self.assertTrue(top.startswith("    @") and "38 likes" in top and top.endswith("\""), top)
        self.assertIn(f"  cannot see: {ft.BROWSER_CANNOT_SEE}", lines)
        self.assertIn(f"  {ft.PRESENTATION_NOTE}", lines)
        self.assertFalse(any("x.com" in line for line in lines))
        self.assertIsNone(__import__("re").search(r"\b(clean|safe|low)\b", "\n".join(lines), __import__("re").IGNORECASE))

    def test_other_api_reasons_and_a_missing_api_file_carry_their_own_label(self):
        for kind, why in (("not_available", "not_available (upstream-unavailable): Fomo API reports the theses unavailable, not proof the coin has none"),
                          ("partial", ft.PARTIAL_WHY), ("missing", "fomo_theses.json missing; the fomo_theses collector did not run")):
            with self.subTest(kind):
                for p in self.run_dir.glob("*.json"):
                    p.unlink()
                _, run = self.ok_run(kind)
                lines = ft.present(run)
                self.assertTrue(lines[0].endswith(f" (read from the logged-in fomo.family page; API not read: {why})."), lines[0])
                self.assertEqual(lines[1], f"Fomo theses (read from the logged-in fomo.family page; API not read: {why}; untrusted text, quoted; presentation only)")

    def test_not_read_never_becomes_no_chatter(self):
        self.api_file()
        for reason, words in (("profile_in_use", "profile in use"), ("no_thesis_data", "page shape changed: no thesis data within 60 s"),
                              ("browser_failed", "browser failed"), ("camoufox_missing", "camoufox not installed in that Python")):
            with self.subTest(reason):
                res = fb._base(BTC, "2026-10-25T13:00:00Z", ("needs_fallback", "credits_exhausted"))
                res.update(status="not_read", reason=reason)
                lines = ft.present(self.save(res))
                self.assertEqual(lines[0], f"{MARK}Fomo chatter: not read ({CREDITS_WHY}; browser fallback not read: {words})")
                self.assertEqual(lines[1], f"{ft.TITLE}: not read ({CREDITS_WHY}; browser fallback not read: {words})")
                for line in lines:
                    self.assertNotIn("no chatter", line)
                    self.assertNotIn("0 theses", line)
        res = fb._base(BTC, "2026-10-25T13:00:00Z", ("needs_fallback", "credits_exhausted"))
        res.update(status="ok", captured_at="2026-10-25T13:00:01Z")
        lines = ft.present(self.save(res))
        self.assertEqual(lines[0], f"{MARK}Fomo chatter (presentation only): 0 theses read (Fomo's count not read; a bounded window, not proof nobody is talking) ({LABEL}).")

    def test_a_foreign_damaged_or_mismatched_fallback_file_is_said_and_never_used(self):
        res, run = self.ok_run()
        for name, damage, words in (("schema", lambda d: d.update(schema="x/1"), "browser fallback file unreadable"),
                                    ("presentation", lambda d: d.pop("presentation_only"), "browser fallback file unreadable"),
                                    ("theses", lambda d: d.update(theses={}), "browser fallback file unreadable"),
                                    ("another mint", lambda d: d.update(mint=RUNS["fresh"][0]), "browser fallback file does not match this run's fomo_theses.json"),
                                    ("another api status", lambda d: d.update(api_status="missing"), "browser fallback file does not match this run's fomo_theses.json"),
                                    ("not needed", lambda d: d.update(status="not_needed"), "browser fallback file does not match this run's fomo_theses.json")):
            with self.subTest(name):
                data = copy.deepcopy(res)
                damage(data)
                lines = ft.present(self.save(data, run))
                self.assertEqual(lines[0], f"{MARK}Fomo chatter: not read ({CREDITS_WHY}; {words})")
        (run / "followup" / "fomo_browser.json").write_text("{nope")
        self.assertEqual(ft.present(run)[0], f"{MARK}Fomo chatter: not read ({CREDITS_WHY}; browser fallback file unreadable)")

    def test_the_api_output_is_byte_identical_with_or_without_a_fallback_file(self):
        """API ok, unavailable, and needs_fallback with no fallback file: the lines are exactly the DS-FOMO-THESES-T1 ones."""
        for kind in ("ok", "unavailable", "credits_exhausted", "partial"):
            with self.subTest(kind):
                run = self.tmp / kind
                run.mkdir()
                self.api_file(kind, run=run)
                before = ft.present(run)
                if kind in ("ok", "unavailable"):
                    res = fb.collect_fomo_browser(BTC, run, profile=self.profile, launcher=refuse_launch)
                    self.save(res, run)
                    self.assertEqual(ft.present(run), before, "the fallback file of a run that did not need it changes nothing")
                if kind == "credits_exhausted":
                    self.assertTrue(before[0].endswith("; browser fallback not run yet)"))
                if kind == "partial":
                    self.assertIn("  partial: Fomo was still fetching older theses; the list below is what it had (browser fallback not run yet)", before)

    def test_present_stays_offline_and_never_imports_the_browser(self):
        _, run = self.ok_run()
        out = io.StringIO()
        with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(out):
            code = ft.main(["--present", str(run)])
        self.assertEqual(code, 0)
        self.assertIn("(read from the logged-in fomo.family page; API not read:", out.getvalue())
        present_code = (SCRIPTS / "fomo_theses.py").read_text(encoding="utf-8").split(
            "# ----------------------------------------------------------------------------- presentation (synthesis, offline)", 1)[1].split("def main(", 1)[0]
        for needle in ("import fomo_browser", "import camoufox", "from camoufox", "write_text", "environ", "getenv", "https://"):
            self.assertNotIn(needle, present_code, needle)

    def test_the_present_wording_covers_every_not_read_reason_of_the_collector(self):
        codes = {k for k in fb.REASON_WORDS if k not in ("landing_page", "sign_in_page", "signed_out", "profile_missing")}
        self.assertEqual(codes - set(ft.BROWSER_NOT_READ), set())
        self.assertEqual((ft.BROWSER_SCHEMA, ft.BROWSER_FILE.as_posix(), set(ft.BROWSER_STATUSES)), (fb.SCHEMA, f"{fb.OUT_DIR}/{fb.OUT_FILE}", set(fb.STATUSES)))
        self.assertEqual(ft.BROWSER_CANNOT_SEE, fb.CANNOT_SEE)


# ----------------------------------------------------------------------------- 7: never an engine input


class PresentationOnlyRuleTests(unittest.TestCase):
    """assess never reads followup/fomo_browser.json: the same assessment.json and report.md with or without it."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        case = case_negative_space_inu()
        cls.mint = case.mint
        cls.run_dir = cls.tmp / "space-run"
        code, _, _ = _run(["funders", case.mint, "--top", str(case.top), "--workers", "6", *case.collector_args, "--out", str(cls.run_dir)], fake=case.fake(), pairs=case.pairs)
        assert code == 0
        cls.alarm_map = cls.tmp / "alarm-map.json"
        cls.alarm_map.write_text(json.dumps(_map(case.mint, [(40, 25.0)], age=2.0)))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def assess(self, extra, name):
        out = self.tmp / name
        code, _, err = run_assess(self.mint, self.run_dir, extra, out=out)
        return code, err, ((out / "assessment.json").read_bytes() if code == 0 else None), ((out / "report.md").read_text() if code == 0 else None)

    def test_the_file_changes_nothing(self):
        clock = Clock()
        res = fb.collect_fomo_browser(self.mint, self.tmp / "nothing", profile=self.tmp, launcher=Launcher(signed_in_page(clock, capture(self.mint))),
                                      clock=clock, now=lambda: CAPTURED_AT)
        self.assertEqual(res["status"], "ok")
        for extra, tag in ((["--bubblemaps-json", str(self.alarm_map)], "alarm"), ([], "no-map")):
            with self.subTest(tag):
                code, err, before, md_before = self.assess(extra, f"{tag}-without")
                self.assertEqual(code, 0, err)
                (self.run_dir / "followup").mkdir(exist_ok=True)
                (self.run_dir / "followup" / "fomo_browser.json").write_text(json.dumps(res))
                try:
                    code, err, after, md_after = self.assess(extra, f"{tag}-with")
                finally:
                    shutil.rmtree(self.run_dir / "followup")
                self.assertEqual(code, 0, err)
                self.assertEqual((after, md_after), (before, md_before))

    def test_unknown_to_both_engines(self):
        for script in [SCRIPTS / "helius_forensics.py", SCRIPTS / "holder_analysis.py", *sorted((SCRIPTS / "ha").glob("*.py"))]:
            text = script.read_text(encoding="utf-8").lower()
            for needle in ("fomo_browser", "fomo.family page", "feed/token/thesis"):
                self.assertNotIn(needle, text, (script.name, needle))


# ----------------------------------------------------------------------------- 8: --login (DS-FOMO-LOGIN-T1), owner-run only


OLD_OPTIONS = {"persistent_context": True, "headless": False, "humanize": True, "block_webrtc": True}  # open-fomo-profile.py's, plus user_data_dir
OLD_STEPS = ["1) Sign into Google in this window.", "2) After Google is in, go to https://fomo.family/ and Start trading.",
             "3) Close the browser when both sessions are saved."]
OLD_DONE = "Browser closed. Session stayed in the profile directory."


class LoginPage:
    def __init__(self, window: "LoginWindow | None" = None):
        self.window = window
        self.gotos: list = []
        self.forbidden: list[str] = []

    def goto(self, url, wait_until=None, timeout=None):
        self.gotos.append((url, wait_until))

    def is_closed(self) -> bool:
        return self.window is not None and self not in self.window.windows

    def wait_for_timeout(self, ms):  # DS-SCANNER-FREE-T1 A2: the login waits through Playwright (each wait one tick)
        if self.is_closed() or self.window.gone:
            raise RuntimeError("Target page, context or browser has been closed")
        self.window.sleep(ms / 1000.0)

    def __getattr__(self, name):
        self.__dict__.setdefault("forbidden", []).append(name)
        return lambda *a, **k: FAKE_STORAGE


class LoginWindow:
    """The visible login browser: `windows` open (the first is the page the script loads); at each count in `closes_at` of the
    login loop's one-second waits the owner closes the OLDEST window, so the first page closes before the others."""

    def __init__(self, windows: int = 2, closes_at=(2, 5)):
        self.windows = [LoginPage(self) for _ in range(windows)]
        self.page = self.windows[0] if self.windows else None
        self.closes_at = list(closes_at)
        self.sleeps: list = []
        self.new_pages = self.exited = 0
        self.handlers: dict = {}
        self.gone = False  # the browser process quit without telling the window list (DS-SCANNER-FREE-T1 A2)
        self.browser = None  # a persistent context has no separate browser object
        self.forbidden: list[str] = []

    def on(self, event, handler):
        self.handlers[event] = handler

    @property
    def pages(self):
        return list(self.windows)

    def new_page(self):
        self.new_pages += 1
        self.page = LoginPage(self)
        self.windows.append(self.page)
        return self.page

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        while self.closes_at and self.closes_at[0] <= len(self.sleeps):
            self.closes_at.pop(0)
            self.windows.pop(0)
        if len(self.sleeps) > 100:
            raise AssertionError("the login loop never ended")

    def __getattr__(self, name):
        self.__dict__.setdefault("forbidden", []).append(name)
        return lambda *a, **k: [{"name": "privy-token", "value": FAKE_JWT}]


@contextlib.contextmanager
def fake_camoufox(window: LoginWindow | None = None, enter_error: Exception | None = None):
    """A camoufox module whose Camoufox records the options it was given; with no window, the launch is recorded and then fails
    (the login code turns a browser error into a fixed line, so the tests check the record, never only the error)."""
    calls: list = []

    class Camoufox:
        def __init__(self, **options):
            calls.append(options)
            if window is None and enter_error is None:
                raise AssertionError("a browser was launched")

        def __enter__(self):
            if enter_error is not None:
                raise enter_error
            return window

        def __exit__(self, *exc):
            window.exited += 1
            return False

    sync_api = types.ModuleType("camoufox.sync_api")
    sync_api.Camoufox = Camoufox
    package = types.ModuleType("camoufox")
    package.sync_api = sync_api
    with mock.patch.dict(sys.modules, {"camoufox": package, "camoufox.sync_api": sync_api}):
        yield calls


def no_plain_sleep(*_a, **_k):
    raise AssertionError("the login waits through Playwright; a plain time.sleep never sees the browser quit (DS-SCANNER-FREE-T1 A2)")


def profile_files(profile: Path) -> list:
    return sorted(p.relative_to(profile).as_posix() for p in profile.rglob("*")) if profile.exists() else []


class LoginTests(TempRun):
    def run_main(self, argv, window: LoginWindow | None = None, profile: Path | None = None) -> tuple[int, str, str, list]:
        out, err = io.StringIO(), io.StringIO()
        with fake_camoufox(window) as calls, mock.patch.object(fb, "PROFILE_DIR", profile or self.profile), \
                mock.patch.object(fb.time, "sleep", no_plain_sleep), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = fb.main(argv)
        return code, out.getvalue(), err.getvalue(), calls

    def test_a_held_lock_refuses_opens_nothing_and_leaves_every_lock_file_unchanged(self):
        lock = self.profile / ".parentlock"
        lock.write_bytes(b"")
        (self.profile / "parent.lock").write_bytes(b"older-lock-content")
        before, files = lock_state(self.profile), profile_files(self.profile)
        with lock_held(lock):
            for argv in (["--login"], ["--login", "--start", "fomo"], ["--login", "--start", "google"]):
                with self.subTest(argv):
                    code, out, err, calls = self.run_main(argv)
                    self.assertEqual((code, out, err, calls), (3, fb.LOGIN_IN_USE + "\n", "", []))
            attempts: list = []
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = fb.login(profile=self.profile, launcher=lambda p: attempts.append(p) or refuse_launch())
            self.assertEqual((code, out.getvalue(), attempts), (3, fb.LOGIN_IN_USE + "\n", []))
        self.assertEqual(lock_state(self.profile), before, "the lock files keep their bytes, inode and time")
        self.assertEqual(profile_files(self.profile), files, "nothing made, moved or deleted in the profile")

    def test_a_symlink_lock_naming_a_live_process_refuses_and_stays(self):
        live = subprocess.Popen([sys.executable, "-I", "-c", "import sys; sys.stdin.read()"], stdin=subprocess.PIPE)
        try:
            os.symlink(f"127.0.0.1:+{live.pid}", self.profile / "lock")
            before = lock_state(self.profile)
            code, out, _, calls = self.run_main(["--login"])
            self.assertEqual((code, out, calls), (3, fb.LOGIN_IN_USE + "\n", []))
            self.assertEqual(lock_state(self.profile), before)
            self.assertTrue((self.profile / "lock").is_symlink())
        finally:
            live.stdin.close()
            live.wait(timeout=10)

    def test_the_refusal_line_says_how_to_recover_and_never_to_delete_a_lock(self):
        line = fb.LOGIN_IN_USE
        self.assertNotIn("\n", line)
        for needle in ("the fomo.family profile is in use by another browser (or a running scan): close it and run this again",
                       "close every Camoufox/Firefox window", "restart the computer", "crashed browser", "Nothing was opened, deleted or changed."):
            self.assertIn(needle, line, needle)
        advice = line.replace("Nothing was opened, deleted or changed.", "")
        self.assertIsNone(__import__("re").search(r"(?i)delet|remov|unlink|\brm\b|lock file|\.parentlock|parent\.lock", advice), advice)
        self.assertIsNone(__import__("re").search(r"(?i)\b(clean|safe|low)\b", " ".join([line, *fb.LOGIN_STEPS, fb.LOGIN_DONE, fb.LOGIN_FAILED])))

    def test_not_in_use_opens_one_visible_window_with_the_old_options_until_the_last_window_closes(self):
        (self.profile / ".parentlock").write_bytes(b"")  # left by an earlier browser, not held: not in use, and left alone
        before, files = lock_state(self.profile), profile_files(self.profile)
        for argv, url in ((["--login"], "https://accounts.google.com/"), (["--login", "--start", "google"], "https://accounts.google.com/"),
                          (["--login", "--start", "fomo"], "https://fomo.family/")):
            with self.subTest(argv):
                window = LoginWindow(windows=2, closes_at=(2, 5))
                code, out, err, calls = self.run_main(argv, window)
                self.assertEqual((code, err), (0, ""))
                self.assertEqual(calls, [{**OLD_OPTIONS, "user_data_dir": str(self.profile)}], "one launch, visible, the old script's options")
                self.assertEqual(window.page.gotos, [(url, "domcontentloaded")])
                self.assertEqual(window.sleeps, [1.0] * 5, "it waits past the first window's close, until the last one is gone")
                self.assertEqual((window.exited, window.new_pages), (1, 0))
                self.assertEqual(out.splitlines(), [f"Profile: {self.profile}", f"Opening: {url}", *OLD_STEPS, OLD_DONE])
                self.assertEqual((window.forbidden, window.page.forbidden), ([], []), "no cookie, storage, page text, click or typing call")
        self.assertEqual(lock_state(self.profile), before)
        self.assertEqual(profile_files(self.profile), files)

    def bounded_login(self, window: LoginWindow) -> tuple[int, str]:
        """fb.login in a worker thread with a 10 s bound: a login that keeps waiting after the browser is gone fails here."""
        import threading

        out, result = io.StringIO(), []

        def go():
            with fake_camoufox(window), mock.patch.object(fb.time, "sleep", no_plain_sleep), contextlib.redirect_stdout(out):
                result.append(fb.login(profile=self.profile))

        worker = threading.Thread(target=go, daemon=True)
        worker.start()
        worker.join(10)
        self.assertFalse(worker.is_alive(), "--login kept waiting after the browser was gone")
        return result[0], out.getvalue()

    def test_it_ends_when_the_browser_quits_without_any_window_close_event(self):
        """DS-SCANNER-FREE-T1 Amendment A2: the hang seen live on 2026-11-05 (scanner_browser --login, the same loop as this
        file's): the owner closed the window, the browser quit, no close event reached the script, and a plain sleep loop kept
        waiting (a real headless control run of this file's old loop was still waiting 33 s after the browser was killed)."""

        class Quits(LoginWindow):
            def sleep(inner, seconds):
                super().sleep(seconds)
                if len(inner.sleeps) >= 3:
                    inner.gone = True  # the process is gone; the window list was never told

        window = Quits(windows=1, closes_at=())
        code, out = self.bounded_login(window)
        self.assertEqual((code, len(window.sleeps), len(window.windows)), (0, 3, 1))
        self.assertEqual(out.splitlines()[-1], OLD_DONE)

    def test_it_ends_on_the_context_close_event(self):
        class Closes(LoginWindow):
            def sleep(inner, seconds):
                super().sleep(seconds)
                if len(inner.sleeps) == 2:
                    inner.handlers["close"](inner)

        window = Closes(windows=1, closes_at=())
        code, out = self.bounded_login(window)
        self.assertEqual((code, len(window.sleeps)), (0, 2))
        self.assertEqual(out.splitlines()[-1], OLD_DONE)

    def test_the_wait_is_shared_with_scanner_browser_and_neither_sleeps_outside_the_browser(self):
        import scanner_browser as sb

        self.assertNotIn("def wait_until_closed", (SCRIPTS / "scanner_browser.py").read_text(encoding="utf-8"), "one helper, by import")
        self.assertIn("fb.wait_until_closed(", (SCRIPTS / "scanner_browser.py").read_text(encoding="utf-8"))
        self.assertEqual((sb.LOGIN_POLL_S, sb.LOGIN_MAX_S, sb.LOGIN_TIME_UP), (fb.LOGIN_POLL_S, fb.LOGIN_MAX_S, fb.LOGIN_TIME_UP))
        for name in ("fomo_browser.py", "scanner_browser.py"):
            tree = ast.parse((SCRIPTS / name).read_text(encoding="utf-8"))
            called = {n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", "") for n in ast.walk(tree) if isinstance(n, ast.Call)}
            self.assertNotIn("sleep", called, name)

    def test_a_missing_profile_folder_is_made_and_a_window_opened_when_none_is(self):
        missing = self.tmp / "new" / "profile"
        window = LoginWindow(windows=0, closes_at=(1,))
        code, out, _, calls = self.run_main(["--login"], window, profile=missing)
        self.assertEqual(code, 0)
        self.assertTrue(missing.is_dir())
        self.assertEqual(profile_files(missing), [], "only the folder is made")
        self.assertEqual((calls[0]["user_data_dir"], window.new_pages, window.page.gotos), (str(missing), 1, [("https://accounts.google.com/", "domcontentloaded")]))
        self.assertEqual(out.splitlines()[-1], OLD_DONE)

    def test_a_missing_camoufox_or_a_browser_error_prints_one_fixed_line(self):
        out = io.StringIO()
        with mock.patch.dict(sys.modules, {"camoufox": None, "camoufox.sync_api": None}), contextlib.redirect_stdout(out):
            self.assertEqual(fb.login(profile=self.profile), 1)
        self.assertEqual(out.getvalue().splitlines()[-1], "not opened (camoufox not installed in this Python; run it with the holder-tools Python)")
        out = io.StringIO()
        with fake_camoufox(enter_error=RuntimeError(f"goto failed at https://accounts.google.com/o/oauth2?code={FAKE_JWT}")), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(fb.login(profile=self.profile), 1)
        self.assertEqual((out.getvalue().splitlines()[-1], err.getvalue()), (fb.LOGIN_FAILED, ""))
        self.assertNotIn(FAKE_JWT, out.getvalue())
        lock = self.profile / ".parentlock"
        lock.write_bytes(b"")
        state = {"held": None}

        class Racing(Launcher):
            def __enter__(inner):
                state["held"] = lock_held(lock)
                state["held"].__enter__()
                raise RuntimeError("browser exited: profile already in use")

        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                code = fb.login(profile=self.profile, launcher=lambda profile: Racing()(profile, 0))
        finally:
            state["held"].__exit__(None, None, None)
        self.assertEqual((code, out.getvalue().splitlines()[-1]), (3, fb.LOGIN_IN_USE))

    def test_bad_arguments_exit_2_and_open_nothing(self):
        for argv in (["--login", BTC], ["--login", "--out", str(self.run_dir)], ["--login", "--check-login"], ["--start", "fomo"],
                     ["--check-login", "--start", "google"], [BTC, "--out", str(self.run_dir), "--start", "fomo"]):
            with self.subTest(argv):
                code, out, err, calls = self.run_main(argv)
                self.assertEqual((code, out, calls), (2, "", []))
                self.assertTrue(err.startswith("error: "), err)
        with self.assertRaises(SystemExit) as raised, contextlib.redirect_stderr(io.StringIO()):
            fb.main(["--login", "--start", "accounts"])
        self.assertEqual(raised.exception.code, 2)

    def test_the_scan_and_check_login_never_reach_the_login_window(self):
        self.api_file("ok")
        with mock.patch.object(fb, "login", side_effect=AssertionError("login reached")), mock.patch.object(fb, "login_launcher", refuse_launch):
            code, out, _, _ = self.run_main([BTC, "--out", str(self.run_dir)])
            self.assertEqual((code, out), (0, "not needed (Fomo API read ok; no browser launched)\n"))
            page = signed_in_page(Clock())
            words = fb.check_login(self.profile, launcher=Launcher(page), clock=page.clock)
            self.assertEqual(words, ("logged in", 0))
        self.assertIn("headless=True", (SCRIPTS / "fomo_browser.py").read_text(encoding="utf-8").split("def camoufox_launcher", 1)[1].split("\ndef ", 1)[0],
                      "the scan's launcher stays headless")

    def test_the_printed_login_command_is_the_new_one_and_the_old_script_is_never_printed(self):
        self.assertEqual(ft.LOGIN_COMMAND, LOGIN_COMMAND)
        repo = SCRIPTS.parents[2]
        self.assertTrue(LOGIN_COMMAND.endswith(f"{(SCRIPTS / 'fomo_browser.py').relative_to(repo).as_posix()} --login"))
        self.assertTrue(LOGIN_COMMAND.startswith("\"${HOLDER_PYTHON:-python3}\" -I "), "the Python that has Camoufox, isolated")
        self.api_file()
        res, _ = self.collect(logged_out_page(Clock()))
        printed = [fb.status_line(res), *ft.present(self.save(res))]
        self.assertIn(f"  {LOGIN_COMMAND}", printed)
        for line in printed:
            self.assertNotIn(OLD_LOGIN_SCRIPT, line)
            self.assertNotIn("lp-research-companion", line)
            self.assertNotIn("<repo>/.venv/", line)


if __name__ == "__main__":
    unittest.main()
