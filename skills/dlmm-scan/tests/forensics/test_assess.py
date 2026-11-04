"""HS-ASSESS-T1: the offline `assess` subcommand (no network, no key, 0 credits).

Every collector of a holder scan starts in the first wave. The forensics collector only collects (`funders`), and the
synthesis runs `assess` over the saved run folder plus the files the other collectors saved. These tests prove:
(1) `funders` then `assess` writes byte-identical assessment.json and report.md to one `report` run with the same inputs
    (only the two documented time/credit lines of report.md differ), for CAPE-style, VEIL-style, a negative control,
    runs that stopped early (credit cap, consecutive failures, Ctrl-C) and every optional input; and `assess` over a copy
    of a `report` run's own saved files reproduces that run's files exactly;
(2) `assess` makes no network call and needs no key (sockets blocked, HELIUS_API_KEY unset, every client refused);
(3) a missing, older, mismatched or edited run folder is refused with exit 2 and a plain reason, never guessed.
Offline: fakes only, frozen clock, dummy key. `equivalence()` and `CASES` are also used by the HS-ASSESS-T1 evidence
harness."""

from __future__ import annotations

import contextlib
import copy
import csv
import datetime as dt
import io
import json
import os
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
import solscanner_scan as ss  # noqa: E402
from test_holder_forensics import MINT, NO_KEY_ENV, SECRET, addr  # noqa: E402
from test_parallel_rows import ParallelFake, funder_addr  # noqa: E402
from test_parallel_rows import scenario as tie_scenario  # noqa: E402
from test_solscanner_scan import CAPE, SPACE, Opener, Response, stream  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
UTC = dt.timezone.utc
FROZEN = dt.datetime(2026, 10, 14, 10, 5, tzinfo=UTC)  # the SolScanner CAPE fixture was read at this time
FROZEN_TS = FROZEN.timestamp()
INPUT_AGE_S = 60  # every saved input file is one minute old when it is read
CAPE_LAUNCH = 1_791_968_640  # 2026-10-14 09:04:00 UTC
CREDIT_NOTE = " (as recorded by the collector run in its saved files; this offline assess step used 0)"
# The only report.md lines allowed to differ between `report` and `funders` + `assess` (documented in SKILL.md).
DOCUMENTED_LINES = (
    re.compile(r"^Generated \S+ - Helius credits used: \d+(?:" + re.escape(CREDIT_NOTE) + r")?$"),
    re.compile(r"^- Data ages: Helius holder list and funded-by: (?:collected at report time|collected by the collector run, files saved \d{4}-\d{2}-\d{2} \d{2}:\d{2} UTC)$"),
)
REASSURING_WORDS = re.compile(r"\b(clean|low|safe|NONE)\b")  # test_verdict_gating's rule, plus "safe"


class FrozenDatetime(dt.datetime):
    @classmethod
    def now(cls, tz=None):
        return FROZEN.astimezone(tz) if tz else FROZEN.replace(tzinfo=None)


@contextlib.contextmanager
def frozen_clock():
    """Every clock the engines read (time.time for file and token ages, datetime.now for report times and the SolScanner
    age) is frozen, so two runs of the same data are repeatable."""
    with mock.patch.object(hf, "dt", types.SimpleNamespace(datetime=FrozenDatetime, timezone=dt.timezone)), \
         mock.patch.object(hf.time, "time", return_value=FROZEN_TS), mock.patch.object(ss, "utc_now", return_value=FROZEN):
        yield


class Refused(AssertionError):
    pass


@contextlib.contextmanager
def no_network_no_key(calls: list | None = None):
    """No socket can connect or resolve, HELIUS_API_KEY is not set, and every network client and key reader refuses."""
    calls = [] if calls is None else calls

    def refuse(*_a, **_k):
        calls.append("refused")
        raise Refused("network or key access during assess")

    env = {k: v for k, v in NO_KEY_ENV.items() if k not in ("HELIUS_API_KEY", "HOLDER_FORENSICS_ENV")}
    with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(socket.socket, "connect", refuse), \
         mock.patch.object(socket, "create_connection", refuse), mock.patch.object(socket, "getaddrinfo", refuse), \
         mock.patch.object(hf, "Helius", side_effect=refuse), mock.patch.object(hf, "dexscreener_pairs", side_effect=refuse), \
         mock.patch.object(hf, "find_env_file", side_effect=refuse), mock.patch.object(hf, "load_key", side_effect=refuse), \
         mock.patch.object(ss, "collect_solscanner", side_effect=refuse):
        yield calls


class Case:
    """One scan: what the fake Helius holds, the Dexscreener pairs, and the saved input files of the other sources."""

    def __init__(self, name, mint, accounts, funded, *, top, pairs=(), fail=(), inputs=None, collector_args=(), workers=6,
                 max_credits=10**9, interrupt_at=None, live_solscanner=None, expect_exit=0, about=""):
        self.name, self.mint, self.accounts, self.funded, self.top = name, mint, accounts, funded, top
        self.pairs, self.fail, self.inputs, self.collector_args, self.workers = list(pairs), set(fail), dict(inputs or {}), list(collector_args), workers
        self.max_credits, self.interrupt_at, self.live_solscanner, self.expect_exit, self.about = max_credits, interrupt_at, live_solscanner, expect_exit, about

    def fake(self):
        def on_call(n):
            if self.interrupt_at is not None and n == self.interrupt_at:
                raise KeyboardInterrupt

        return ParallelFake(self.accounts, self.funded, fail=self.fail, max_credits=self.max_credits, on_call=on_call)


def _run(argv, *, fake=None, pairs=(), solscanner_result=None):
    """hf.main with a fake Helius client, fixed Dexscreener pairs, a dummy key and the frozen clock."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.ExitStack() as stack:
        stack.enter_context(mock.patch.dict(os.environ, {**NO_KEY_ENV, "HELIUS_API_KEY": SECRET}, clear=True))
        stack.enter_context(mock.patch.object(hf, "Helius", return_value=fake))
        stack.enter_context(mock.patch.object(hf, "dexscreener_pairs", return_value=(list(pairs), True)))
        if solscanner_result is not None:
            stack.enter_context(mock.patch.object(ss, "collect_solscanner", return_value=copy.deepcopy(solscanner_result)))
        stack.enter_context(frozen_clock())
        stack.enter_context(contextlib.redirect_stdout(out))
        stack.enter_context(contextlib.redirect_stderr(err))
        code = hf.main(argv)
    return code, out.getvalue(), err.getvalue()


def run_assess(mint, run_dir, extra=(), out=None, calls=None):
    """`assess` with sockets blocked, no key and every client refused, on the frozen clock."""
    argv = ["assess", mint, "--from", str(run_dir), *extra] + (["--out", str(out)] if out else [])
    o, e = io.StringIO(), io.StringIO()
    with no_network_no_key(calls), frozen_clock(), contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        code = hf.main(argv)
    return code, o.getvalue(), e.getvalue()


def solscanner_cli(mint, out_path, result):
    o, e = io.StringIO(), io.StringIO()
    with mock.patch.object(ss, "collect_solscanner", return_value=copy.deepcopy(result)) as call, contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        code = ss.main([mint, "--out", str(out_path)])
    call.assert_called_once_with(mint)
    return code, o.getvalue()


def write_inputs(case, folder: Path) -> list[str]:
    argv = []
    for flag, payload in case.inputs.items():
        p = folder / (flag.strip("-") + ".json")
        p.write_text(json.dumps(payload))
        os.utime(p, (FROZEN_TS - INPUT_AGE_S, FROZEN_TS - INPUT_AGE_S))
        argv += [flag, str(p)]
    return argv


def report_differences(a: str, b: str) -> list[tuple[str, str]]:
    la, lb = a.splitlines(), b.splitlines()
    if len(la) != len(lb):
        return [("<line count>", f"{len(la)} vs {len(lb)}")]
    return [(x, y) for x, y in zip(la, lb) if x != y]


def undocumented(diffs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(x, y) for x, y in diffs if not any(p.match(x) and p.match(y) for p in DOCUMENTED_LINES)]


def credits_in(report: str) -> int | None:
    m = re.search(r"^Generated \S+ - Helius credits used: (\d+)", report, re.M)
    return int(m.group(1)) if m else None


def _files(folder: Path) -> dict[str, str]:
    return {n: (folder / n).read_text() for n in ("assessment.json", "report.md") if (folder / n).exists()}


def equivalence(case: Case, keep_dir: Path | None = None) -> dict:
    """Run one case three ways and return everything needed to compare them:
    A  one `report` run with every input (the old single collector);
    B  the new flow: `funders` (collect only, no inputs; the SolScanner CLI too when the case reads SolScanner live), then
       `assess` over its run folder with the same inputs, under no_network_no_key;
    C  `assess` over a copy of A's own saved holders.json / funders.json with the same inputs (pure rebuild check).
    keep_dir (evidence harness only): copy every folder of the three runs there before the scratch folder is removed."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        (tmp / "inputs").mkdir()
        inputs = write_inputs(case, tmp / "inputs")
        base = ["--top", str(case.top), "--workers", str(case.workers), *case.collector_args]
        a_dir, b_dir, c_src, c_out = tmp / "report", tmp / "run", tmp / "copy", tmp / "copy-out"
        live = ["--solscanner"] if case.live_solscanner is not None else []
        code_a, out_a, _ = _run(["report", case.mint, *base, "--out", str(a_dir), *inputs, *live], fake=case.fake(), pairs=case.pairs, solscanner_result=case.live_solscanner)
        code_b, _, _ = _run(["funders", case.mint, *base, "--out", str(b_dir)], fake=case.fake(), pairs=case.pairs)
        b_inputs, ss_line = list(inputs), None
        if case.live_solscanner is not None:
            ss_code, ss_line = solscanner_cli(case.mint, b_dir / "solscanner.json", case.live_solscanner)
            assert ss_code == 0
            b_inputs += ["--solscanner-json", str(b_dir / "solscanner.json")]
        calls: list = []
        code_s, out_s, err_s = run_assess(case.mint, b_dir, b_inputs, calls=calls)
        c_src.mkdir()
        for name in ("holders.json", "funders.json"):
            if (a_dir / name).exists():
                shutil.copy2(a_dir / name, c_src / name)
        c_inputs = list(inputs)
        if case.live_solscanner is not None:
            (c_src / "solscanner.json").write_text(json.dumps(case.live_solscanner))
            c_inputs += ["--solscanner-json", str(c_src / "solscanner.json")]
        code_c, _, _ = run_assess(case.mint, c_src, c_inputs, out=c_out, calls=calls)
        fa, fb, fc = _files(a_dir), _files(b_dir), _files(c_out)
        if keep_dir is not None:
            shutil.copytree(tmp, keep_dir, dirs_exist_ok=True)
        assessment = json.loads(fa["assessment.json"]) if "assessment.json" in fa else {}
        return {
            "case": case.name, "about": case.about, "exit_report": code_a, "exit_funders": code_b, "exit_assess": code_s, "exit_assess_copy": code_c,
            "refused_calls": len(calls), "funders_json": (a_dir / "funders.json").exists(), "solscanner_cli": ss_line,
            "report_files": fa, "assess_files": fb, "copy_files": fc, "report_stdout": out_a, "assess_stdout": out_s, "assess_stderr": err_s,
            "verdict": (assessment.get("verdict") or {}).get("level"), "flag": (assessment.get("flag") or {}).get("label"),
            "assessment_identical": fa.get("assessment.json") is not None and fa.get("assessment.json") == fb.get("assessment.json"),
            "assessment_identical_copy": fa.get("assessment.json") is not None and fa.get("assessment.json") == fc.get("assessment.json"),
            "report_diffs": report_differences(fa.get("report.md", ""), fb.get("report.md", "")),
            "report_diffs_copy": report_differences(fa.get("report.md", ""), fc.get("report.md", "")),
            "credits_report": credits_in(fa.get("report.md", "")), "credits_assess": credits_in(fb.get("report.md", "")),
        }


# ----------------------------------------------------------------------------- scenarios

def _cape_rows():
    with (FIX / "cape_cohort_fixture.csv").open(newline="") as fh:
        return list(csv.DictReader(fh))


def _unix(text: str) -> int:
    return int(dt.datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC).timestamp())


def _map(mint, clusters, age=0.0):
    return {"mint": mint, "age_min_after": age, "clusters": [{"cluster": i, "wallets": w, "supply_pct": p} for i, (w, p) in enumerate(clusters, 1)],
            "parse_ok": True, "refresh_effective": True}


def _solscanner_result(name, mint):
    return ss.collect_solscanner(mint, opener=Opener(Response(stream(name))), now=lambda: FROZEN)


def cape_holdings():
    """The CAPE funding fixture as a Helius holder list: 88 wallets (the 50-wallet farm C2, a 30-wallet sample of cluster 1,
    an 8-wallet cluster 3) with their real first funders (six labeled exchanges/services) and a 30% pool."""
    pool = addr(901)
    accounts = [{"owner": pool, "amount": 3.0e8}]
    funded: dict = {}
    for r in _cape_rows():
        accounts.append({"owner": r["wallet"], "amount": float(r["supply_pct_bubblemaps"]) * 1e7})
        label = r["first_funder_label"] if r["first_funder_label"] not in ("", "unlabeled") else None
        funded[r["wallet"]] = {"funder": r["first_funder"], "funderName": label, "funderType": "Centralized Exchange" if label else None,
                               "timestamp": _unix(r["first_funded_utc"]), "amount": float(r["first_funding_sol"])}
    return pool, accounts, funded


def case_cape_all_inputs():
    pool, accounts, funded = cape_holdings()
    gmgn = json.loads((FIX / "cape_gmgn.json").read_text())
    acquisition = {r["wallet"]: r["first_acquired_at"] for r in hf.gmgn_cohort_rows(gmgn)[:60] if r["first_acquired_at"]}
    providers = {"unit": "percent", "providers": [
        {"provider": "okx", "status": "ok", "largest_cluster_pct": 4.0, "bundle_pct": 1.0, "data_age_min": 3.0, "alarm_hint": "same fund source 0.947 vs Low headline"},
        {"provider": "insightx", "status": "empty", "detail": "0 percent clusters with an empty list"},
    ]}
    return Case("cape_all_inputs", CAPE, accounts, funded, top=100, pairs=[{"pairAddress": pool, "pairCreatedAt": CAPE_LAUNCH * 1000}],
                inputs={"--bubblemaps-json": _map(CAPE, [(115, 25.45), (50, 17.44)]), "--providers-json": providers, "--acquisition-json": acquisition,
                        "--gmgn-holders-json": gmgn, "--jupiter-holders-json": json.loads((FIX / "cape_jupiter.json").read_text()),
                        "--solscanner-json": _solscanner_result("cape", CAPE)},
                about="CAPE funding fixture (88 wallets, six labeled exchange funders), Bubblemaps 25%/17% clusters, real GMGN and Jupiter top-100 rows, acquisition times, two --providers-json findings, saved SolScanner result")


def case_cape_rows_below_top():
    """--top 20: most GMGN / Jupiter row wallets rank below the funded-by window, so their exact supply share must come
    from the full Helius balances saved in holders.json (owner_balances), not from the rounded top_holders shares."""
    pool, accounts, funded = cape_holdings()
    gmgn = json.loads((FIX / "cape_gmgn.json").read_text())
    return Case("cape_rows_below_top", CAPE, accounts, funded, top=20, pairs=[{"pairAddress": pool, "pairCreatedAt": CAPE_LAUNCH * 1000}],
                inputs={"--gmgn-holders-json": gmgn, "--jupiter-holders-json": json.loads((FIX / "cape_jupiter.json").read_text())},
                about="CAPE with --top 20 and GMGN/Jupiter rows: provider-row wallets below the funded-by window take their exact Helius share (owner_balances)")


def case_cape_live_solscanner():
    pool, accounts, funded = cape_holdings()
    return Case("cape_live_solscanner", CAPE, accounts, funded, top=100, pairs=[{"pairAddress": pool, "pairCreatedAt": CAPE_LAUNCH * 1000}],
                inputs={"--bubblemaps-json": _map(CAPE, [(115, 25.45), (50, 17.44)])}, live_solscanner=_solscanner_result("cape", CAPE),
                about="CAPE with the map; SolScanner read live inside `report --solscanner` versus the new solscanner collector (solscanner_scan.py) + `assess --solscanner-json`")


def veil_holdings(labeled: bool):
    """VEIL style: 230 wallets in 12 scripted rounds about 2 minutes apart, 2-3 SOL each, bought the same second; the 12
    round funders were funded a week earlier by five exchanges. labeled=True funds the wallets straight from a labeled
    exchange instead (the known limit: the funder-batch detector ignores labeled funders)."""
    rng = random.Random(3)
    start = int(FROZEN_TS) - 3 * 3600
    launch = start - 6
    pool = addr(950)
    accounts = [{"owner": pool, "amount": 35_600.0}]
    funded, acquisition, n = {}, {}, 0
    exchanges = ["Binance Hot Wallet 2", "KuCoin Hot Wallet 2", "Gate Hot Wallet", "Bybit Hot Wallet 10", "OKX Hot Wallet"]
    for r in range(12):
        f = funder_addr("V" + "ABCDEFGHJKLM"[r])
        funded[f] = {"funder": funder_addr("X" + "ABCDE"[r % 5]), "funderName": exchanges[r % 5], "funderType": "Centralized Exchange", "timestamp": launch - 7 * 86_400 + r * 3600, "amount": 50.0 + r}
        for w in range(19 if r < 11 else 21):
            wallet, t = addr(n), start + r * 118 + w * 5
            accounts.append({"owner": wallet, "amount": 280.0})
            funded[wallet] = {"funder": f, "timestamp": t, "amount": round(rng.uniform(2.0, 3.0), 3)}
            if labeled:
                funded[wallet] |= {"funderName": exchanges[r % 5], "funderType": "Centralized Exchange"}
            acquisition[wallet] = t
            n += 1
    return pool, launch, accounts, funded, acquisition


def case_veil(labeled=False):
    pool, launch, accounts, funded, acquisition = veil_holdings(labeled)
    name = "veil_labeled_exchanges" if labeled else "veil_unlabeled_funders"
    about = ("VEIL style funded straight from labeled exchanges (known limit: cohort one sign only, funder-batch blind), quiet fresh map, acquisition times"
             if labeled else "VEIL style (230 wallets, 12 unlabeled round funders 118 s apart, upstream exchanges), quiet fresh map, acquisition times")
    # --funders-top 250 (DS-HELIUS-BUDGET-T1): these cases need funded-by on all 230 wallets; the default is the top 100 since 2026-10-28
    return Case(name, MINT, accounts, funded, top=250, pairs=[{"pairAddress": pool, "pairCreatedAt": launch * 1000}],
                inputs={"--bubblemaps-json": _map(MINT, [(4, 2.0)], age=2.0), "--acquisition-json": acquisition}, collector_args=["--funders-top", "250"], about=about)


def case_negative_space_inu():
    """Negative control: the real Space Inu GMGN / Jupiter top-100 rows and Bubblemaps map; Helius holds the same 100
    wallets plus 150 small ones, each funded by its own funder over 200 days. The largest wallet is excluded as a
    treasury with --exclude on the collector."""
    rng = random.Random(17)
    jup = json.loads((FIX / "space_inu_jupiter.json").read_text())
    pool = addr(960)
    accounts = [{"owner": pool, "amount": 2.0e8}]
    wallets = [r["address"] for r in hf._unwrap(jup)]
    accounts += [{"owner": r["address"], "amount": float(r["amount"])} for r in hf._unwrap(jup)]
    small = [addr(500 + i) for i in range(150)]
    accounts += [{"owner": w, "amount": 1000.0} for w in small]
    funded = {}
    for i, w in enumerate(wallets + small):
        funded[w] = {"funder": funder_addr(f"N{i}"), "funderName": "Binance Hot Wallet 2" if i % 3 == 0 else None, "timestamp": int(FROZEN_TS) - rng.randrange(40, 240) * 86_400 + rng.randrange(86_400),
                     "amount": round(rng.uniform(0.05, 20.0), 3)}
    treasury = max(hf._unwrap(jup), key=lambda r: float(r["amount"]))["address"]
    return Case("negative_space_inu", SPACE, accounts, funded, top=250, pairs=[{"pairAddress": pool, "pairCreatedAt": (int(FROZEN_TS) - 30 * 86_400) * 1000}],
                collector_args=["--exclude", treasury],
                inputs={"--bubblemaps-json": json.loads((FIX / "space_inu_bubblemaps.json").read_text()), "--gmgn-holders-json": json.loads((FIX / "space_inu_gmgn.json").read_text()),
                        "--jupiter-holders-json": jup},
                about="negative control: real Space Inu GMGN/Jupiter rows and map, independent funding over 200 days, treasury excluded with --exclude")


def case_stopped_credit_cap():
    pool, accounts, funded, fail = tie_scenario()
    return Case("stopped_credit_cap", MINT, accounts, funded, top=70, pairs=[{"pairAddress": pool}], fail=fail, workers=1, max_credits=30 * hf.COST_FUNDED_BY,
                inputs={"--bubblemaps-json": _map(MINT, [(40, 22.0), (9, 6.5)], age=4.0)}, expect_exit=4,
                about="run stopped by the credit cap after 30 funded-by lookups (exit 4, RUN STOPPED EARLY), Bubblemaps 22% cluster")


def case_stopped_failures():
    accounts = [{"owner": addr(i), "amount": 100.0 - i} for i in range(40)]
    funded = {addr(i): {"funder": funder_addr("Z"), "timestamp": 1_700_000_000 + i} for i in range(4)}
    providers = [{"provider": "gmgn", "status": "ok", "largest_cluster_pct": 3.0, "bundle_pct": 0.7, "data_age_min": 2.0, "unit": "percent"}]
    return Case("stopped_failures", MINT, accounts, funded, top=40, fail={addr(i) for i in range(4, 40)}, workers=1,
                inputs={"--bubblemaps-json": _map(MINT, [(5, 3.0)], age=1.0), "--providers-json": providers},
                about="run stopped by 5 consecutive funded-by failures (partial), quiet map, calm GMGN finding")


def case_interrupted():
    pool, accounts, funded, fail = tie_scenario()
    return Case("interrupted_ctrl_c", MINT, accounts, funded, top=70, pairs=[{"pairAddress": pool}], fail=fail, workers=1, interrupt_at=12,
                inputs={"--bubblemaps-json": _map(MINT, [(40, 22.0)], age=4.0)}, expect_exit=130,
                about="collector interrupted (Ctrl-C, exit 130) during funded-by: only the holder-list checkpoint was saved, no funders.json")


def case_tie_parallel():
    pool, accounts, funded, fail = tie_scenario()
    jup = {"holders": [{"address": addr(i), "amount": 100 - (i // 10), "addressInfo": {"fundingAddress": funder_addr("A" if (i % 10) < 5 else "B"), "fundingAmount": 2.5,
                                                                                         "fundingBlockTime": 1_700_000_000 + i * 5}} for i in range(20)]}
    return Case("tie_six_workers", MINT, accounts, funded, top=70, pairs=[{"pairAddress": pool}], fail=fail, workers=6,
                inputs={"--bubblemaps-json": _map(MINT, [(12, 9.0)], age=3.0), "--jupiter-holders-json": jup},
                about="HF-T1 tie scenario with 6 workers (tied batches, failures, no-record wallets, upstream trace), quiet map, Jupiter rows")


CASES = [case_cape_all_inputs, case_cape_rows_below_top, case_cape_live_solscanner, lambda: case_veil(False), lambda: case_veil(True), case_negative_space_inu,
         case_stopped_credit_cap, case_stopped_failures, case_interrupted, case_tie_parallel]


# ----------------------------------------------------------------------------- tests

class EquivalenceTests(unittest.TestCase):
    """funders + assess == report, for every scenario (assessment.json byte-identical; report.md identical apart from
    the documented Generated/credits line and the Helius data-age line)."""

    @classmethod
    def setUpClass(cls):
        cls.results = {}
        for make in CASES:
            case = make()
            cls.results[case.name] = (case, equivalence(case))

    def test_every_scenario_is_identical(self):
        for name, (case, r) in self.results.items():
            with self.subTest(name):
                self.assertEqual(r["exit_report"], case.expect_exit)
                self.assertEqual(r["exit_funders"], case.expect_exit)
                self.assertEqual(r["exit_assess"], 0, r["assess_stderr"])
                self.assertEqual(r["exit_assess_copy"], 0)
                self.assertEqual(r["refused_calls"], 0, "assess tried the network or a key")
                self.assertTrue(r["assessment_identical"], "assessment.json differs between report and funders + assess")
                self.assertTrue(r["assessment_identical_copy"], "assessment.json differs between report and assess over its own files")
                self.assertEqual(undocumented(r["report_diffs"]), [])
                self.assertEqual(undocumented(r["report_diffs_copy"]), [])
                self.assertEqual(len(r["report_diffs"]), 2)  # exactly the two documented lines
                self.assertEqual(r["credits_assess"], r["credits_report"])

    def test_assess_report_states_the_credits_truthfully(self):
        for name, (_, r) in self.results.items():
            with self.subTest(name):
                self.assertIn(CREDIT_NOTE, r["assess_files"]["report.md"])
                self.assertNotIn(CREDIT_NOTE, r["report_files"]["report.md"])
                self.assertIn("collected by the collector run, files saved", r["assess_files"]["report.md"])
                self.assertIn("0 Helius credits", r["assess_stderr"])

    def test_the_scenarios_cover_what_the_ticket_names(self):
        got = {n: (r["verdict"], r["flag"]) for n, (_, r) in self.results.items()}
        self.assertEqual(got["cape_all_inputs"], (hf.VERDICT_HIGH, hf.FLAG_DANGER))
        self.assertEqual(got["veil_unlabeled_funders"][0], hf.VERDICT_HIGH)
        self.assertEqual(got["veil_labeled_exchanges"][0], hf.VERDICT_UNRESOLVED)
        self.assertNotIn(got["negative_space_inu"][0], (hf.VERDICT_HIGH, hf.VERDICT_UNRESOLVED))
        self.assertIn("RUN STOPPED EARLY: credit budget reached", self.results["stopped_credit_cap"][1]["assess_files"]["report.md"])
        self.assertIn("RUN STOPPED EARLY: 5 consecutive failures", self.results["stopped_failures"][1]["assess_files"]["report.md"])
        self.assertFalse(self.results["interrupted_ctrl_c"][1]["funders_json"])
        self.assertIn("funding lookups: not run", self.results["interrupted_ctrl_c"][1]["assess_files"]["report.md"])
        self.assertIn("no funders.json", self.results["interrupted_ctrl_c"][1]["assess_stderr"])
        cape = json.loads(self.results["cape_all_inputs"][1]["assess_files"]["assessment.json"])
        keys = {s["key"]: s["status"] for s in cape["sources"]}
        self.assertEqual({k: keys[k] for k in ("bubblemaps_map", "solscanner", "gmgn", "jupiter", "okx", "insightx")},
                         {"bubblemaps_map": "read", "solscanner": "read", "gmgn": "read", "jupiter": "read", "okx": "read", "insightx": "empty"})
        self.assertTrue(json.loads(self.results["cape_all_inputs"][1]["assess_files"]["assessment.json"]))
        live = self.results["cape_live_solscanner"][1]
        self.assertTrue(live["solscanner_cli"].startswith("ok (1 bundle group"))
        self.assertIn("SolScanner public scan: read", live["assess_files"]["report.md"])

    def test_no_reassuring_words_in_any_assess_report(self):
        for name, (_, r) in self.results.items():
            with self.subTest(name):
                self.assertIsNone(REASSURING_WORDS.search(r["assess_files"]["report.md"]))
                self.assertNotIn(SECRET, r["assess_files"]["report.md"] + r["assess_files"]["assessment.json"] + r["assess_stdout"] + r["assess_stderr"])

    def test_assess_prints_the_report_like_report_does(self):
        r = self.results["veil_unlabeled_funders"][1]
        self.assertEqual(undocumented(report_differences(r["report_stdout"], r["assess_stdout"])), [])


def _saved_run(case=None):
    """A collector run folder (funders) plus the case, for the refusal tests."""
    case = case or case_stopped_failures()
    tmp = Path(tempfile.mkdtemp())
    code, _, _ = _run(["funders", case.mint, "--top", str(case.top), "--workers", "1", "--out", str(tmp)], fake=case.fake(), pairs=case.pairs)
    assert code == case.expect_exit
    return case, tmp


class NoNetworkNoKeyTests(unittest.TestCase):
    def test_assess_runs_with_every_socket_blocked_and_no_key(self):
        case, run = _saved_run(case_veil(False))
        try:
            calls: list = []
            with no_network_no_key():
                self.assertNotIn("HELIUS_API_KEY", os.environ)
                with self.assertRaises(Refused):
                    socket.create_connection(("api.helius.xyz", 443))
            code, out, err = run_assess(case.mint, run, calls=calls)
            self.assertEqual(code, 0, err)
            self.assertEqual(calls, [])
            self.assertTrue((run / "assessment.json").exists())
            self.assertIn(CREDIT_NOTE, (run / "report.md").read_text())
        finally:
            shutil.rmtree(run)

    def test_assess_in_a_separate_process_with_sockets_blocked_and_no_key(self):
        """End to end through the real command line: `python3 -I helius_forensics.py assess`, in a fresh process whose
        socket module refuses every connection and name lookup, with HELIUS_API_KEY absent and the .env finder and key
        loader replaced by functions that fail the run if they are ever called."""
        case, run = _saved_run(case_veil(False))
        driver = textwrap.dedent(
            """
            import socket, sys
            def refuse(*a, **k):
                raise SystemExit("network access attempted")
            socket.socket.connect = refuse
            socket.socket.connect_ex = refuse
            socket.create_connection = refuse
            socket.getaddrinfo = refuse
            sys.path.insert(0, sys.argv[1])
            import helius_forensics as hf
            hf.find_env_file = hf.load_key = refuse
            sys.exit(hf.main(["assess", sys.argv[2], "--from", sys.argv[3]]))
            """
        )
        env = {k: v for k, v in NO_KEY_ENV.items() if k not in ("HELIUS_API_KEY", "HOLDER_FORENSICS_ENV")}
        try:
            proc = subprocess.run([sys.executable, "-I", "-c", driver, str(SCRIPTS), case.mint, str(run)], capture_output=True, text=True, env=env, timeout=120)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertNotIn("network access attempted", proc.stdout + proc.stderr)
            self.assertIn("0 Helius credits", proc.stderr)
            self.assertIn(CREDIT_NOTE, (run / "report.md").read_text())
        finally:
            shutil.rmtree(run)

    def test_assess_offers_no_live_or_spending_flag(self):
        for flag in (["--solscanner"], ["--workers", "6"], ["--top", "250"], ["--max-credits", "5"], ["--env-file", "x"], ["--exclude", addr(1)]):
            with self.subTest(flag[0]), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
                hf.main(["assess", MINT, "--from", "x", *flag])
            self.assertEqual(ctx.exception.code, 2)

    def test_from_is_required(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as ctx:
            hf.main(["assess", MINT])
        self.assertEqual(ctx.exception.code, 2)


class RefusalTests(unittest.TestCase):
    """Missing, older, mismatched or edited run folders exit 2 with one plain line; nothing is written."""

    def setUp(self):
        self.case, self.run = _saved_run()
        self.before = (self.run / "report.md").read_text()

    def tearDown(self):
        shutil.rmtree(self.run, ignore_errors=True)

    def edit(self, name, change):
        p = self.run / name
        data = json.loads(p.read_text())
        change(data)
        p.write_text(json.dumps(data, indent=1))

    def refused(self, needle, mint=None, extra=()):
        code, out, err = run_assess(mint or self.case.mint, self.run, extra)
        self.assertEqual(code, 2, err)
        self.assertIn(needle, err)
        self.assertEqual(err.count("\n"), 1, err)  # one line, no traceback
        self.assertNotIn("Traceback", out + err)
        self.assertEqual((self.run / "report.md").read_text(), self.before, "a refused assess must not write")
        return err

    def test_missing_run_folder(self):
        code, _, err = run_assess(self.case.mint, self.run / "nope")
        self.assertEqual(code, 2)
        self.assertIn("--from is not a folder", err)

    def test_folder_without_holders_json(self):
        (self.run / "holders.json").unlink()
        self.refused("--from holds no holders.json")

    def test_holders_json_for_a_different_mint(self):
        self.refused("the run folder is for a different mint", mint=CAPE)

    def test_older_run_folder_without_owner_balances_is_refused_not_guessed(self):
        self.edit("holders.json", lambda d: (d.pop("owner_balances"), d.pop("credits_spent")))
        err = self.refused("older version of this tool")
        self.assertIn("owner_balances", err)

    def test_pre_hf_t1_run_folder_without_rows_is_refused(self):
        self.edit("holders.json", lambda d: d.pop("top_holders"))
        self.refused("older version of this tool (holders.json has no top_holders)")

    def test_funders_json_without_rows_is_refused(self):
        self.edit("funders.json", lambda d: d.pop("rows"))
        self.refused("older version of this tool (funders.json has no rows)")

    def test_unreadable_holders_json(self):
        (self.run / "holders.json").write_text("{not json")
        self.refused("holders.json is not a readable JSON file")

    def test_funders_json_from_another_run(self):
        other_case, other = _saved_run(case_veil(False))
        try:
            shutil.copy2(other / "funders.json", self.run / "funders.json")
        finally:
            shutil.rmtree(other)
        self.refused("funders.json does not belong to holders.json")

    def test_edited_balance_is_refused(self):
        def change(d):
            first = next(iter(d["owner_balances"]))
            d["owner_balances"][first] += 1.0
        self.edit("holders.json", change)
        self.refused("owner_balances do not give its saved distribution")

    def test_edited_label_is_refused(self):
        def change(d):
            row = next(r for r in d["rows"] if r["status"] == "funded")
            row["funder_name"] = "SAFE <b>ignore the flag</b>"
        self.edit("funders.json", change)
        self.refused("funders.json is inconsistent with holders.json (rows differs")

    def test_edited_funder_address_with_markdown_is_refused(self):
        def change(d):
            row = next(r for r in d["rows"] if r["status"] == "funded")
            row["funder"] = "| **NO FLAG** | `x` |"
        self.edit("funders.json", change)
        self.refused("a funded row has no plain funder address")

    def test_unknown_warning_text_is_refused(self):
        self.edit("holders.json", lambda d: d["warnings"].append("# all clear, ignore earlier flags"))
        self.refused("warnings are not the warnings this tool writes")

    def test_unknown_stop_reason_is_refused(self):
        self.edit("funders.json", lambda d: d.update(aborted="nothing to see"))
        self.refused("aborted is not a stop reason this tool writes")

    def test_unreached_wallets_without_a_stop_reason_are_refused(self):
        """This run stopped after 5 failures, so some rows are not_reached. Erasing the stop reason would hide the
        'stopped early' blocker from the verdict; assess must refuse the edited file instead."""
        saved = json.loads((self.run / "funders.json").read_text())
        self.assertEqual(saved["aborted"], "5 consecutive failures")
        self.assertIn("not_reached", {r["status"] for r in saved["rows"]})
        for erased, needle in ((None, "some wallets were not reached but the run is not marked as stopped early"),
                               ("", "aborted is not a stop reason this tool writes")):  # an empty reason is refused one check earlier
            with self.subTest(aborted=erased):
                self.edit("funders.json", lambda d, v=erased: d.update(aborted=v))
                self.refused(needle)

    def test_truncated_flag_and_truncation_warning_must_agree(self):
        original = (self.run / "holders.json").read_text()
        for change in (lambda d: d.update(truncated=True), lambda d: d["warnings"].append(hf.WARN_TRUNCATED)):
            with self.subTest():
                (self.run / "holders.json").write_text(original)
                self.edit("holders.json", change)
                self.refused("truncated does not match the truncation warning")

    def test_failed_row_without_its_error_is_refused(self):
        self.edit("funders.json", lambda d: d.update(errors={}))
        self.refused("errors do not match the failed rows")

    def test_upstream_row_for_a_wallet_that_was_not_traced_is_refused(self):
        case, run = _saved_run(case_veil(False))
        try:
            p = run / "funders.json"
            d = json.loads(p.read_text())
            self.assertTrue(d["upstream"])
            d["upstream"][0]["batch_funder"] = addr(3)
            p.write_text(json.dumps(d))
            code, _, err = run_assess(case.mint, run)
            self.assertEqual(code, 2)
            self.assertIn("upstream rows do not match", err)
        finally:
            shutil.rmtree(run)

    def test_bad_input_files_fail_like_report(self):
        bad = self.run / "bad.json"
        bad.write_text(json.dumps([{"provider": "x", "status": "ok", "largest_cluster_pct": 0.3}]))
        for extra, needle in ((["--bubblemaps-json", "/nonexistent/map.json"], "--bubblemaps-json is not a readable JSON file"),
                              (["--providers-json", str(bad)], "--providers-json is ambiguous"),
                              (["--solscanner-json", str(self.run / "holders.json")], "--solscanner-json is not a valid saved SolScanner result"),
                              (["--gmgn-holders-json", str(self.run / "holders.json")], "GMGN holders payload is not empty but holds no holder rows")):
            with self.subTest(extra[0]):
                report_code, _, report_err = _run(["report", self.case.mint, "--top", "1", *extra], fake=self.case.fake())
                self.assertEqual(report_code, 2)
                self.assertIn(needle, report_err)
                err = self.refused(needle, extra=extra)
                self.assertEqual(err, report_err)  # the very same message as report

    def test_inputs_for_another_mint_are_reported_like_report_does(self):
        other_map = self.run / "map.json"
        other_map.write_text(json.dumps(_map(CAPE, [(9, 30.0)])))
        os.utime(other_map, (FROZEN_TS - INPUT_AGE_S, FROZEN_TS - INPUT_AGE_S))
        code, _, err = run_assess(self.case.mint, self.run, ["--bubblemaps-json", str(other_map)])
        self.assertEqual(code, 0, err)
        a = json.loads((self.run / "assessment.json").read_text())
        bm = next(f for f in a["findings"] if f["provider"] == "bubblemaps_map")
        self.assertEqual((bm["status"], bm["detail"]), ("unavailable", "map result is for a different mint"))
        self.assertNotEqual(a["verdict"]["level"], hf.VERDICT_NO_ALARM)


if __name__ == "__main__":
    unittest.main()
