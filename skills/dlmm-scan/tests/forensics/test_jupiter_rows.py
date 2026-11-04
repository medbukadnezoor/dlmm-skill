"""HS-PROV-T1: the `jupiter_rows` collector (one bounded Jupiter datapi read of the top 100 holders, free, no key).
Offline: fake transport, the real Jupiter payloads (CAPE 2026-10-14 and the live CAPE answer of 2026-10-19, Space Inu,
Altai the Tiger).

Covers: reuse of the analysis engine's Jupiter client and the request it builds (host, path, query, no auth header, no
env proxy, no redirects, size and time bounds, the hard wall-clock deadline); the retry cap; the ok / empty / unavailable
paths and the loud field guards; documented fields only and inert tags; the collector file reading exactly like a raw
datapi answer in the forensics adapter and through `assess` (byte-identical); and the alarm-only rule: Jupiter rows can
flag a cohort but never count toward NO_ALARM."""

from __future__ import annotations

import ast
import contextlib
import email.message
import io
import json
import os
import shutil
import socket
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
import jupiter_rows as jr  # noqa: E402
from ha import jupiter as ha_jupiter  # noqa: E402
from ha import transport  # noqa: E402
from test_assess import CAPE_LAUNCH, _map, _run, cape_holdings, case_negative_space_inu, run_assess  # noqa: E402
from test_solscanner_scan import CAPE  # noqa: E402

FIX = Path(__file__).resolve().parent / "fixtures"
NOW = 1_792_400_000  # 2026-10-19
ROW_FIELDS = {"address", "amount", "addressInfo", "tags"}
INFO_FIELDS = {"fundingAddress", "fundingAmount", "fundingBlockTime"}


def fixture(name):
    return json.loads((FIX / f"{name}.json").read_text())


def body_of(payload) -> bytes:
    return json.dumps(payload).encode()


class FakeResponse:
    def __init__(self, body: bytes, status: int = 200):
        self._buf, self.status = io.BytesIO(body), status

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, n=-1):
        return self._buf.read(n)

    def close(self):
        pass


class FakeOpener:
    """Answers in order; records every request (and its timeout). An exception answer is raised."""

    def __init__(self, *answers):
        self.answers, self.requests = list(answers), []

    def open(self, request, timeout=None):
        self.requests.append((request, timeout))
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer


def http_error(code, headers=None):
    msg = email.message.Message()
    for k, v in (headers or {}).items():
        msg[k] = v
    return urllib.error.HTTPError(f"https://{jr.HOST}/v1/holders/{CAPE}", code, "error", msg, io.BytesIO(b""))


@contextlib.contextmanager
def no_sleep(record=None):
    """The transport's retry backoff (a keyword default bound at definition time) records instead of sleeping."""
    sleeps = [] if record is None else record
    with mock.patch.dict(transport.request_json.__kwdefaults__, {"sleep": sleeps.append}):
        yield sleeps


def collect(opener):
    with no_sleep():
        return jr.collect_jupiter_rows(CAPE, opener=opener, now=lambda: NOW)


def run_main(argv, opener):
    out, err = io.StringIO(), io.StringIO()
    with mock.patch.object(jr, "default_opener", return_value=opener), no_sleep(), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = jr.main(argv)
    return code, out.getvalue(), err.getvalue()


class RequestConstructionTests(unittest.TestCase):
    def test_one_get_through_the_analysis_engines_client(self):
        opener = FakeOpener(FakeResponse(body_of(fixture("cape_jupiter_live_20261019"))))
        res = collect(opener)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(len(opener.requests), 1)
        request, timeout = opener.requests[0]
        url = urllib.parse.urlparse(request.full_url)
        self.assertEqual((url.scheme, url.hostname, url.port, url.path), ("https", "datapi.jup.ag", None, f"/v1/holders/{CAPE}"))
        self.assertEqual(dict(urllib.parse.parse_qsl(url.query)), {"limit": "100"})
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual({k.lower() for k in dict(request.header_items())}, {"accept", "user-agent"}, "no key, no auth header")
        self.assertEqual(timeout, int(jr.TIMEOUT_S))
        self.assertEqual(res["request"], {"method": "GET", "host": "datapi.jup.ag", "path": "/v1/holders/<MINT>", "query_fields": ["limit"], "limit": 100,
                                          "auth_header_names": [], "requests_sent": 1, "max_requests": 3})

    def test_it_reuses_the_existing_jupiter_client(self):
        """The analysis engine's client does the request, the shape check and the row normalizing; the collector's
        subclass only remembers the raw answer (to tell text-tag fields apart) and overrides nothing else."""
        self.assertIs(jr.JupiterClient, ha_jupiter.JupiterClient)
        self.assertTrue(issubclass(jr.RawKeepingClient, ha_jupiter.JupiterClient))
        self.assertEqual({k for k in vars(jr.RawKeepingClient) if not (k.startswith("__") and k.endswith("__"))}, {"_get", "raw"})
        self.assertEqual(jr.HOST, ha_jupiter.HOST)
        original = ha_jupiter.JupiterClient.holders
        with mock.patch.object(ha_jupiter.JupiterClient, "holders", autospec=True, side_effect=original) as holders:
            res = collect(FakeOpener(FakeResponse(body_of(fixture("cape_jupiter")))))
        holders.assert_called_once()
        self.assertEqual(res["status"], "ok")

    def test_default_opener_ignores_env_proxies_and_refuses_redirects(self):
        with mock.patch.dict(os.environ, {"https_proxy": "http://proxy.invalid:3128", "HTTPS_PROXY": "http://proxy.invalid:3128"}):
            opener = jr.default_opener()
            plain = urllib.request.build_opener()  # control: urllib's default opener does pick the env proxy up
        self.assertTrue(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies.get("https") for h in plain.handlers))
        self.assertFalse(any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in opener.handlers), "no env proxy in the collector's opener")
        self.assertTrue(any(isinstance(h, jr.NoRedirect) for h in opener.handlers))
        self.assertFalse(any(type(h) is urllib.request.HTTPRedirectHandler for h in opener.handlers))
        self.assertIsNone(jr.NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://elsewhere.example/"))

    def test_only_the_allowlisted_https_host(self):
        for url in ("http://datapi.jup.ag/v1/holders/x", "https://datapi.jup.ag.evil.example/v1/holders/x", "https://user:pw@datapi.jup.ag/v1/holders/x", "https://datapi.jup.ag:8443/v1/holders/x"):
            with self.subTest(url), self.assertRaises(transport.TransportError):
                transport.request_json("GET", url, allowed_hosts={jr.HOST}, opener=FakeOpener())

    def test_redirect_size_and_error_bounds(self):
        cases = [(http_error(302), "redirect_disallowed", 1), (FakeResponse(b"", status=301), "redirect_disallowed", 1), (http_error(401), "auth_failed", 1),
                 (http_error(403), "access_denied", 1), (http_error(404), "not_found", 1), (FakeResponse(b"not json"), "invalid_json", 1),
                 (FakeResponse(body_of({"rows": []})), "holder_list_missing", 1), (FakeResponse(body_of([1, 2])), "holder_list_missing", 1)]
        for answer, reason, sent in cases:
            with self.subTest(reason=reason, answer=type(answer).__name__):
                opener = FakeOpener(answer)
                res = collect(opener)
                self.assertEqual((res["status"], res["reason"], len(opener.requests), res["request"]["requests_sent"]), ("unavailable", reason, sent, sent))
        with mock.patch.dict(transport.request_json.__kwdefaults__, {"max_bytes": 1000}):
            res = collect(FakeOpener(FakeResponse(b"x" * 1001)))
        self.assertEqual(res["reason"], "response_too_large")
        res = collect(FakeOpener(RuntimeError("boom with request text")))
        self.assertEqual(res["reason"], "request_failed", "an unexpected error is a fixed code, never its text")
        self.assertNotIn("boom", json.dumps(res))


class RetryCapTests(unittest.TestCase):
    def test_a_429_is_retried_with_backoff_and_never_more_than_twice(self):
        sleeps = []
        opener = FakeOpener(http_error(429), http_error(429), http_error(429), FakeResponse(body_of(fixture("cape_jupiter"))))
        with no_sleep(sleeps):
            res = jr.collect_jupiter_rows(CAPE, opener=opener, now=lambda: NOW)
        self.assertEqual((res["status"], res["reason"], res["http_status"], res["request"]["requests_sent"]), ("unavailable", "rate_limited", 429, 3))
        self.assertEqual(len(opener.requests), 3, "at most 3 requests per scan")
        self.assertEqual(sleeps, [1.0, 2.0])

    def test_a_transient_failure_then_an_answer_is_ok(self):
        for first in (http_error(429), http_error(503), urllib.error.URLError(OSError("reset"))):
            with self.subTest(type(first).__name__):
                opener = FakeOpener(first, FakeResponse(body_of(fixture("cape_jupiter"))))
                res = collect(opener)
                self.assertEqual((res["status"], res["request"]["requests_sent"]), ("ok", 2))


class StatusAndFileTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_live_cape_answer_is_ok(self):
        code, line, err = run_main([CAPE, "--out", str(self.tmp)], FakeOpener(FakeResponse(body_of(fixture("cape_jupiter_live_20261019")))))
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(line.strip(), "ok (100 rows; 64 with a funding time; tags read; 1 Jupiter request (free, no key))")
        saved = json.loads((self.tmp / jr.OUT_FILE).read_text())
        self.assertEqual((saved["status"], saved["holder_count"], saved["rows_read"], saved["with_funding_time"], saved["with_funder"], saved["tag_fields_present"]),
                         ("ok", 1520, 100, 64, 64, True))
        self.assertEqual(saved["tag_claims"]["tags"], {}, "Jupiter tagged no bundler in CAPE's top 100 on 2026-10-19 (its claim)")
        self.assertIn("claims, not proof", saved["tag_claims"]["note"])
        self.assertEqual(saved["mint"], CAPE)

    def test_empty_holder_list_is_empty_never_no_holders(self):
        code, line, _ = run_main([CAPE, "--out", str(self.tmp)], FakeOpener(FakeResponse(b'{"count": 0, "holders": []}')))
        self.assertEqual(code, 0)
        self.assertTrue(line.startswith("empty (Jupiter returned an empty holder list: unknown, not a reassurance"))
        saved = json.loads((self.tmp / jr.OUT_FILE).read_text())
        self.assertEqual((saved["status"], saved["reason"], saved["holders"]), ("empty", "holder_list_empty", []))

    def test_a_saved_non_ok_file_is_refused_by_assess_never_read_as_no_holders(self):
        for answers in ((FakeResponse(b'{"holders": []}'),), (http_error(500), http_error(500), http_error(500))):
            res = collect(FakeOpener(*answers))
            self.assertNotEqual(res["status"], "ok")
            with self.assertRaises(hf.ConfigError):
                hf.jupiter_cohort_rows(res)

    def test_bad_mint_or_out_exits_2_without_a_call(self):
        opener = FakeOpener()
        code, _, err = run_main(["not-a-mint", "--out", str(self.tmp)], opener)
        self.assertEqual((code, opener.requests), (2, []))
        self.assertIn("mint", err)
        blocker = self.tmp / "file"
        blocker.write_text("x")
        code, _, err = run_main([CAPE, "--out", str(blocker / "sub")], opener)
        self.assertEqual((code, opener.requests), (2, []))


class FieldGuardTests(unittest.TestCase):
    """A renamed load-bearing field is loud (unavailable with a reason), never a calmer ok."""

    def live(self):
        return fixture("cape_jupiter_live_20261019")

    def test_no_funding_time_anywhere_is_unavailable(self):
        payload = self.live()
        for r in payload["holders"]:
            if "addressInfo" in r:
                r["addressInfo"]["fundedAt"] = r["addressInfo"].pop("fundingBlockTime")
        res = collect(FakeOpener(FakeResponse(body_of(payload))))
        self.assertEqual((res["status"], res["reason"], res["holders"]), ("unavailable", "funding_field_missing", []))

    def test_funding_times_without_any_funder_are_unavailable(self):
        """Read as ok, every unknown funder would look like ONE shared funder (a farm would read calmer)."""
        payload = self.live()
        for r in payload["holders"]:
            if "addressInfo" in r:
                r["addressInfo"]["funder"] = r["addressInfo"].pop("fundingAddress")
        res = collect(FakeOpener(FakeResponse(body_of(payload))))
        self.assertEqual((res["status"], res["reason"]), ("unavailable", "funder_field_missing"))

    def test_no_valid_address_is_unavailable(self):
        payload = {"holders": [{"wallet": r["address"], "amount": r["amount"]} for r in self.live()["holders"]]}
        res = collect(FakeOpener(FakeResponse(body_of(payload))))
        self.assertEqual((res["status"], res["reason"]), ("unavailable", "no_valid_holder_rows"))

    def test_no_tag_field_anywhere_stays_ok_but_tags_are_unknown(self):
        payload = self.live()
        for r in payload["holders"]:
            for k in ("holderTags", "walletCategories", "tags"):
                r.pop(k, None)
        res = collect(FakeOpener(FakeResponse(body_of(payload))))
        self.assertEqual((res["status"], res["tag_fields_present"], res["tag_claims"]), ("ok", False, None))
        self.assertIn("tags unknown (no text tag field in any row)", jr.status_line(res))
        self.assertTrue(all("tags" not in r for r in res["holders"]))

    def test_object_valued_pool_tags_alone_are_not_tag_fields(self):
        """R4: datapi's `tags` objects (pool labels) are not text tags. Rows that carry only them give tags unknown,
        never "Jupiter tags no bundler"."""
        payload = self.live()
        for r in payload["holders"]:
            r.pop("holderTags", None)
            r.pop("walletCategories", None)
        self.assertEqual(sum(1 for r in payload["holders"] if r.get("tags")), 3, "the three pool rows keep their object tags")
        res = collect(FakeOpener(FakeResponse(body_of(payload))))
        self.assertEqual((res["status"], res["tag_fields_present"], res["tag_claims"]), ("ok", False, None))
        self.assertTrue(all("tags" not in r for r in res["holders"]))
        for r in payload["holders"][:2]:
            r["holderTags"] = [{"id": "x", "name": "bundler"}]  # objects in holderTags are not text tags either
        self.assertFalse(collect(FakeOpener(FakeResponse(body_of(payload))))["tag_fields_present"])
        payload["holders"][5]["walletCategories"] = []  # an empty text-tag list is a present field (no tags on that row)
        self.assertTrue(collect(FakeOpener(FakeResponse(body_of(payload))))["tag_fields_present"])

    def test_text_tag_field_rule(self):
        cases = [({"holderTags": []}, True), ({"walletCategories": []}, True), ({"holderTags": ["bundler"]}, True), ({"tags": ["sniper"]}, True),
                 ({"tags": [{"id": "Pool", "name": "x"}]}, False), ({"tags": []}, False), ({"holderTags": [{"id": 1}]}, False), ({"holderTags": "bundler"}, False), ({}, False)]
        for row, expected in cases:
            with self.subTest(row=row):
                self.assertEqual(jr.has_text_tag_field(row), expected)

    def test_partial_gaps_stay_ok(self):
        res = collect(FakeOpener(FakeResponse(body_of(self.live()))))
        self.assertEqual((res["status"], res["with_funding_time"]), ("ok", 64))
        self.assertEqual(sum(1 for r in res["holders"] if "addressInfo" not in r), 36)


class RowSanitizingTests(unittest.TestCase):
    def test_documented_fields_only_with_datapi_names(self):
        res = collect(FakeOpener(FakeResponse(body_of(fixture("cape_jupiter_live_20261019")))))
        for row in res["holders"]:
            self.assertLessEqual(set(row), ROW_FIELDS)
            self.assertLessEqual(set(row.get("addressInfo") or {}), INFO_FIELDS)
        raw_fields = {k for r in json.loads((FIX / "cape_jupiter_live_20261019.json").read_text())["holders"] for k in r}
        self.assertIn("holderTags", raw_fields)

    def test_tags_are_inert_labels_and_tag_objects_are_ignored(self):
        payload = {"count": 3, "holders": [
            {"address": CAPE, "amount": 5.0, "addressInfo": {"fundingAddress": CAPE, "fundingAmount": 1.0, "fundingBlockTime": "2026-10-01T16:09:40Z"},
             "holderTags": ["bundler", "bundler<script>alert(1)</script>", "  ", 7], "walletCategories": ["smartMoney", "Influencer"], "tags": [{"id": "Pool", "name": "Meteora DLMM Liquidity Pool"}]},
        ]}
        res = collect(FakeOpener(FakeResponse(body_of(payload))))
        self.assertEqual(res["holders"][0]["tags"], ["bundler", "bundleralert1", "influencer", "smartmoney"])  # HS-LABELS-T1 hardening (a): inline HTML tags are dropped, not left as letters
        self.assertEqual(res["tag_claims"]["tags"]["bundler"], {"wallets": 1, "amount": 5.0, "amount_unknown_wallets": 0})
        self.assertEqual(hf.tag_summary(res), hf.tag_summary(payload), "the forensics tag summary reads the same counts")

    def test_values_are_validated(self):
        good = "2026-10-01T16:09:40Z"
        rows = [
            {"address": CAPE, "amount": -1, "addressInfo": {"fundingAddress": "not-an-address", "fundingAmount": float("inf"), "fundingBlockTime": "yesterday"}},
            {"address": CAPE, "amount": 2},  # duplicate: the first row is kept
            {"address": "bad", "amount": 1},
            {"address": "Gyk9Z93Ri2JUjqES9HTpc7pxCJTLD7vhBhEjBhyApump", "amount": True, "addressInfo": {"fundingAddress": CAPE, "fundingAmount": 0.5, "fundingBlockTime": 1_790_000_000_000}},
            {"address": "HfpLdX35Kc6b7zDNWbe5x1xWLekKUXPYZbmz71vMpump", "amount": 3.5, "addressInfo": {"fundingAddress": CAPE, "fundingAmount": 1, "fundingBlockTime": good}},
            {"address": "HgTGdc29D5bDMrDvsCLnorxz899VyDj7ZN7FPa6vpump", "amount": 1.0, "addressInfo": {"fundingAddress": CAPE, "fundingBlockTime": "2026-10-01T16:09:40"}},  # no zone
            {"address": "So11111111111111111111111111111111111111112", "amount": 1.0, "addressInfo": {"fundingAddress": CAPE, "fundingBlockTime": 4_000_000_000}},  # far future
        ]
        rows_out, dropped = jr.sanitize_rows([ha_jupiter.normalize_holder(r) for r in rows], NOW)
        self.assertEqual(dropped, {"invalid_address": 1, "duplicate": 1, "over_limit": 0})
        self.assertEqual(rows_out[0], {"address": CAPE, "amount": None})
        self.assertEqual(rows_out[1]["addressInfo"], {"fundingAddress": CAPE, "fundingAmount": 0.5, "fundingBlockTime": 1_790_000_000_000})
        self.assertEqual(rows_out[1]["amount"], None)
        self.assertEqual(rows_out[2]["addressInfo"], {"fundingAddress": CAPE, "fundingAmount": 1.0, "fundingBlockTime": good})
        self.assertEqual(rows_out[3]["addressInfo"]["fundingBlockTime"], None)
        self.assertEqual(rows_out[4]["addressInfo"]["fundingBlockTime"], None)

    def test_limit_is_100_after_dropping_bad_rows(self):
        live = fixture("cape_jupiter_live_20261019")["holders"]
        extra = [dict(r, address=r["address"][:-2] + "zz") for r in live[:30]]
        res = collect(FakeOpener(FakeResponse(body_of({"holders": [{"address": "x"}] + live + extra}))))
        self.assertEqual((res["rows_read"], res["rows_dropped"]), (100, {"invalid_address": 1, "duplicate": 0, "over_limit": 30}))


class DripResponse:
    """Drip-feeds one byte every 10 ms inside one read (each byte would restart a socket timeout). Gives up after 3 s."""

    status = 200

    def __init__(self, stop):
        self.stop, self.start = stop, time.monotonic()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, n=-1):
        got = b""
        while not self.stop.is_set() and time.monotonic() - self.start < 3.0:
            time.sleep(0.01)
            got += b"x"
        return got


class StallingOpener:
    def __init__(self, stop):
        self.stop, self.requests = stop, []

    def open(self, request, timeout=None):
        self.requests.append(request)
        self.stop.wait(3.0)
        raise OSError("released")


class HardDeadlineTests(unittest.TestCase):
    DEADLINE = 0.5
    MARGIN = 0.5

    def setUp(self):
        self.stop = threading.Event()
        patcher = mock.patch.object(jr, "TIMEOUT_S", self.DEADLINE)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.stop.set)

    def timed(self, opener):
        started = time.monotonic()
        res = collect(opener)
        return res, time.monotonic() - started

    def test_a_drip_feed_ends_at_the_deadline(self):
        res, took = self.timed(FakeOpener(DripResponse(self.stop)))
        self.assertEqual((res["status"], res["reason"]), ("unavailable", "timeout"))
        self.assertLess(took, self.DEADLINE + self.MARGIN)

    def test_a_stalled_open_ends_at_the_deadline(self):
        opener = StallingOpener(self.stop)
        res, took = self.timed(opener)
        self.assertEqual((res["status"], res["reason"], len(opener.requests)), ("unavailable", "timeout", 1))
        self.assertLess(took, self.DEADLINE + self.MARGIN)


class AdapterEquivalenceTests(unittest.TestCase):
    """The collector's file reads exactly like a raw datapi answer in the forensics adapter (rows and tag counts)."""

    def test_rows_and_tags_read_like_the_raw_payload(self):
        for name in ("cape_jupiter", "cape_jupiter_live_20261019", "space_inu_jupiter", "altai_the_tiger_jupiter"):
            with self.subTest(name):
                raw = fixture(name)
                mine = collect(FakeOpener(FakeResponse(body_of(raw))))
                self.assertEqual(mine["status"], "ok")
                self.assertEqual(hf.jupiter_cohort_rows(json.loads(json.dumps(mine))), hf.jupiter_cohort_rows(raw))
                self.assertEqual(hf.tag_summary(mine), hf.tag_summary(raw))


class AssessIntegrationTests(unittest.TestCase):
    """The owner-visible chain: forensics collector run folder + jupiter_rows file -> offline assess."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp())
        pool, accounts, funded = cape_holdings()
        from test_parallel_rows import ParallelFake

        cls.cape_run = cls.tmp / "cape-run"
        code, _, _ = _run(["funders", CAPE, "--top", "100", "--workers", "6", "--out", str(cls.cape_run)], fake=ParallelFake(accounts, funded),
                          pairs=[{"pairAddress": pool, "pairCreatedAt": CAPE_LAUNCH * 1000}])
        assert code == 0
        cls.map_file = cls.tmp / "map.json"
        cls.map_file.write_text(json.dumps(_map(CAPE, [(115, 25.45), (50, 17.44)])))
        code, cls.cape_line, _ = run_main([CAPE, "--out", str(cls.cape_run)], FakeOpener(FakeResponse(body_of(fixture("cape_jupiter")))))
        assert code == 0

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def assess(self, run, mint, extra, name):
        out = self.tmp / name
        code, _, err = run_assess(mint, run, extra, out=out)
        self.assertEqual(code, 0, err)
        return json.loads((out / "assessment.json").read_text()), (out / "report.md").read_text()

    def test_collector_file_gives_the_same_assessment_and_report_as_the_raw_payload(self):
        raw = self.tmp / "cape_jupiter_raw.json"
        raw.write_text((FIX / "cape_jupiter.json").read_text())
        a_mine, md_mine = self.assess(self.cape_run, CAPE, ["--bubblemaps-json", str(self.map_file), "--jupiter-holders-json", str(self.cape_run / jr.OUT_FILE)], "mine")
        a_raw, md_raw = self.assess(self.cape_run, CAPE, ["--bubblemaps-json", str(self.map_file), "--jupiter-holders-json", str(raw)], "raw")
        self.assertEqual(a_mine, a_raw)
        self.assertEqual(md_mine, md_raw)
        self.assertIn("- Jupiter datapi holder rows: read", md_mine)
        self.assertIn("100 rows read; 98 carry a funding time", md_mine)
        self.assertIn("tags (Jupiter's claims, not proof):", md_mine)
        self.assertIn("jupiter", a_mine["cohort_sources"])
        self.assertTrue(self.cape_line.startswith("ok (100 rows; 98 with a funding time;"))

    def test_jupiter_rows_add_an_alarm_capable_cohort_source_on_cape(self):
        a, md = self.assess(self.cape_run, CAPE, ["--bubblemaps-json", str(self.map_file), "--jupiter-holders-json", str(self.cape_run / jr.OUT_FILE)], "cape-alarm")
        self.assertGreaterEqual(a["cohort_sources"]["jupiter"]["cohorts"], 1, "the CAPE farm shows up as a cohort over Jupiter's funding rows")
        self.assertIn("cohort over JUPITER rows (top 100 only, cannot clear the rest)", md)
        self.assertEqual(a["flag"]["label"], hf.FLAG_DANGER)

    def test_jupiter_rows_never_count_toward_no_alarm(self):
        """Negative control (Space Inu): with or without the Jupiter rows the level is the same, Jupiter is never a
        counted all-clear source, and without the map Jupiter rows cannot lift LIMITED to NO_ALARM."""
        case = case_negative_space_inu()
        run = self.tmp / "space-run"
        code, _, _ = _run(["funders", case.mint, "--top", str(case.top), "--workers", "6", *case.collector_args, "--out", str(run)], fake=case.fake(), pairs=case.pairs)
        self.assertEqual(code, 0)
        code, line, _ = run_main([case.mint, "--out", str(run)], FakeOpener(FakeResponse(body_of(fixture("space_inu_jupiter")))))
        self.assertTrue(line.startswith("ok (100 rows;"), line)
        mp = self.tmp / "space-map.json"
        mp.write_text(json.dumps(case.inputs["--bubblemaps-json"]))
        jup = ["--jupiter-holders-json", str(run / jr.OUT_FILE)]
        without, _ = self.assess(run, case.mint, ["--bubblemaps-json", str(mp)], "space-without")
        with_rows, _ = self.assess(run, case.mint, ["--bubblemaps-json", str(mp), *jup], "space-with")
        self.assertEqual(with_rows["cohort_sources"]["jupiter"]["cohorts"], 0, "negative control: no flagged Jupiter cohort")
        self.assertEqual(with_rows["verdict"]["level"], without["verdict"]["level"])
        self.assertEqual(with_rows["flag"], without["flag"])
        self.assertNotIn("jupiter", " ".join(with_rows["verdict"].get("sources_counted") or []).lower())
        no_map, _ = self.assess(run, case.mint, jup, "space-no-map")
        self.assertEqual(no_map["verdict"]["level"], hf.VERDICT_LIMITED, "Jupiter rows never stand in for the required map")


class SelfContainedTests(unittest.TestCase):
    def test_standard_library_and_no_key(self):
        text = (SCRIPTS / "jupiter_rows.py").read_text()
        tree = ast.parse(text)
        modules = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                modules |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                modules.add(node.module.split(".")[0])
        self.assertEqual(sorted(modules - set(sys.stdlib_module_names) - {"__future__", "ha", "provider_words"}), [])  # HS-LABELS-T1: the shared verdict-word rule
        self.assertFalse(any(isinstance(n, ast.Attribute) and n.attr in ("environ", "getenv") for n in ast.walk(tree)), "jupiter_rows reads no environment variable and no key")
        self.assertNotIn("import os", text)
        self.assertNotRegex(text, r"\b[A-Z][A-Z0-9_]*_(?:KEY|SECRET|TOKEN|PASSWORD)\b")
        self.assertNotIn("/Users/", text)
        self.assertNotIn("/Users/", Path(__file__).read_text().replace('"/Users/"', ""))


if __name__ == "__main__":
    unittest.main()
