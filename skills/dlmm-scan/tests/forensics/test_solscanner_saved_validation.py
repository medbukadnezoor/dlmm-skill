"""A saved SolScanner result is revalidated like the live parser before use (offline)."""

from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[2] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import helius_forensics as hf  # noqa: E402
from test_holder_forensics import MINT, NO_KEY_ENV, SECRET, FakeHelius  # noqa: E402
from test_solscanner_scan import CAPE, NOW_ALTAI, NOW_CAPE, NOW_SPACE, SPACE, ALTAI, Opener, Response, stream  # noqa: E402
import solscanner_scan as ss  # noqa: E402


def good():
    return ss.collect_solscanner(CAPE, opener=Opener(Response(stream("cape"))), now=lambda: NOW_CAPE)


def mutated(fn):
    data = copy.deepcopy(good())
    fn(data)
    return data


class ValidationTests(unittest.TestCase):
    def test_real_fixture_results_pass(self):
        for name, mint, now in (("cape", CAPE, NOW_CAPE), ("space-inu", SPACE, NOW_SPACE), ("altai-the-tiger", ALTAI, NOW_ALTAI)):
            res = ss.collect_solscanner(mint, opener=Opener(Response(stream(name))), now=lambda n=now: n)
            self.assertIs(hf.validate_solscanner_result(json.loads(json.dumps(res))) is not None, True)

    def test_bad_values_are_rejected_with_a_clear_error(self):
        cases = {
            "negative share": lambda d: d["groups"][0]["wallets"][0].update(share_pct=-1.0),
            "share over 100": lambda d: d["groups"][0]["wallets"][0].update(share_pct=101),
            "string share": lambda d: d["groups"][0]["wallets"][0].update(share_pct="44"),
            "bool share": lambda d: d["groups"][0]["wallets"][0].update(share_pct=True),
            "bad confidence": lambda d: d["groups"][0].update(confidence="certain"),
            "numeric confidence": lambda d: d["groups"][0].update(confidence=3),
            "wallets not a list": lambda d: d["groups"][0].update(wallets="x"),
            "wallet row not an object": lambda d: d["groups"][0]["wallets"].__setitem__(0, "x"),
            "risk out of range": lambda d: d["groups"][0].update(risk_score=101),
            "risk string": lambda d: d["groups"][0].update(risk_score="96"),
            "risk bool": lambda d: d["groups"][0].update(risk_score=True),
            "group not an object": lambda d: d["groups"].__setitem__(0, 5),
            "bad address": lambda d: d["groups"][0]["wallets"][0].update(address="short"),
            "bad bundle type": lambda d: d["groups"][0].update(bundle_type="<script>"),
            "stale not bool": lambda d: d.update(is_stale="yes"),
            "negative age": lambda d: d.update(scan_age_min=-5),
            "too many groups": lambda d: d.update(groups=[d["groups"][0]] * (ss.MAX_GROUPS + 1)),
            "groups missing": lambda d: d.pop("groups"),
        }
        for name, change in cases.items():
            with self.assertRaises(hf.ConfigError, msg=name) as ctx:
                hf.validate_solscanner_result(mutated(change))
            self.assertIn("--solscanner-json", str(ctx.exception), name)

    def test_nan_and_infinity_are_rejected(self):
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.assertRaises(hf.ConfigError, msg=repr(value)):
                hf.validate_solscanner_result(mutated(lambda d: d["groups"][0]["wallets"][0].update(share_pct=value)))
        with self.assertRaises(hf.ConfigError):
            hf.validate_solscanner_result(mutated(lambda d: d.update(scan_age_min=float("nan"))))


class CliTests(unittest.TestCase):
    def _main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {**NO_KEY_ENV, "HELIUS_API_KEY": SECRET}, clear=True), mock.patch.object(hf, "Helius", return_value=FakeHelius()), \
             mock.patch.object(hf, "dexscreener_pairs", return_value=([], True)), contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            return hf.main(argv), out.getvalue(), err.getvalue()

    def test_bad_saved_file_is_rejected_before_any_call_with_exit_2(self):
        bad = mutated(lambda d: d["groups"][0]["wallets"][0].update(share_pct="44"))
        bad["mint"] = MINT
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(hf, "run_holders", side_effect=AssertionError("must not run")):
            p = Path(tmp) / "s.json"
            p.write_text(json.dumps(bad))
            code, _, err = self._main(["report", MINT, "--top", "1", "--solscanner-json", str(p)])
        self.assertEqual(code, 2)
        self.assertIn("not a valid saved SolScanner result", err)
        self.assertNotIn("44", err)

    def test_nan_in_a_saved_file_is_rejected_by_the_cli(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(hf, "run_holders", side_effect=AssertionError("must not run")):
            text = json.dumps(dict(good(), mint=MINT)).replace('"share_pct": 2.108193804300921', '"share_pct": NaN', 1)
            self.assertIn("NaN", text)
            p = Path(tmp) / "s.json"
            p.write_text(text)
            code, _, err = self._main(["report", MINT, "--top", "1", "--solscanner-json", str(p)])
        self.assertEqual(code, 2)

    def test_a_good_saved_file_still_works(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "s.json"
            p.write_text(json.dumps(dict(good(), mint=MINT)))
            code, out, _ = self._main(["report", MINT, "--top", "1", "--solscanner-json", str(p), "--out", tmp])
        self.assertEqual(code, 0)
        self.assertIn("SolScanner public scan: read", out)


if __name__ == "__main__":
    unittest.main()
