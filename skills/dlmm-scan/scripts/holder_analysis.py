#!/usr/bin/env python3
"""Cross-check Solana token holders across Jupiter datapi (free) and Helius (paid).

Usage:
  python3 -I holder_analysis.py <MINT> [--workers 4] [--json out.json] [--external-artifact evidence.json]

Reads HELIUS_API_KEY from the environment or the repository base .env (only that one
name), never prints or stores it, and exits non-zero only on bad input (2), an
unexpected error (3, reduced to its type name: never a traceback) or Ctrl-C (130).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from ha import analysis, report  # noqa: E402
from ha.env import EnvError, load_keys  # noqa: E402
from ha.helius import ANALYSIS_RATE_CAP_PER_S, KEY_RE, HeliusClient  # noqa: E402
from ha.jupiter import JupiterClient  # noqa: E402
from ha.solana import is_solana_address  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mint", help="Solana token mint address")
    parser.add_argument("--top", type=int, default=20, help="holders to analyse and compare (default 20)")
    parser.add_argument("--funding-top", type=int, default=20, help="top wallets to run funded-by + first-activity on (2 Helius calls each)")
    parser.add_argument("--max-pages", type=int, default=10, help="DAS pages (1000 token accounts each) for the full holder scan")
    parser.add_argument("--max-helius-calls", type=int, default=150, help="hard cap on Helius calls this run")
    parser.add_argument(
        "--workers",
        type=int,
        default=analysis.DEFAULT_WORKERS,
        help=f"wallets checked at once, 1-{analysis.MAX_WORKERS} (default {analysis.DEFAULT_WORKERS}); all share one pace of at most "
        f"{ANALYSIS_RATE_CAP_PER_S} Helius requests/s and one 429 pause; same calls; 1 = the old one-at-a-time order",
    )
    parser.add_argument("--no-helius", action="store_true", help="Jupiter only (no key, no credits)")
    parser.add_argument("--no-jupiter", action="store_true", help="Helius only")
    parser.add_argument("--external-artifact", type=Path, help="lp-research-companion evidence JSON to cross-check GMGN/Bubblemaps against Helius")
    parser.add_argument("--env-file", type=Path, help="dotenv file holding HELIUS_API_KEY (default: auto-detect)")
    parser.add_argument("--json", type=Path, dest="json_out", help="write the full artifact here")
    args = parser.parse_args(argv)
    try:
        if not is_solana_address(args.mint):
            print("error: mint is not a valid Solana address", file=sys.stderr)
            return 2
        if args.top < 1 or args.max_pages < 1 or args.max_helius_calls < 1 or args.funding_top < 0:
            print("error: --top, --max-pages and --max-helius-calls must be positive", file=sys.stderr)
            return 2
        if not 1 <= args.workers <= analysis.MAX_WORKERS:
            print(f"error: --workers must be between 1 and {analysis.MAX_WORKERS}", file=sys.stderr)
            return 2
        if args.external_artifact is not None:  # local file only: refused before the key is read and before any call
            analysis.read_external_artifact(args.external_artifact)

        helius = None
        if not args.no_helius:
            try:
                keys = load_keys(["HELIUS_API_KEY"], args.env_file)
            except EnvError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 2
            if "HELIUS_API_KEY" in keys:
                if not KEY_RE.fullmatch(keys["HELIUS_API_KEY"]):  # one token of allowed characters, as the forensics engine
                    print("error: HELIUS_API_KEY has an unexpected format", file=sys.stderr)  # never echo the value
                    return 2
                helius = HeliusClient(keys["HELIUS_API_KEY"], max_calls=args.max_helius_calls)
            else:
                print("note: HELIUS_API_KEY not found; continuing without Helius (cross-check will be limited)", file=sys.stderr)
        jupiter = None if args.no_jupiter else JupiterClient()

        artifact = analysis.run(
            args.mint,
            helius=helius,
            jupiter=jupiter,
            top=args.top,
            funding_top=args.funding_top,
            max_pages=args.max_pages,
            external_artifact=args.external_artifact,
            workers=args.workers,
        )
        if args.json_out:
            args.json_out.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        sys.stdout.write(report.render(artifact))
        return 0
    except analysis.ArtifactRefused as exc:  # refused before the key is read; run() re-checks before any call
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # Ctrl-C: no traceback; wallet-check threads are daemons, so nothing holds the exit up
        print("error: interrupted (Ctrl-C); no new Helius lookups were started", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - never a traceback: an error message can carry the key (urllib puts a bad header value in it)
        print(f"error: unexpected {type(exc).__name__}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
