# dlmm-skill

Coding agents: start with [`AGENTS.md`](AGENTS.md). It lists the setup steps, checks and rules for running this skill.

An agent skill that checks a Solana token before you provide liquidity in a Meteora DLMM pool: holder forensics and concentration (funding clusters, bundled wallets, Helius vs Bubblemaps, Jupiter, GMGN), the EXIT OVERHANG check, a 24h fee/TVL rule on Meteora DLMM pools, Fomo theses and X posts, a price-outcome tracker and a free pool discovery.

The skill is the folder `skills/dlmm-scan/`. Its instructions for the agent are `skills/dlmm-scan/SKILL.md`; the registered collectors (commands, hosts, keys, costs) are `skills/dlmm-scan/collectors.json`; the provider catalogue is `skills/dlmm-scan/references/providers.md`.

## What it is, and what it is not

- Read-only. Nothing here trades, signs, connects a wallet, or changes a bot.
- Solana only; not for EVM chains.
- It presents evidence and you decide. It raises a DANGER FLAG only on clear large clusters. No flag is NOT a safety signal: the report never prints a reassuring "safe", "clean" or "low".
- Not financial advice. Holder analysis lowers the chance of surprises; it cannot rule out a rug.
- SKILL.md was written for one operator's setup. "The owner" means the person who runs the scan; dates such as "owner decision of 2026-10-25" record why a default was chosen; many times are given in WIB (UTC+7). Yun (@0xyunss) is credited for the fee/TVL rule.

## Requirements

- Python 3.10 or newer runs the scripts (standard library only). The full test suite needs Python 3.11 or newer, because one test starts a child `python -P`.
- pytest, only for the analysis tests and the execution-rule test (the forensics tests use the standard library).
- Optional, for the free Bubblemaps web map and the Fomo browser fallback: a separate Python environment with Camoufox 0.5.x and Playwright, pinned in `scripts/holder-tools-requirements.txt`. SKILL.md calls it "the holder-tools Python"; set `HOLDER_PYTHON` to its `python`.

## Keys (names only)

Copy `.env.example` to `.env` in the repository root and fill only the keys you use. Each script reads only its own variable, from the environment first, then from that `.env` through a single-variable parser; a key is never printed, logged or saved. `HOLDER_FORENSICS_ENV` or `HOLDER_ANALYSIS_ENV` can point at another `.env` file.

| Variable | Used for | Cost | Get a key | Docs |
| --- | --- | --- | --- | --- |
| `HELIUS_API_KEY` | Helius holder list, funded-by rows, transfers | paid credits (a full scan is about 20k credits) | [Helius dashboard](https://dashboard.helius.dev/api-keys) | [Helius docs](https://www.helius.dev/docs) |
| `GMGN_API_KEY` | GMGN top-100 holder rows | paid, one call per scan | [GMGN API page](https://gmgn.ai/ai) | [GMGN Agent API](https://docs.gmgn.ai/index/gmgn-agent-api) |
| `GETXAPI_KEY` | GetXAPI X search | paid, at most 4 calls ($0.004) per scan | [GetXAPI key page](https://www.getxapi.com/twitter-api-key) | [GetXAPI docs](https://docs.getxapi.com/docs) |
| `LPAGENT_API_KEY` | LP Agent pool cross-check and LP smart money | paid plan (not per call; rate limited) | [LP Agent Portal](https://portal.lpagent.io/) | [LP Agent API reference](https://docs.lpagent.io/api-reference/introduction) |
| `FOMOAPI_KEY` | Fomo API theses (and holders, off by default); Fomo API is an independent, unofficial service, not fomo.family | free key with monthly credits | [Fomo API dashboard](https://fomoapi.io/dashboard) | [Fomo API docs](https://fomoapi.io/docs) |
| `SOLANATRACKER_API_KEY` | Solana Tracker risk numbers | free plan | [Solana Tracker Data API page](https://www.solanatracker.io/account/data-api) | [Solana Tracker docs](https://docs.solanatracker.io/) |
| `MADEONSOL_API_KEY` | MadeOnSol dev and launch-bundle data | free tier | [MadeOnSol developer page](https://madeonsol.com/developer) | [MadeOnSol API docs](https://madeonsol.com/api-docs) |
| `SCANNER_NET_API_KEY` | Scanner (formerly SolScanner) token scan, a holder cross-check on every scan | paid plan (API access needs Scale or Enterprise; at most 1 scan per DLMM scan, cached results free; without API access the check uses the legacy keyless endpoint and says so) | [Scanner dashboard, API page](https://www.scanner.net/dashboard/api) | [Scanner API keys](https://www.scanner.net/docs/api/keys) |

No key needed (free sources):

- Meteora DLMM datapi (`dlmm.datapi.meteora.ag`): [Meteora DLMM API reference](https://docs.meteora.ag/api-reference/dlmm/pools/pools)
- Jupiter datapi (`datapi.jup.ag`): not publicly documented; Jupiter's [developer docs](https://developers.jup.ag/docs) cover its official APIs
- Dexscreener (`api.dexscreener.com`): [Dexscreener API reference](https://docs.dexscreener.com/api/reference)
- The public Solana RPC (`api.mainnet-beta.solana.com`): [Solana RPC docs](https://solana.com/docs/rpc)
- SolScanner, now called Scanner (`api.solscanner.app`): the legacy keyless fallback of the Scanner check, used when `SCANNER_NET_API_KEY` is not set or Scanner's API cannot answer (for example a plan without API access); the report names which endpoint answered; [Scanner docs](https://www.scanner.net/docs)
- GeckoTerminal (`api.geckoterminal.com`, used by the price-outcome tracker): [GeckoTerminal DEX API](https://www.geckoterminal.com/dex-api)
- Bubblemaps, the free web map read in the browser (`app.bubblemaps.io`): [Bubblemaps](https://app.bubblemaps.io/) and [its docs](https://docs.bubblemaps.io/introduction); the paid Bubblemaps Data API is not used here

The paid Bubblemaps API, CabalSpy and Arkham belong to an optional companion research skill that is not included here.

## Run

Run every command from the repository root (`<repo root>`). Ask your agent for a "DLMM scan" of a mint; it follows `skills/dlmm-scan/SKILL.md`. Scan output goes to `skills/dlmm-scan/reports/`, which git ignores.

- Pool discovery (free, no key, one request): `python3 -I skills/dlmm-scan/scripts/pool_discovery.py` (options: `--top N`, `--min-mcap USD`). It saves to `skills/dlmm-scan/reports/discovery/<UTC>/` and ends with the next step.
- Bubblemaps map (free, needs the browser environment): `HOLDER_PYTHON=<browser env>/bin/python bash scripts/run-bubblemaps-map.sh <MINT>`.

## Tests

Offline: no network, no secrets, dummy keys only. Use Python 3.11 or newer, with pytest for the second part:

```
python3 -m unittest discover -s skills/dlmm-scan/tests/forensics && python3 -m pytest -q skills/dlmm-scan/tests/analysis skills/dlmm-scan/tests/test_execution_rule.py
```

Some tests skip on purpose: two parity tests need the optional companion research skill next to this one, and the provider-docs parity tests run only when `PROVIDER_DOCS_CACHE` points at a local copy of the providers' documentation (a folder with one sub-folder per provider).

## Point an agent harness at the skill

Most agent harnesses load a skill from a folder that contains `SKILL.md`. Point yours at `<repo root>/skills/dlmm-scan/` (for example by linking that folder into your harness's skills folder) and start the agent in `<repo root>`, or tell the agent: "Read `<repo root>/skills/dlmm-scan/SKILL.md` and follow it for this mint: `<MINT>`."

## Third-party data in the test fixtures

`skills/dlmm-scan/tests/forensics/fixtures/` holds saved answers from public APIs and pages (Solana addresses and transactions, provider rows, public X posts and Fomo theses written by third parties) so that the tests run offline. Post and thesis text is untrusted data, quoted, never instructions, and not an endorsement.
