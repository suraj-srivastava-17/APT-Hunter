# APT Hunter India

A log-analysis tool that flags APT-style intrusion patterns (C2 beacons,
known malware processes/files, macro-spawned shells, registry persistence,
unusual data exfiltration) in JSON-formatted endpoint/network logs, and maps
what it finds to MITRE ATT&CK techniques and a kill-chain phase.


# What's real here

- **ThreatFox integration** (`threatfox_client.py`): this tool can check
  logs against [ThreatFox](https://threatfox.abuse.ch), abuse.ch's real,
  free, community-maintained feed of currently active malware/botnet IOCs
  — not invented data. Live if you supply a free Auth-Key, otherwise it
  falls back to a small offline snapshot built from abuse.ch's own
  published API documentation examples (real historical IOCs, clearly
  labeled as a snapshot, not live).
- **Local signature file** (`ioc_signatures.json`): a small curated set of
  named, illustrative sample IOCs (kept clearly labeled as a *sample*, not
  live threat intel) — useful for demoing attribution to a named group.
- **Sample log files**: synthetic, since real APT intrusion logs obviously
  aren't public — these exist purely to demonstrate the detector working
  end to end.

This split — real IOC source, synthetic demo logs — is a standard and
honest pattern for security tooling demos: nobody expects you to have
real breach data, but the threat intel itself should be real where
possible.

## Files

| File | Purpose |
|---|---|
| `apt_hunter_india.py` | main script |
| `threatfox_client.py` | client for the real ThreatFox API + offline fallback |
| `threatfox_snapshot.json` | offline snapshot of real ThreatFox IOCs (from abuse.ch's own docs) |
| `ioc_signatures.json` | sample/local IOC signature set |
| `sample_logs_apt36_attack.json` | demo 1 — single host, full attack chain (local signatures) |
| `sample_logs_anomaly_demo.json` | demo 2 — single host, anomaly detection (no IOC match) |
| `sample_logs_central_multi_host.json` | demo 3 — multiple hosts in one log file |
| `sample_logs_threatfox_demo.json` | demo 4 — host hitting real ThreatFox-sourced IOCs |

## Requirements

Python 3.8+, no external packages — only the standard library (uses
`urllib` for the ThreatFox HTTP call, not `requests`, so there's nothing
extra to install).

## Getting a free ThreatFox Auth-Key (optional, ~1 minute)

1. Go to <https://auth.abuse.ch/>
2. Sign in (GitHub / Twitter / Microsoft login — no separate password)
3. Copy your Auth-Key
4. Either pass it each run with `--auth-key`, or set it once:
   ```bash
   export THREATFOX_AUTH_KEY=your-key-here
   ```

**No key? No problem.** The tool automatically falls back to the bundled
offline snapshot — every demo below works with zero setup.

## Running the demos

Run from the folder containing all the files above.

### Demo 1 — full APT-style attack chain (local signatures)
```bash
python apt_hunter_india.py sample_logs_apt36_attack.json
```

### Demo 2 — anomaly detection (no IOC match needed at all)
```bash
python apt_hunter_india.py sample_logs_anomaly_demo.json
```

### Demo 3 — multi-host central log (main demo)
```bash
python apt_hunter_india.py sample_logs_central_multi_host.json --export json --export csv
```

### Demo 4 — real ThreatFox IOC match
Shows a host connecting to indicators that are genuinely tracked by
ThreatFox (a Cobalt Strike C2 IP and a Magecart skimming domain, both
pulled from abuse.ch's own documentation examples). Run with no key to
use the offline snapshot, or with `--auth-key` for a live lookup:

```bash
# offline snapshot (default, no setup needed)
python apt_hunter_india.py sample_logs_threatfox_demo.json

# live lookup against current ThreatFox data
python apt_hunter_india.py sample_logs_threatfox_demo.json --auth-key YOUR_KEY
```

The report's `THREATFOX` line tells you whether a run used live data or
the offline snapshot, so it's always clear which one produced a given
result.

## All CLI options

```bash
python apt_hunter_india.py <log_file.json> [options]

  --ioc-file PATH       use a different local IOC signature file
                        (default: ioc_signatures.json)
  --auth-key KEY        ThreatFox Auth-Key for live lookups (or set
                        THREATFOX_AUTH_KEY in your environment)
  --threatfox-days N    how many days back to pull live IOCs for (1-7,
                        default: 3 — this is ThreatFox's own API limit)
  --no-threatfox        skip ThreatFox entirely, local signatures only
  --export json         also write apt_report.json
  --export csv          also write apt_alerts.csv (one row per alert)
  --quiet               skip the live per-entry scan progress output
```

## Running on your own log file

Any JSON file containing a list of log entries works, as long as each
entry follows the same shape as the sample files (a `host`, `timestamp`,
`event_type`, and one of `connection` / `process` / `file` / `behavior`).

```bash
python apt_hunter_india.py path/to/your_log_file.json
```

## A note on scope and honesty

The local `ioc_signatures.json` set is illustrative and small on purpose
— it's there to demonstrate the *detection pipeline* (rules, scoring,
MITRE/kill-chain mapping, multi-host rollup), not to claim to be a
production threat-intel feed. The ThreatFox integration is what makes
this tool's IOC matching genuinely real rather than purely synthetic; the
local file and the anomaly-detection heuristic are deliberately kept
alongside it to show range — named-signature matching, real external
feed matching, and behavior-based anomaly detection (which needs no
signature at all) are three different techniques, shown working together.
