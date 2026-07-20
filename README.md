# APT Hunter India
### A detection pipeline that combines live threat intelligence, signature matching, and behavioral anomaly detection — mapped end-to-end to MITRE ATT&CK.

## TL;DR

Feed it a JSON log of endpoint/network activity. It flags C2 beacons, known-malware activity, macro-spawned shells, registry persistence, and abnormal exfiltration — cross-checked against a **real, live-updating threat intel feed** (not synthetic IOCs), and tags every hit with a MITRE ATT&CK technique + kill-chain phase. Multi-host logs get rolled into one consolidated report.

No dependencies. No API key required to run it. Four working demos included.

## Why three detection methods instead of one

Most student projects in this space pick one technique and stop. This one runs three in parallel, because real detection pipelines don't rely on a single signal:

| Method | What it catches | Backed by |
|---|---|---|
| **Named signature matching** | Known IOCs tied to a specific threat group | Local curated set |
| **Live threat intel correlation** | Currently-active malware/botnet infrastructure | [ThreatFox](https://threatfox.abuse.ch) (abuse.ch) — real, live, free |
| **Behavioral anomaly detection** | Novel activity with *no* matching signature | Rule-based heuristics |

## What's real vs. synthetic — stated once, plainly

- **ThreatFox integration is real.** Live API lookup if you supply a free Auth-Key; otherwise falls back to an offline snapshot built from ThreatFox's own published examples. The report always states which one produced a given result.
- **Demo logs are synthetic**, because real APT breach data isn't public. They exist to exercise the full pipeline end-to-end, not to simulate a specific real incident.

## Files

| File | Purpose |
|---|---|
| `apt_hunter_india.py` | main detection engine |
| `threatfox_client.py` | live ThreatFox API client + offline fallback |
| `threatfox_snapshot.json` | offline snapshot of real ThreatFox IOCs |
| `ioc_signatures.json` | local signature set |
| `sample_logs_apt36_attack.json` | demo — full single-host attack chain |
| `sample_logs_anomaly_demo.json` | demo — anomaly detection, zero signature matches |
| `sample_logs_central_multi_host.json` | demo — multi-host rollup |
| `sample_logs_threatfox_demo.json` | demo — real ThreatFox IOC hit |
| `run_demos.sh` | runs all four demos in sequence |

## Requirements

Python 3.8+ — **zero external dependencies.** The ThreatFox client uses `urllib` from the standard library, so there's nothing to `pip install`.

## Run it in under a minute

```bash
git clone https://github.com/suraj-srivastava-17/APT-Hunter.git
cd APT-Hunter
python apt_hunter_india.py sample_logs_apt36_attack.json
```

Or run every demo at once:

```bash
bash run_demos.sh
```

### All four demos

```bash
# full attack chain, local signatures
python apt_hunter_india.py sample_logs_apt36_attack.json

# anomaly detection, no signature needed
python apt_hunter_india.py sample_logs_anomaly_demo.json

# multi-host log, exported to JSON + CSV
python apt_hunter_india.py sample_logs_central_multi_host.json --export json --export csv

# real ThreatFox IOC match (offline snapshot by default)
python apt_hunter_india.py sample_logs_threatfox_demo.json
```

### Optional: live ThreatFox lookups

```bash
export THREATFOX_AUTH_KEY=your-key-here   # free at https://auth.abuse.ch/
python apt_hunter_india.py sample_logs_threatfox_demo.json --auth-key $THREATFOX_AUTH_KEY
```

## Full CLI

```
python apt_hunter_india.py <log_file.json> [options]

  --ioc-file PATH       alternate local signature file (default: ioc_signatures.json)
  --auth-key KEY        ThreatFox Auth-Key for live lookups
  --threatfox-days N    days of live IOCs to pull (1-7, default 3)
  --no-threatfox        local signatures only
  --export json|csv     write apt_report.json / apt_alerts.csv
  --quiet               suppress per-entry scan output
```

## Bring your own logs

Any JSON list of entries works, given `host`, `timestamp`, `event_type`, and one of `connection` / `process` / `file` / `behavior`:

```bash
python apt_hunter_india.py path/to/your_log_file.json
```

## What's next — the honest gap

This is a working pipeline, not a finished research product, and the gap between the two is exactly where I want to go next:

- **No labeled evaluation yet.** The demos prove the pipeline runs end-to-end, not a detection rate. Next step: run it against a real public dataset (CICIDS2017/2018) and report actual precision/recall instead of "it caught the demo."
- **Anomaly detection is heuristic, not learned.** Swapping in an unsupervised model (isolation forest, or a sequence model over event streams) trained against labeled data is the natural upgrade.
- **Single threat-intel source.** Adding MISP or OTX would let the tool cross-validate IOCs instead of trusting one feed.
- **Static MITRE/kill-chain mapping.** A graph model over technique co-occurrence would be a more principled version of what's currently a lookup table.



