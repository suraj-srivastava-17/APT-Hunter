"""
APT Hunter India
=================
A log-analysis tool that flags APT-style intrusion patterns (C2 beacons,
known malware processes/files, macro-spawned shells, registry persistence,
unusual data exfiltration) in JSON-formatted endpoint/network logs, and maps
what it finds to MITRE ATT&CK techniques and a kill-chain phase.

Built for the IITK B.Cyber admission hackathon.

WHY THIS EXISTS
----------------
Most "is my machine compromised" demos either (a) hardcode a tiny IOC list
and call it a day, or (b) try to look like a finished commercial product
and end up shallow. This project picks a narrower, more honest scope:
  - one realistic detection pipeline (network / process / file / behavior)
  - explicit mapping to MITRE ATT&CK + kill-chain phases, so the output is
    explainable, not just "alert fired"
  - one genuinely useful extra: anomaly detection for IOCs we DON'T have,
    using a simple "new destination + abnormally large upload" heuristic
  - support for multi-host logs, since a real SOC never looks at one PC
    in isolation

WHAT'S NOT REAL HERE
----------------------
The IOC list in ioc_signatures.json is a small, made-up sample built from
public reporting on how APT36/SideCopy-style campaigns typically behave
(fake "Windows update" domains, RAT process names, etc.) — it is NOT a live
threat-intel feed and shouldn't be treated as one. The point of the project
is the detection pipeline and reporting logic, not the specific IOCs, which
is also why they live in a separate JSON file instead of being baked into
the code — swap that file for a real feed and the rest of the pipeline
still works.

USAGE
------
    python apt_hunter_india.py <log_file.json> [options]

    Options:
      --ioc-file PATH     use a different IOC signature file
                          (default: ioc_signatures.json)
      --export json       also write a machine-readable report (apt_report.json)
      --export csv        also write the alert list as a CSV (apt_alerts.csv)
      --quiet             skip the per-entry scan progress, just show the report

    Examples:
      python apt_hunter_india.py sample_logs_apt36_attack.json
      python apt_hunter_india.py sample_logs_central_multi_host.json --export json --export csv

SAMPLE LOG FILES (for demo purposes)
--------------------------------------
  1. sample_logs_apt36_attack.json
       single host (PC-DRDO-01), full intrusion chain: C2 connection,
       known malware process, persistence, exfiltration. Good for showing
       the kill-chain checklist filling up across all four stages.

  2. sample_logs_anomaly_demo.json
       single host (PC-MHA-USER), mostly normal traffic + one big upload
       to an IP that's not in any IOC list. Shows the anomaly rule catching
       something a pure IOC-matching tool would miss entirely.

  3. sample_logs_central_multi_host.json
       three hosts in one file (PC-DRDO-01 compromised, PC-MHA-USER
       anomalous, PC-MOD-CLEAN clean). This is the main demo — shows the
       per-host summary answering "which machine should I look at first."

LOG FORMAT
-----------
Each entry is a JSON object with a "host", "timestamp", "event_type", and
one of "connection" / "process" / "file" / "behavior" depending on what
it's describing. See the sample log files for the exact shape.

CHANGELOG
----------
  v1.0  - initial detection rules (network/process/file) + scoring
  v1.1  - kill-chain phase mapping per alert
  v1.2  - kill-chain checklist in the report
  v2.1  - destination-IP frequency tracking
  v2.2  - anomaly rule: large upload to a brand-new IP, no IOC match needed
  v3.0  - multi-host support, per-host stats
  v3.1  - moved IOC signatures out of source into ioc_signatures.json
  v3.2  - CLI args (argparse) instead of hardcoded filename
  v3.3  - JSON / CSV export of the report, alongside the text report
  v3.4  - input validation + clearer error messages for malformed logs
  v4.0  - integrated abuse.ch ThreatFox as a real, optional live IOC feed
          (see threatfox_client.py) alongside the curated local signature
          file, so the tool isn't limited to a static hardcoded list

THREAT INTEL SOURCES
----------------------
This tool checks logs against IOCs from two places:

  1. ioc_signatures.json — a small, curated, manually-labeled signature
     set (named groups, e.g. sample regional APT clusters). Useful for
     attributing a finding to a specific named group, but static.

  2. ThreatFox (https://threatfox.abuse.ch) — a real, free, community-run
     feed of currently active malware/botnet IOCs. Pulled live if you
     supply an Auth-Key (see threatfox_client.py for how to get one, free,
     in about a minute), otherwise falls back to a small bundled offline
     snapshot built from abuse.ch's own published API documentation
     examples. See --auth-key / --no-live below.

     ThreatFox matches are reported under the group name "ThreatFox" with
     the actual malware family attached (e.g. "Dridex", "Cobalt Strike")
     pulled from the feed itself, not hardcoded.
"""

import argparse
import csv
import json
import datetime
import os
import sys
from collections import defaultdict

try:
    from threatfox_client import get_iocs as tf_get_iocs, normalize_iocs as tf_normalize_iocs
    THREATFOX_AVAILABLE = True
except ImportError:
    THREATFOX_AVAILABLE = False


# ─────────────────────────────────────────────
# MITRE ATT&CK technique IDs -> readable names
# (IDs pulled from attack.mitre.org while researching detection categories)
# ─────────────────────────────────────────────
TECHNIQUE_NAMES = {
    "spearphish":       "T1566 - Spear Phishing",
    "macro_execution":  "T1059 - Command & Scripting Interpreter",
    "persistence":      "T1547 - Boot/Logon Autostart Execution",
    "c2_communication": "T1071 - Application Layer Protocol (C2)",
    "exfiltration":     "T1041 - Exfiltration Over C2 Channel",
    "process_inject":   "T1055 - Process Injection",
    "new_service":      "T1543 - Create or Modify System Process"
}

# Maps our internal alert "category" to a kill-chain phase for the report.
ATTACK_PHASES = {
    'Network C2': 'Command & Control',
    'DNS': 'Command & Control',
    'Process Behavior': 'Execution',
    'Process': 'Execution',
    'File System': 'Execution',
    'Persistence': 'Persistence',
    'Exfiltration': 'Exfiltration',
    'Network': 'Command & Control',
    'Email': 'Initial Access'   # reserved for if/when phishing detection gets added
}

KILL_CHAIN_ORDER = [
    'Initial Access', 'Execution', 'Persistence',
    'Command & Control', 'Exfiltration'
]

SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}

# Categories that are generic detections rather than a named APT family —
# excluded from "APT families found" so that list doesn't get noisy.
GENERIC_GROUPS = {'BEHAVIOR', 'SUSPICIOUS', 'ANOMALY'}


def load_ioc_signatures(path):
    """Load the IOC signature file. Exits with a clear message if it's
    missing or malformed, rather than failing deep inside a detection
    function with a confusing traceback."""
    if not os.path.exists(path):
        sys.exit(f"[ERROR] IOC signature file not found: {path}")
    try:
        with open(path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        sys.exit(f"[ERROR] IOC signature file is not valid JSON: {path}\n        {e}")

    # strip the _comment key if present, it's just documentation
    data.pop('_comment', None)
    return data


def load_threatfox_iocs(auth_key=None, days=3, use_threatfox=True):
    """
    Pulls IOCs from ThreatFox (live if auth_key is given and reachable,
    otherwise the bundled offline snapshot) and normalizes them into the
    {ips, domains, urls, metadata} shape _check_network expects.

    Returns (normalized_iocs, source_label) where source_label is a short
    human-readable string describing where the data came from, used in
    alert text and the report so it's always clear whether a finding came
    from live current data or a saved snapshot.

    If ThreatFox integration isn't available at all (missing module) or
    explicitly disabled, returns an empty IOC set rather than failing —
    the tool should still work using only the local signature file.
    """
    empty = {'ips': set(), 'domains': set(), 'urls': set(), 'metadata': {}}

    if not use_threatfox:
        return empty, "disabled (--no-threatfox)"

    if not THREATFOX_AVAILABLE:
        print("[!] threatfox_client.py not found alongside this script — "
              "skipping ThreatFox integration, using local signatures only")
        return empty, "unavailable"

    try:
        raw_iocs, source = tf_get_iocs(auth_key=auth_key, days=days, prefer_live=bool(auth_key))
    except Exception as e:
        print(f"[!] ThreatFox lookup failed entirely ({e}); using local signatures only")
        return empty, "unavailable"

    normalized = tf_normalize_iocs(raw_iocs)
    normalized['ips'] = set(normalized['ips'])
    normalized['domains'] = set(normalized['domains'])
    normalized['urls'] = set(normalized['urls'])

    label = f"live, last {days}d" if source == "live" else "offline snapshot"
    return normalized, label


class APTHunter:
    def __init__(self, ioc_signatures, threatfox_iocs=None, threatfox_source="not used"):
        self.ioc_signatures = ioc_signatures
        self.threatfox_iocs = threatfox_iocs or {'ips': set(), 'domains': set(), 'urls': set(), 'metadata': {}}
        self.threatfox_source = threatfox_source
        self.alerts = []
        self.risk_score = 0
        self.apt_groups_found = set()
        self.techniques_found = set()
        self.timeline = []
        self.phases_found = set()

        # how many times we've seen each destination IP so far — used by
        # the anomaly rule to tell "first contact" from "we talk to this
        # IP all the time"
        self.dest_ip_counts = defaultdict(int)

        # per-host rollup, used for the multi-host summary at the end
        self.host_stats = {}

    def _host_bucket(self, host):
        """Returns the stats dict for a host, creating it on first use.
        (Doing this explicitly instead of defaultdict(lambda: ...) so the
        shape of a host's stats is easy to see in one place.)"""
        if host not in self.host_stats:
            self.host_stats[host] = {
                'alerts': 0,
                'critical': 0,
                'groups': set(),
                'phases': set()
            }
        return self.host_stats[host]

    # ── MAIN ANALYSIS ──────────────────────────
    def analyze(self, log_file, quiet=False):
        if not os.path.exists(log_file):
            sys.exit(f"[ERROR] Log file not found: {log_file}")

        with open(log_file, 'r') as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError as e:
                sys.exit(f"[ERROR] Log file is not valid JSON: {log_file}\n        {e}")

        if not isinstance(logs, list):
            sys.exit(f"[ERROR] Expected a JSON list of log entries, got {type(logs).__name__}")

        total = len(logs)
        skipped = 0

        if not quiet:
            tf_count = len(self.threatfox_iocs.get('ips', [])) + len(self.threatfox_iocs.get('domains', []))
            print(f"\n[*] Loaded {total} log entries from {log_file}")
            print(f"[*] Local IOC signatures: {', '.join(self.ioc_signatures.keys())}")
            print(f"[*] ThreatFox IOCs       : {tf_count} indicators ({self.threatfox_source})")
            print(f"[*] Scanning...\n")

        for i, entry in enumerate(logs):
            if not isinstance(entry, dict):
                skipped += 1
                continue

            host = entry.get('host', 'UNKNOWN-HOST')
            timestamp = entry.get('timestamp')
            if timestamp is None:
                # an entry with no timestamp still gets scanned, just sorts
                # first in the timeline since we can't place it chronologically
                timestamp = ''
                entry = {**entry, 'timestamp': timestamp}

            if not quiet:
                print(
                    f"    [{i+1}/{total}] {entry.get('event_type', '?').upper():<10} "
                    f"{timestamp:<20} {host}",
                    end='\r'
                )

            self._check_network(entry, host)
            self._check_process(entry, host)
            self._check_file(entry, host)
            self._check_behavior(entry, host)

        if not quiet:
            print(f"\n\n[done] Scan complete — {total} entries processed"
                  + (f", {skipped} skipped (malformed)" if skipped else ""))

        return self.build_report()

    # ── DETECTION RULES ────────────────────────
    def _check_network(self, entry, host):
        conn = entry.get('connection')
        if not conn:
            return
        ip = conn.get('dest_ip', '')
        domain = conn.get('domain', '')
        bytes_sent = conn.get('bytes_sent', 0) or 0

        if ip:
            self.dest_ip_counts[ip] += 1

        is_known_apt_ip = False
        for apt, sigs in self.ioc_signatures.items():
            if ip in sigs.get('ips', []):
                is_known_apt_ip = True
                self._alert(
                    'CRITICAL', apt,
                    f"Connection to known {apt} C2 server: {ip}",
                    entry['timestamp'], 'Network C2',
                    'c2_communication', score=30, host=host
                )

            for d in sigs.get('domains', []):
                if d in domain:
                    self._alert(
                        'HIGH', apt,
                        f"DNS query to {apt} domain: {domain}",
                        entry['timestamp'], 'DNS',
                        'c2_communication', score=20, host=host
                    )

        # ThreatFox match — same idea as the curated signatures above, but
        # against a real, externally-sourced IOC feed instead of a
        # hardcoded list. See _check_threatfox_match for the lookup logic.
        if ip and ip in self.threatfox_iocs.get('ips', set()):
            is_known_apt_ip = True
            meta = self.threatfox_iocs['metadata'].get(ip, {})
            malware = meta.get('malware', 'Unknown')
            self._alert(
                'CRITICAL', 'ThreatFox',
                f"Connection to IP flagged on ThreatFox ({self.threatfox_source}): "
                f"{ip} — associated with {malware}",
                entry['timestamp'], 'Network C2',
                'c2_communication', score=30, host=host
            )
        if domain and domain in self.threatfox_iocs.get('domains', set()):
            is_known_apt_ip = True
            meta = self.threatfox_iocs['metadata'].get(domain, {})
            malware = meta.get('malware', 'Unknown')
            self._alert(
                'CRITICAL', 'ThreatFox',
                f"DNS query to domain flagged on ThreatFox ({self.threatfox_source}): "
                f"{domain} — associated with {malware}",
                entry['timestamp'], 'DNS',
                'c2_communication', score=30, host=host
            )

        # Generic large-transfer rule — anything over 10MB outbound is
        # worth a look regardless of destination.
        if bytes_sent > 10_000_000:
            self._alert(
                'HIGH', 'BEHAVIOR',
                f"Large outbound transfer: {bytes_sent/1e6:.1f} MB — possible exfiltration",
                entry['timestamp'], 'Network',
                'exfiltration', score=25, host=host
            )

        # Anomaly rule: first-ever contact with an IP, paired with an
        # immediate large upload, is suspicious even with zero IOC matches.
        # This is the one detection that doesn't depend on the signature
        # file at all — it's behavior-based instead of list-based, which
        # is also why it can catch infrastructure that isn't in our IOCs.
        ANOMALY_UPLOAD_THRESHOLD = 5_000_000  # 5 MB
        if ip and not is_known_apt_ip and self.dest_ip_counts[ip] == 1 \
                and bytes_sent >= ANOMALY_UPLOAD_THRESHOLD:
            self._alert(
                'HIGH', 'ANOMALY',
                f"Anomalous large upload ({bytes_sent/1e6:.1f} MB) to new destination IP: {ip}",
                entry['timestamp'], 'Network',
                'exfiltration', score=20, host=host
            )

    def _check_process(self, entry, host):
        proc_info = entry.get('process')
        if not proc_info:
            return
        proc = proc_info.get('name', '').lower()
        parent = proc_info.get('parent', '').lower()

        for apt, sigs in self.ioc_signatures.items():
            if any(p in proc for p in sigs.get('processes', [])):
                self._alert(
                    'CRITICAL', apt,
                    f"Known {apt}-related malware process running: {proc}",
                    entry['timestamp'], 'Process',
                    'process_inject', score=40, host=host
                )

        # Office app spawning a shell/script interpreter is one of the
        # most reliable signs of a malicious macro firing.
        if parent in ('winword.exe', 'excel.exe', 'powerpnt.exe') \
                and proc in ('cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'):
            self._alert(
                'CRITICAL', 'BEHAVIOR',
                f"Suspicious macro behavior: {parent} spawned {proc}",
                entry['timestamp'], 'Process Behavior',
                'macro_execution', score=35, host=host
            )

    def _check_file(self, entry, host):
        file_info = entry.get('file')
        if not file_info:
            return
        fname = file_info.get('name', '').lower()
        path = file_info.get('path', '')

        for apt, sigs in self.ioc_signatures.items():
            if any(f in fname for f in sigs.get('malware_files', [])):
                self._alert(
                    'CRITICAL', apt,
                    f"Known {apt}-related malware file: {fname} at {path}",
                    entry['timestamp'], 'File System',
                    'process_inject', score=35, host=host
                )

        # Executable sitting in a temp directory is a common dropper
        # pattern — flagged MEDIUM since on its own it's not conclusive.
        if 'temp' in path.lower() and fname.endswith('.exe'):
            self._alert(
                'MEDIUM', 'SUSPICIOUS',
                f"Executable dropped in Temp folder: {path}",
                entry['timestamp'], 'File System',
                'persistence', score=10, host=host
            )

    def _check_behavior(self, entry, host):
        behavior = entry.get('behavior')
        if not behavior:
            return
        action = behavior.get('action', '')

        if action == 'data_exfiltration':
            size = behavior.get('size', '?')
            dest = behavior.get('dest_ip', '?')
            self._alert(
                'CRITICAL', 'BEHAVIOR',
                f"Data exfiltration pattern: {size} sent to {dest}",
                entry['timestamp'], 'Exfiltration',
                'exfiltration', score=45, host=host
            )
        elif action == 'registry_persistence':
            key = behavior.get('key', '?')
            self._alert(
                'HIGH', 'BEHAVIOR',
                f"Persistence via registry key: {key}",
                entry['timestamp'], 'Persistence',
                'persistence', score=20, host=host
            )
        elif action == 'new_service':
            svc = behavior.get('service_name', '?')
            self._alert(
                'HIGH', 'BEHAVIOR',
                f"New suspicious service created: {svc}",
                entry['timestamp'], 'Persistence',
                'new_service', score=20, host=host
            )

    # ── HELPER ─────────────────────────────────
    def _alert(self, severity, group, description, timestamp, category, technique, score, host):
        phase = ATTACK_PHASES.get(category, 'Unknown')
        technique_name = TECHNIQUE_NAMES.get(technique, technique)

        a = {
            'severity': severity,
            'apt_group': group,
            'description': description,
            'timestamp': timestamp,
            'category': category,
            'technique': technique_name,
            'score': score,
            'phase': phase,
            'host': host or 'UNKNOWN-HOST',
        }
        self.alerts.append(a)
        self.timeline.append(a)
        self.risk_score = min(100, self.risk_score + score)

        if group not in GENERIC_GROUPS:
            self.apt_groups_found.add(group)
        self.techniques_found.add(technique_name)
        if phase != 'Unknown':
            self.phases_found.add(phase)

        stats = self._host_bucket(a['host'])
        stats['alerts'] += 1
        if severity == 'CRITICAL':
            stats['critical'] += 1
        if group not in GENERIC_GROUPS:
            stats['groups'].add(group)
        if phase != 'Unknown':
            stats['phases'].add(phase)

    # ── VERDICT ─────────────────────────────────
    def _verdict(self):
        if self.risk_score >= 80:
            return ("CRITICAL", "APT-style attack pattern matched",
                     "Isolate the system from the network immediately.")
        if self.risk_score >= 50:
            return ("HIGH", "Active intrusion-style behavior detected",
                     "Disconnect the host from the network and investigate.")
        if self.risk_score >= 25:
            return ("MEDIUM", "Suspicious activity worth a closer look",
                     "Investigate further before deciding next steps.")
        return ("LOW", "No strong indicators found",
                 "Continue normal monitoring.")

    # ── REPORT (structured data, reused by every output format) ──
    def build_report(self):
        level, summary, action = self._verdict()
        return {
            'risk_score': self.risk_score,
            'threat_level': level,
            'summary': summary,
            'recommended_action': action,
            'apt_families': sorted(self.apt_groups_found),
            'techniques': sorted(self.techniques_found),
            'phases': {ph: (ph in self.phases_found) for ph in KILL_CHAIN_ORDER},
            'alert_counts': {
                sev: sum(1 for a in self.alerts if a['severity'] == sev)
                for sev in SEVERITY_ORDER
            },
            'alerts': sorted(self.alerts, key=lambda a: SEVERITY_ORDER[a['severity']]),
            'timeline': sorted(self.timeline, key=lambda a: a['timestamp']),
            'host_stats': {
                host: {
                    'alerts': s['alerts'],
                    'critical': s['critical'],
                    'apt_families': sorted(s['groups']),
                    'phases': sorted(s['phases']),
                }
                for host, s in self.host_stats.items()
            },
            'threatfox_source': self.threatfox_source,
            'generated_at': datetime.datetime.now().isoformat(timespec='seconds'),
        }


# ─────────────────────────────────────────────
# OUTPUT FORMATTING (kept separate from detection logic on purpose —
# the report dict above is the single source of truth, these functions
# just render it differently)
# ─────────────────────────────────────────────
def print_text_report(report):
    line = "=" * 62
    print(f"\n{line}")
    print("           APT HUNTER INDIA — THREAT REPORT")
    print(line)
    print(f"\n  RISK SCORE    : {report['risk_score']}/100")
    print(f"  THREAT LEVEL  : {report['threat_level']} — {report['summary']}")
    print(f"  RECOMMENDED   : {report['recommended_action']}")
    print(f"  THREATFOX     : {report['threatfox_source']}")
    print(f"\n  APT FAMILIES  : {', '.join(report['apt_families']) or 'None detected'}")
    print(f"  TOTAL ALERTS  : {len(report['alerts'])}")
    for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
        print(f"    {sev:<8}: {report['alert_counts'][sev]}")

    if report['techniques']:
        print(f"\n{'-'*62}")
        print("  MITRE ATT&CK TECHNIQUES DETECTED:")
        for t in report['techniques']:
            print(f"    → {t}")

    print(f"\n{'-'*62}")
    print("  ATTACK PHASES (Kill Chain):")
    print('-'*62)
    for ph in KILL_CHAIN_ORDER:
        mark = '✔' if report['phases'][ph] else '✖'
        print(f"  {mark} {ph}")

    print(f"\n{'-'*62}")
    print("  DETAILED FINDINGS:")
    print('-'*62)
    for a in report['alerts']:
        print(f"\n  [{a['severity']}] {a['apt_group']}")
        print(f"     Time      : {a['timestamp']}")
        print(f"     Host      : {a['host']}")
        print(f"     Category  : {a['category']}")
        print(f"     Finding   : {a['description']}")
        print(f"     Technique : {a['technique']}")
        print(f"     Phase     : {a['phase']}")

    print(f"\n{'-'*62}")
    print("  ATTACK TIMELINE (chronological):")
    print('-'*62)
    for i, step in enumerate(report['timeline'], 1):
        print(f"\n  STEP {i} ▸ {step['timestamp']} on {step['host']}")
        print(f"          {step['description']}")

    print(f"\n{'-'*62}")
    print("  INCIDENT RESPONSE RECOMMENDATIONS:")
    print('-'*62)
    if report['risk_score'] >= 50:
        recs = [
            "Isolate the affected machine from the network immediately.",
            "Notify the security team and follow the org's IR plan.",
            "Block identified C2 IPs/domains at the firewall/proxy.",
            "Preserve host and network logs for forensic review.",
            "Check other hosts for the same indicators.",
            "Rotate credentials used on the affected system.",
        ]
    else:
        recs = [
            "Continue monitoring for 24–48 hours for similar patterns.",
            "Review firewall rules for the external IPs/domains seen.",
            "Tighten endpoint logging on the affected host if needed.",
        ]
    for i, rec in enumerate(recs, 1):
        print(f"  {i}. {rec}")

    if report['host_stats']:
        print(f"\n{'-'*62}")
        print("  PER-HOST SUMMARY:")
        print('-'*62)
        # worst host first, by risk contribution (critical count, then total alerts)
        ranked = sorted(
            report['host_stats'].items(),
            key=lambda kv: (-kv[1]['critical'], -kv[1]['alerts'])
        )
        for host, s in ranked:
            print(f"\n  HOST: {host}")
            print(f"    Total alerts  : {s['alerts']}")
            print(f"    Critical      : {s['critical']}")
            print(f"    APT families  : {', '.join(s['apt_families']) or 'None'}")
            print(f"    Phases seen   : {', '.join(s['phases']) or 'None'}")

    print(f"\n{line}\n")


def save_text_report(report, path='apt_report.txt'):
    with open(path, 'w') as f:
        f.write("APT HUNTER INDIA — THREAT REPORT\n")
        f.write(f"Generated   : {report['generated_at']}\n")
        f.write(f"Risk Score  : {report['risk_score']}/100\n")
        f.write(f"Threat Level: {report['threat_level']}\n")
        f.write(f"APT Families: {', '.join(report['apt_families']) or 'None'}\n\n")
        f.write("ALERTS:\n")
        for a in report['alerts']:
            f.write(f"[{a['severity']}] {a['timestamp']} ({a['host']}) — {a['description']}\n")
    return path


def save_json_report(report, path='apt_report.json'):
    with open(path, 'w') as f:
        json.dump(report, f, indent=2)
    return path


def save_csv_report(report, path='apt_alerts.csv'):
    fieldnames = ['severity', 'host', 'timestamp', 'apt_group', 'category',
                  'phase', 'technique', 'description', 'score']
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for a in report['alerts']:
            writer.writerow({k: a[k] for k in fieldnames})
    return path


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(
        description="Detect APT-style intrusion patterns in JSON endpoint/network logs."
    )
    parser.add_argument('log_file', help="path to the JSON log file to analyze")
    parser.add_argument('--ioc-file', default='ioc_signatures.json',
                         help="path to the local IOC signature file (default: ioc_signatures.json)")
    parser.add_argument('--export', action='append', choices=['json', 'csv'], default=[],
                         help="also write the report as 'json' and/or 'csv' "
                              "(repeatable, e.g. --export json --export csv)")
    parser.add_argument('--quiet', action='store_true',
                         help="skip the live scan progress output")
    parser.add_argument('--auth-key', default=os.environ.get('THREATFOX_AUTH_KEY'),
                         help="ThreatFox Auth-Key for live IOC lookups (free, see "
                              "https://auth.abuse.ch/). Falls back to the "
                              "THREATFOX_AUTH_KEY environment variable if not given. "
                              "Without a key, the bundled offline snapshot is used.")
    parser.add_argument('--threatfox-days', type=int, default=3, choices=range(1, 8),
                         metavar='[1-7]',
                         help="how many days back to pull live ThreatFox IOCs for (default: 3)")
    parser.add_argument('--no-threatfox', action='store_true',
                         help="skip ThreatFox entirely and only use the local signature file")
    return parser.parse_args()


def main():
    args = parse_args()

    ioc_signatures = load_ioc_signatures(args.ioc_file)
    threatfox_iocs, threatfox_source = load_threatfox_iocs(
        auth_key=args.auth_key,
        days=args.threatfox_days,
        use_threatfox=not args.no_threatfox,
    )

    hunter = APTHunter(ioc_signatures, threatfox_iocs, threatfox_source)
    report = hunter.analyze(args.log_file, quiet=args.quiet)

    print_text_report(report)
    saved = [save_text_report(report)]

    if 'json' in args.export:
        saved.append(save_json_report(report))
    if 'csv' in args.export:
        saved.append(save_csv_report(report))

    print("Saved: " + ", ".join(saved))


if __name__ == "__main__":
    main()
