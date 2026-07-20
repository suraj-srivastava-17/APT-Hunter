"""
test_apt_hunter.py
===================
Small, dependency-free test suite for apt_hunter_india.py.

Run with:
    python3 test_apt_hunter.py

Uses plain assert statements (no pytest requirement) so it runs anywhere
the main tool runs — matches the project's "standard library only" design.

WHAT THIS COVERS
-----------------
1. domain_matches() — the exact bug class that used to exist here
   (naive substring matching flagging lookalike domains as hits).
2. End-to-end: a log file with a known-bad IOC produces a CRITICAL
   alert with the right APT family attributed.
3. End-to-end: a clean log with no IOC hits stays at LOW / risk 0.
4. The anomaly rule fires on a first-contact large upload even with
   zero IOC matches, and does NOT fire on a small upload.
"""

import json
import os
import tempfile

from apt_hunter_india import APTHunter, domain_matches


def test_domain_matches_exact():
    assert domain_matches("evil.com", "evil.com") is True


def test_domain_matches_subdomain():
    assert domain_matches("cdn.evil.com", "evil.com") is True


def test_domain_matches_rejects_lookalike_suffix():
    # "evil.com" appears as a substring but this is NOT evil.com or a
    # subdomain of it — a naive `"evil.com" in domain` check would
    # wrongly match this. This is the bug this helper exists to fix.
    assert domain_matches("notevil.com.attacker.net", "evil.com") is False


def test_domain_matches_rejects_partial_word():
    # "myevil.com" is a different registered domain than "evil.com",
    # not a subdomain of it.
    assert domain_matches("myevil.com", "evil.com") is False


def test_domain_matches_empty_inputs():
    assert domain_matches("", "evil.com") is False
    assert domain_matches("evil.com", "") is False
    assert domain_matches(None, "evil.com") is False


def _run_hunter(log_entries, ioc_signatures=None):
    """Helper: run APTHunter over an in-memory list of log entries and
    return the report dict, without needing a real file on disk for the
    IOC signatures (log entries still go through a temp file since
    analyze() reads from a path)."""
    ioc_signatures = ioc_signatures or {
        "TestAPT": {
            "ips": ["203.0.113.99"],
            "domains": ["malicious-c2.test"],
            "processes": ["evil_rat.exe"],
            "malware_files": ["dropper.bin"],
        }
    }
    hunter = APTHunter(ioc_signatures)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(log_entries, f)
        path = f.name
    try:
        report = hunter.analyze(path, quiet=True)
    finally:
        os.unlink(path)
    return report


def test_known_bad_ip_triggers_critical_alert():
    logs = [{
        "host": "PC-TEST-01",
        "timestamp": "2026-01-01T00:00:00",
        "event_type": "network",
        "connection": {"dest_ip": "203.0.113.99", "domain": "", "bytes_sent": 1000},
    }]
    report = _run_hunter(logs)
    # A single known-bad-IP hit produces one CRITICAL *alert*, but overall
    # threat_level only reaches "CRITICAL" once risk_score >= 80 (see
    # _verdict()) — that's by design, one match alone isn't enough
    # evidence to call the whole host fully compromised. So we assert on
    # the alert itself and the attribution, not the aggregate verdict.
    assert report["alert_counts"]["CRITICAL"] >= 1, report
    assert "TestAPT" in report["apt_families"]
    assert any(a["severity"] == "CRITICAL" and a["apt_group"] == "TestAPT"
               for a in report["alerts"]), report["alerts"]


def test_clean_log_stays_low_risk():
    logs = [{
        "host": "PC-CLEAN-01",
        "timestamp": "2026-01-01T00:00:00",
        "event_type": "network",
        "connection": {"dest_ip": "198.51.100.1", "domain": "totally-normal-site.test", "bytes_sent": 500},
    }]
    report = _run_hunter(logs)
    assert report["threat_level"] == "LOW", report
    assert report["risk_score"] == 0
    assert report["apt_families"] == []


def test_anomaly_rule_fires_on_first_contact_large_upload():
    logs = [{
        "host": "PC-TEST-02",
        "timestamp": "2026-01-01T00:00:00",
        "event_type": "network",
        # brand-new IP, not in any IOC list, but a big first-contact upload
        "connection": {"dest_ip": "198.51.100.200", "domain": "", "bytes_sent": 8_000_000},
    }]
    report = _run_hunter(logs)
    descriptions = [a["description"] for a in report["alerts"]]
    assert any("Anomalous large upload" in d for d in descriptions), report["alerts"]


def test_anomaly_rule_does_not_fire_on_small_upload():
    logs = [{
        "host": "PC-TEST-03",
        "timestamp": "2026-01-01T00:00:00",
        "event_type": "network",
        "connection": {"dest_ip": "198.51.100.201", "domain": "", "bytes_sent": 100_000},
    }]
    report = _run_hunter(logs)
    descriptions = [a["description"] for a in report["alerts"]]
    assert not any("Anomalous large upload" in d for d in descriptions), report["alerts"]


def run_all():
    tests = [obj for name, obj in list(globals().items()) if name.startswith("test_")]
    passed, failed = 0, 0
    for t in tests:
        try:
            t()
            print(f"  PASS  {t.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {t.__name__} -> {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed out of {passed + failed}")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    run_all()
