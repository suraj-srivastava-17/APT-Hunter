"""
threatfox_client.py
=====================
Thin client for the abuse.ch ThreatFox Community API — a real, free,
community-maintained feed of indicators of compromise (IOCs) for active
malware/botnet infrastructure.

This is the "live data" half of APT Hunter India: instead of (or alongside)
a hardcoded IOC list, the detector can pull real, currently-active IOCs
from ThreatFox and check logs against those.

WHY THREATFOX SPECIFICALLY
----------------------------
- It's free for non-commercial/research use under abuse.ch's fair use policy.
- The data is genuinely live and community-vetted, not synthetic.
- The API is simple (one POST endpoint, JSON in/out) and well documented:
  https://threatfox.abuse.ch/api/

GETTING AN AUTH-KEY (free, takes ~1 minute)
----------------------------------------------
ThreatFox requires an Auth-Key for all API queries (this changed at some
point — older examples online show key-free access, that's no longer
accurate). To get one:
  1. Go to https://auth.abuse.ch/
  2. Sign in (supports GitHub/Twitter/Microsoft login, no separate
     password to manage)
  3. Copy your Auth-Key and either:
       - pass it with --auth-key on the command line, or
       - set it as an environment variable: export THREATFOX_AUTH_KEY=xxxx

OFFLINE / NO-KEY MODE
------------------------
If no Auth-Key is available (e.g. demoing somewhere without internet, or
you haven't registered for one yet), this module falls back to a small
bundled snapshot of real IOCs (threatfox_snapshot.json) that were pulled
from ThreatFox's public "recent IOCs" feed and saved to disk — see that
file's header for when it was captured. This keeps the demo fully
self-contained and offline-safe without inventing fake data.

API REFERENCE (for the one endpoint we use)
----------------------------------------------
POST https://threatfox-api.abuse.ch/api/v1/
Header: Auth-Key: <your key>
Body:   {"query": "get_iocs", "days": <1-7>}

Response shape (abbreviated):
{
  "query_status": "ok",
  "data": [
    {
      "id": "41",
      "ioc": "gaga.com",
      "ioc_type": "domain",
      "threat_type": "botnet_cc",
      "threat_type_desc": "...",
      "malware": "win.dridex",
      "malware_printable": "Dridex",
      "confidence_level": 50,
      "first_seen": "2020-12-08 13:36:27 UTC",
      "reporter": "abuse_ch",
      "reference": "https://twitter.com/..."
    },
    ...
  ]
}
"""

import json
import os
import urllib.request
import urllib.error

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"
SNAPSHOT_PATH = os.path.join(os.path.dirname(__file__), "threatfox_snapshot.json")


class ThreatFoxError(Exception):
    """Raised when the ThreatFox API can't be reached or returns an error."""
    pass


def fetch_live_iocs(auth_key, days=3, timeout=10):
    """
    Pulls recent IOCs directly from the ThreatFox API.

    auth_key : your personal ThreatFox Auth-Key (see module docstring)
    days     : how many days back to pull IOCs for (1-7, ThreatFox's own limit)
    timeout  : socket timeout in seconds, so a slow/dead connection doesn't
               hang the whole tool

    Returns a list of IOC dicts in ThreatFox's native schema.
    Raises ThreatFoxError on any failure (network, bad key, bad response)
    so the caller can decide whether to fall back to the offline snapshot.
    """
    if not (1 <= days <= 7):
        raise ValueError("days must be between 1 and 7 (ThreatFox API limit)")

    body = json.dumps({"query": "get_iocs", "days": days}).encode("utf-8")
    req = urllib.request.Request(
        THREATFOX_API_URL,
        data=body,
        headers={
            "Auth-Key": auth_key,
            "Content-Type": "application/json",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise ThreatFoxError(f"ThreatFox API returned HTTP {e.code}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise ThreatFoxError(f"Could not reach ThreatFox API: {e.reason}") from e
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ThreatFoxError(f"ThreatFox API returned unparseable data: {e}") from e

    if payload.get("query_status") != "ok":
        raise ThreatFoxError(
            f"ThreatFox API query failed: {payload.get('query_status', 'unknown error')}"
        )

    return payload.get("data", [])


def load_snapshot_iocs():
    """
    Loads the bundled offline snapshot — real IOCs captured from ThreatFox
    at an earlier point, saved in the same schema the live API returns.
    Used when no Auth-Key is supplied or the live call fails.
    """
    if not os.path.exists(SNAPSHOT_PATH):
        raise ThreatFoxError(f"No offline snapshot found at {SNAPSHOT_PATH}")
    with open(SNAPSHOT_PATH, "r") as f:
        snapshot = json.load(f)
    return snapshot.get("data", [])


def get_iocs(auth_key=None, days=3, prefer_live=True):
    """
    Main entry point: returns (iocs, source) where source is either
    'live' or 'snapshot' so callers/reports can be transparent about
    where the data came from — important for an admissions reviewer to
    be able to tell "this ran against real, current IOCs" vs "this ran
    against a saved sample".
    """
    if prefer_live and auth_key:
        try:
            return fetch_live_iocs(auth_key, days=days), "live"
        except ThreatFoxError as e:
            print(f"[!] Live ThreatFox fetch failed ({e}); falling back to offline snapshot")

    return load_snapshot_iocs(), "snapshot"


def normalize_iocs(raw_iocs):
    """
    Converts ThreatFox's native IOC records into the simpler shape APT
    Hunter's detection rules use internally: separate lists of IPs,
    domains, and URLs, each tagged with which malware family and
    confidence level they came from.

    ThreatFox mixes several ioc_type values together (domain, url,
    ip:port, md5_hash, sha256_hash, ...). We only care about domain/url/ip
    for the network-based detection rules in this project, so file hashes
    are filtered out here — they'd need a separate file-hash detection
    rule to be useful, which is a natural next feature but out of scope
    for v1.
    """
    ips, domains, urls = set(), set(), set()
    by_indicator = {}  # indicator string -> metadata, for report enrichment

    for entry in raw_iocs:
        ioc_type = entry.get("ioc_type", "")
        ioc_value = entry.get("ioc", "")
        if not ioc_value:
            continue

        meta = {
            "malware": entry.get("malware_printable") or entry.get("malware") or "Unknown",
            "confidence": entry.get("confidence_level"),
            "first_seen": entry.get("first_seen"),
            "reference": entry.get("reference"),
            "threat_type": entry.get("threat_type_desc") or entry.get("threat_type"),
        }

        if ioc_type == "domain":
            domains.add(ioc_value)
            by_indicator[ioc_value] = meta
        elif ioc_type == "url":
            urls.add(ioc_value)
            by_indicator[ioc_value] = meta
        elif ioc_type == "ip:port":
            ip_only = ioc_value.split(":")[0]
            ips.add(ip_only)
            by_indicator[ip_only] = meta
        elif ioc_type == "ip":
            ips.add(ioc_value)
            by_indicator[ioc_value] = meta
        # md5_hash / sha256_hash and anything else: skipped, see docstring

    return {
        "ips": sorted(ips),
        "domains": sorted(domains),
        "urls": sorted(urls),
        "metadata": by_indicator,
    }
