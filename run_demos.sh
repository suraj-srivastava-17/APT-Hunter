#!/bin/bash
# run_demos.sh
# Runs all four APT Hunter India demo scenarios back to back.
# Usage: ./run_demos.sh
#
# Note: demo 4 (ThreatFox) runs in offline-snapshot mode by default.
# To use live ThreatFox data instead, set THREATFOX_AUTH_KEY first:
#   export THREATFOX_AUTH_KEY=your-key-here
#   ./run_demos.sh

set -e

echo "############################################"
echo "# DEMO 1: Full APT-style attack chain (local signatures)"
echo "############################################"
python3 apt_hunter_india.py sample_logs_apt36_attack.json
echo

echo "############################################"
echo "# DEMO 2: Anomaly detection (no IOC match)"
echo "############################################"
python3 apt_hunter_india.py sample_logs_anomaly_demo.json
echo

echo "############################################"
echo "# DEMO 3: Multi-host central log + exports"
echo "############################################"
python3 apt_hunter_india.py sample_logs_central_multi_host.json --export json --export csv
echo

echo "############################################"
echo "# DEMO 4: Real ThreatFox IOC match"
echo "############################################"
python3 apt_hunter_india.py sample_logs_threatfox_demo.json
echo

echo "All four demos complete. Reports saved as apt_report.txt"
echo "(+ apt_report.json / apt_alerts.csv from demo 3)."
