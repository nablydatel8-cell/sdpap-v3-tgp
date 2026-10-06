#!/usr/bin/env bash
set -e

echo "========================================================="
echo "   SDPAP v3 & TGP Keyless Deployment Automator"
echo "========================================================="

DB_PATH="${SDPAP_DB_PATH:-./sdpap_kernel.db}"

echo "[+] Initializing Append-Only SQLite WAL Database..."
python3 sdpap_cli.py --db "$DB_PATH" init-db

echo "[+] Executing Fail-Closed Adversarial Test Suite..."
PYTHONPATH=. python3 -m unittest test_suite_full.py

echo "========================================================="
echo "   SDPAP v3 Deployment Ready & Integrity Verified!"
echo "========================================================="
