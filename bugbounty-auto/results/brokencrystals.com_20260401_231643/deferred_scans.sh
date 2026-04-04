#!/usr/bin/env bash
# Deferred scans from bbhunt — run these manually when ready
# Generated: Sat Apr  4 02:14:16 AM EDT 2026

# sqlmap (timed out at 15m — resume with --resume)
sqlmap -m "results/brokencrystals.com_20260401_231643/vulns/sqli/targets_limited.txt" --batch --random-agent --level=2 --risk=1 --threads=10 --output-dir="results/brokencrystals.com_20260401_231643/vulns/sqli/sqlmap_results" --resume
