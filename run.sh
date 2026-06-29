#!/bin/bash
# ─────────────────────────────────────────────
# NanoJS Scanner — Quick Run Script
# Usage:
#   ./run.sh 0xContractAddress Ethereum
#   ./run.sh 0xContractAddress BSC
#   ./run.sh 0xContractAddress Base
#   ./run.sh 0xContractAddress Optimism
#   ./run.sh 0xContractAddress Arbitrum
#   ./run.sh                              ← scans recent blocks on all chains
# ─────────────────────────────────────────────

cd "$(dirname "$0")"

if [ -z "$1" ]; then
    echo "Scanning recent blocks on all chains..."
    python3 scanner_v3.py
else
    ADDRESS=$1
    CHAIN=${2:-Ethereum}
    echo "Scanning $ADDRESS on $CHAIN..."
    python3 scanner_v3.py "$ADDRESS" "$CHAIN"
fi

if [ -f scan_results.json ]; then
    echo ""
    echo "Generating Word report..."
    python3 report_generator.py
    echo ""
    echo "Done. Look for NanoJS-*.docx in this folder."
else
    echo "No findings — no report generated."
fi
