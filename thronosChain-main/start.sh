#!/bin/bash
set -e
mkdir -p /data/contracts

echo "=== Starting Stratum engine on TCP port 3333 ==="
python stratum_engine.py &
STRATUM_PID=$!

echo "=== Starting MicroMiner demonstration ==="
python micro_miner.py &
MINER_PID=$!

echo "=== Starting Flask app on HTTP port 8000 ==="
python server.py

echo "=== Shutting down background services ==="
kill $STRATUM_PID $MINER_PID || true


