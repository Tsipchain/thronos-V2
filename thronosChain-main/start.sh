#!/usr/bin/env bash
set -e

#!/usr/bin/env bash
set -e

# This start script runs the Stratum engine, a simple microminer
# demonstration and the main Flask application.  It is designed for
# deployment on platforms such as Railway.  When the Flask app exits,
# the background processes are cleaned up.

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
