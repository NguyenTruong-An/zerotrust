#!/bin/bash
# Operator-private Risk Observatory on the GCP VM (D-13). Run via IAP SSH with a local port forward:
#   gcloud compute ssh zt-academic-private --zone us-central1-a --tunnel-through-iap -- -L 8765:127.0.0.1:8765 "sudo bash /opt/zerotrust/src/deploy/gcp-fast-track/observatory.sh"
# then open http://localhost:8765/ on your own machine. Ctrl+C stops both processes.
# The HTTP server binds 127.0.0.1 only: no firewall rule, never reachable from the public ingress.
set -euo pipefail
OUT=/var/lib/zerotrust-gcp/observatory
PORT="${PORT:-8765}"
install -d -m 0700 "$OUT"
cd /opt/zerotrust/src
python3 -X utf8 scripts/observation/observe.py --risk-container zt-gcp-ft-risk-1 --keycloak-container zt-gcp-ft-keycloak-1 \
  --since "${SINCE:-24h}" --watch-seconds 5 --output "$OUT/index.html" >/dev/null 2>&1 &
WATCH=$!
trap 'kill "$WATCH" 2>/dev/null || true' EXIT
echo "Observatory ready: open http://localhost:${PORT}/ on your machine (Ctrl+C to stop)"
python3 -m http.server "$PORT" --bind 127.0.0.1 --directory "$OUT"
