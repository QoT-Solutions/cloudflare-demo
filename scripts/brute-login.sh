#!/usr/bin/env bash
set -euo pipefail

# Simple brute-force style script to hit /login multiple times.
# Useful for demonstrating Cloudflare Rate Limiting / Bot protection.
BASE_URL="${BASE_URL:-http://localhost:3000}"
URL="${URL:-${BASE_URL%/}/login}"

echo "Sending 25 POST requests to ${URL}"
echo

for i in $(seq 1 25); do
  status="$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "${URL}" \
    -H "Content-Type: application/json" \
    -d '{"username":"demo","password":"wrong-password"}')"
  echo "Attempt ${i}: HTTP ${status}"
  # Short delay so you can tune rate limits up/down as needed
  sleep 0.1
done

