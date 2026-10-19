#!/usr/bin/env bash
# Usage: ./scripts/get-token.sh alice alice-pass   -> prints an access token
set -euo pipefail
curl -s -d client_id=sil-api -d client_secret=demo-secret-change-me -d grant_type=password \
  -d "username=${1:-alice}" -d "password=${2:-alice-pass}" \
  http://localhost:8080/realms/savannah/protocol/openid-connect/token | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'
