#!/usr/bin/env sh
set -eu

SERVICE="${SERVICE:-dashboard}"

case "$SERVICE" in
  dashboard) MODULE="dashboard.dashboard:app"; PORT="8000" ;;
  portscanner) MODULE="portscanner.portscanner:app"; PORT="8001" ;;
  bannergrabbing) MODULE="bannergrabbing.bannergrabbing:app"; PORT="8002" ;;
  vulnerability) MODULE="vulnerability.vulnerability:app"; PORT="8003" ;;
  subenum) MODULE="subdomainenumeration.subdomainenumeration:app"; PORT="8004" ;;
  smbshares) MODULE="smbshares.smbshares:app"; PORT="8005" ;;
  whatweb) MODULE="whatweb.whatweb:app"; PORT="8006" ;;
  cvelookup) MODULE="cvelookup.cvelookup:app"; PORT="8007" ;;
  metasploit) MODULE="metasploit.metasploit:app"; PORT="8008" ;;
  *)
    echo "Unknown SERVICE=$SERVICE" >&2
    exit 1
    ;;
esac


exec uvicorn "$MODULE" --host 0.0.0.0 --port "$PORT"
