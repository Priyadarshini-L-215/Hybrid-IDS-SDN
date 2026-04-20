#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SURICATA_REPO_ROOT:-$SCRIPT_DIR}"
SURICATA_INTERFACE="${SURICATA_INTERFACE:-eth0}"
SURICATA_BIN="${SURICATA_BIN:-$(command -v suricata || true)}"
CONFIG_TEMPLATE="${SURICATA_CONFIG_TEMPLATE:-$REPO_ROOT/config/suricata/suricata.yaml}"
RULES="${SURICATA_RULES:-$REPO_ROOT/config/suricata/signatures.rules}"
LOG_DIR="${SURICATA_LOG_DIR:-$REPO_ROOT/data/logs}"
TMP_CONFIG="$(mktemp /tmp/fyp-suricata.XXXXXX.yaml)"

cleanup() {
  rm -f "$TMP_CONFIG"
}
trap cleanup EXIT

if [[ -z "$SURICATA_BIN" ]]; then
  echo "[ERROR] Suricata binary not found on PATH. Set SURICATA_BIN if needed."
  exit 1
fi

if [[ ! -f "$CONFIG_TEMPLATE" ]]; then
  echo "[ERROR] Suricata config template not found: $CONFIG_TEMPLATE"
  exit 1
fi

if [[ ! -f "$RULES" ]]; then
  echo "[ERROR] Rules file not found: $RULES"
  exit 1
fi

mkdir -p "$LOG_DIR"

sed \
  -e "s#__REPO_ROOT__#${REPO_ROOT}#g" \
  -e "s#__SURICATA_INTERFACE__#${SURICATA_INTERFACE}#g" \
  "$CONFIG_TEMPLATE" > "$TMP_CONFIG"

echo "[*] Cleaning up old Suricata sessions..."
pkill -x suricata || true
sleep 1

echo "[*] Starting Suricata Sensor on ${SURICATA_INTERFACE}..."
echo "[*] Config: $TMP_CONFIG"
"$SURICATA_BIN" -c "$TMP_CONFIG" -s "$RULES" -i "$SURICATA_INTERFACE"

echo ""
echo "[!] Suricata exited. Check logs if this was unexpected."
echo "Press Enter to close this window..."
read -r
