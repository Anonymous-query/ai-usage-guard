#!/usr/bin/env bash
# Re-apply policy after editing /etc/intern-ai-guard/*, or refresh program files
# from a fresh clone. v1 = local only (v2 will pull signed policy centrally).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 1; }
BIN=/usr/local/bin/intern-ai-guard
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

# If run from a clone, refresh code (not config) first.
if [ -d "$SRC_DIR/src/intern_ai_guard" ] && [ -d /usr/local/lib/intern-ai-guard ]; then
  cp -a "$SRC_DIR/src/intern_ai_guard/." /usr/local/lib/intern-ai-guard/
  [ -d "$SRC_DIR/docs" ] && cp -a "$SRC_DIR/docs" /usr/local/lib/intern-ai-guard/docs
  echo "[update] program files refreshed"
fi
"$BIN" show-policy >/dev/null || { echo "[update] policy invalid — not applying"; exit 2; }
"$BIN" apply
echo "[update] done"
