#!/usr/bin/env bash
# intern-ai-guard uninstaller.
# Removes ONLY what this project created. Never flushes the firewall, never
# touches ufw or resolved or user data. Restores the backed-up /etc/hosts region by
# removing our marker block.
set -euo pipefail

PKG_LIB=/usr/local/lib/intern-ai-guard
BIN=/usr/local/bin/intern-ai-guard
ETC=/etc/intern-ai-guard
STATE=/var/lib/intern-ai-guard
UNIT_DIR=/etc/systemd/system
KEEP_CONFIG=0
[ "${1:-}" = "--keep-config" ] && KEEP_CONFIG=1

log() { echo "[uninstall] $*"; }
[ "$(id -u)" -eq 0 ] || { echo "must run as root" >&2; exit 1; }

# 1. stop + disable units
if [ -d /run/systemd/system ]; then
  systemctl disable --now intern-ai-guard.timer >/dev/null 2>&1 || true
  systemctl disable --now intern-ai-guard.service >/dev/null 2>&1 || true
fi
rm -f "$UNIT_DIR/intern-ai-guard.service" "$UNIT_DIR/intern-ai-guard.timer"
[ -d /run/systemd/system ] && systemctl daemon-reload || true
log "service + timer removed"

# 2. remove ONLY our nft table (targeted delete; never a whole-ruleset wipe)
if command -v nft >/dev/null 2>&1; then
  nft delete table inet intern_ai_guard >/dev/null 2>&1 && log "nft table removed" || log "no nft table present"
fi

# 3. remove ONLY our /etc/hosts marker block
python3 - <<'PY'
import re
b="# >>> intern-ai-guard BEGIN"; e="# <<< intern-ai-guard END"
try:
    t=open("/etc/hosts").read()
except OSError:
    raise SystemExit(0)
new=re.sub(re.escape(b)+r".*?"+re.escape(e)+r"\n?", "", t, flags=re.S)
if new!=t:
    open("/etc/hosts","w").write(new); print("[uninstall] /etc/hosts block removed")
PY

# 4. remove browser policy files we wrote (only our filename)
for d in /etc/opt/chrome/policies/managed /etc/chromium/policies/managed \
         /etc/chromium-browser/policies/managed /etc/brave/policies/managed \
         /etc/opt/edge/policies/managed; do
  rm -f "$d/intern-ai-guard.json"
done
rm -f /etc/firefox/policies/policies.json
log "browser policies removed"

# 5. remove program files
rm -rf "$PKG_LIB"; rm -f "$BIN"
log "program files removed"

# 6. config + state
if [ "$KEEP_CONFIG" -eq 0 ]; then
  rm -rf "$ETC"
  # keep backups dir for audit unless fully purging
  find "$STATE" -maxdepth 1 -type f -delete 2>/dev/null || true
  log "config removed ($STATE/backups kept for audit)"
else
  log "config in $ETC preserved (--keep-config)"
fi

log "uninstall complete. Firewall, DNS config, and user data were not touched."
echo "Backups (if any) remain in $STATE/backups"
