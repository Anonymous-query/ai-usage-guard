#!/usr/bin/env bash
# intern-ai-guard installer.
# Deploy: git clone … && cd intern-ai-guard && sudo ./install.sh && cd .. && rm -rf intern-ai-guard
# Exit codes: 0 ok · 1 precondition failed (nothing changed) · 2 apply failed (rolled back)
set -euo pipefail

PKG_LIB=/usr/local/lib/intern-ai-guard
BIN=/usr/local/bin/intern-ai-guard
ETC=/etc/intern-ai-guard
STATE=/var/lib/intern-ai-guard
UNIT_DIR=/etc/systemd/system
TS=$(date +%Y%m%d-%H%M%S)
BACKUP="$STATE/backups/$TS"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

log()  { echo -e "[install] $*"; }
err()  { echo -e "[install] ERROR: $*" >&2; }

# ── rollback trap ────────────────────────────────────────────────────────────
ROLLBACK_ENABLED=0
declare -a CREATED_PATHS=()
rollback() {
  [ "$ROLLBACK_ENABLED" -eq 1 ] || return
  err "installation failed — rolling back"
  systemctl disable --now intern-ai-guard.timer >/dev/null 2>&1 || true
  # remove anything we created this run
  for p in "${CREATED_PATHS[@]}"; do rm -rf "$p" 2>/dev/null || true; done
  # restore backed-up originals
  if [ -d "$BACKUP" ]; then
    [ -f "$BACKUP/hosts" ] && cp -a "$BACKUP/hosts" /etc/hosts || true
  fi
  # drop our nft table if we managed to create it
  nft delete table inet intern_ai_guard >/dev/null 2>&1 || true
  err "rollback complete. System returned to pre-install state."
}
trap rollback ERR

# ── 1. preconditions ─────────────────────────────────────────────────────────
[ "$(id -u)" -eq 0 ] || { err "must run as root (sudo ./install.sh)"; exit 1; }

if [ ! -r /etc/os-release ]; then err "cannot read /etc/os-release"; exit 1; fi
. /etc/os-release
log "OS: ${PRETTY_NAME:-unknown}  arch: $(uname -m)"
case "${ID:-}" in
  ubuntu|debian|linuxmint|pop) : ;;
  *) log "WARNING: designed for Ubuntu/Debian; ${ID:-unknown} is untested — continuing" ;;
esac

if ! [ -d /run/systemd/system ]; then
  err "systemd is not PID 1 — the timer/service cannot be installed here."
  err "(This is expected inside a plain container. Use --no-systemd to install"
  err " policy+CLI only.)"
  [ "${1:-}" = "--no-systemd" ] || exit 1
fi
NO_SYSTEMD=0; [ "${1:-}" = "--no-systemd" ] && NO_SYSTEMD=1

need() { command -v "$1" >/dev/null 2>&1; }
MISSING=()
need python3 || MISSING+=("python3")
python3 -c "import yaml" 2>/dev/null || MISSING+=("python3-yaml")
need nft || log "note: nft not found — firewall layer will be UNSUPPORTED (hosts+browser still work)"
if [ "${#MISSING[@]}" -gt 0 ]; then
  log "installing missing prerequisites: ${MISSING[*]}"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq "${MISSING[@]}"
fi

log "network check:"; getent hosts github.com >/dev/null 2>&1 && log "  DNS ok" || log "  WARNING: DNS resolution of github.com failed pre-install"

# ── 2. backups (before touching anything) ────────────────────────────────────
ROLLBACK_ENABLED=1
mkdir -p "$BACKUP"
cp -a /etc/hosts "$BACKUP/hosts"
[ -d "$ETC" ] && cp -a "$ETC" "$BACKUP/etc-intern-ai-guard" || true
nft list table inet intern_ai_guard >"$BACKUP/pre-nft.txt" 2>/dev/null || true
log "backed up changed files to $BACKUP"
# Keep only the 5 most recent backup sets — installs/reinstalls otherwise pile up.
ls -1dt "$STATE"/backups/*/ 2>/dev/null | tail -n +6 | xargs -r rm -rf

# ── 3. install package + config + units ──────────────────────────────────────
mkdir -p "$PKG_LIB" "$ETC" "$STATE"; CREATED_PATHS+=("$PKG_LIB" "$STATE")
install -m 0755 -d "$PKG_LIB"
cp -a "$SRC_DIR/src/intern_ai_guard/." "$PKG_LIB/"
cp -a "$SRC_DIR/docs" "$PKG_LIB/docs"
cp -a "$SRC_DIR/uninstall.sh" "$PKG_LIB/uninstall.sh"; chmod 0755 "$PKG_LIB/uninstall.sh"
install -m 0755 "$SRC_DIR/intern-ai-guard.launcher" "$BIN"; CREATED_PATHS+=("$BIN")

# config: never clobber an existing policy — first install only
if [ ! -f "$ETC/policy.yaml" ]; then
  install -m 0644 "$SRC_DIR/policy.yaml.example" "$ETC/policy.yaml"
  log "installed default policy.yaml"
else
  log "existing $ETC/policy.yaml preserved"
fi
for f in "$SRC_DIR"/config/*.txt; do
  base=$(basename "$f")
  # preserve admin-edited lists across reinstall
  if [ ! -f "$ETC/$base" ]; then install -m 0644 "$f" "$ETC/$base"; else log "preserved $base"; fi
done

if [ "$NO_SYSTEMD" -eq 0 ]; then
  install -m 0644 "$SRC_DIR/systemd/intern-ai-guard.service" "$UNIT_DIR/"
  install -m 0644 "$SRC_DIR/systemd/intern-ai-guard.timer" "$UNIT_DIR/"
  CREATED_PATHS+=("$UNIT_DIR/intern-ai-guard.service" "$UNIT_DIR/intern-ai-guard.timer")
  systemctl daemon-reload
fi

# ── 4. validate policy BEFORE enforcing ──────────────────────────────────────
if ! "$BIN" show-policy >/dev/null; then err "policy validation failed"; exit 2; fi
log "policy validated"

# ── 5. first apply ───────────────────────────────────────────────────────────
if ! "$BIN" apply; then err "initial apply failed"; exit 2; fi

# ── 6. enable timer ──────────────────────────────────────────────────────────
if [ "$NO_SYSTEMD" -eq 0 ]; then
  systemctl enable --now intern-ai-guard.timer
  log "timer enabled: $(systemctl is-active intern-ai-guard.timer)"
fi

# success — disable rollback
trap - ERR
ROLLBACK_ENABLED=0
log "installation complete."
echo
"$BIN" status || true
echo
log "You may now delete the source directory: rm -rf '$SRC_DIR'"
log "Manage policy in $ETC/  then run: sudo intern-ai-guard apply"
exit 0
