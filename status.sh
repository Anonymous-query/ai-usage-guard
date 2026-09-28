#!/usr/bin/env bash
# Convenience wrapper: full status + recent audit log.
set -euo pipefail
/usr/local/bin/intern-ai-guard status
echo
if command -v journalctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  echo "── recent events (journalctl -u intern-ai-guard) ──"
  journalctl -u intern-ai-guard --no-pager -n 15 2>/dev/null || echo "(no journal entries yet)"
fi
