#!/usr/bin/env bash
# Normal-development regression suite — run ON a guarded machine.
# Verifies the guard did NOT break legitimate connectivity/tools.
set -u
PASS=0; FAIL=0
ok()  { echo "  PASS  $1"; PASS=$((PASS+1)); }
no()  { echo "  FAIL  $1  <-- guard may be over-blocking"; FAIL=$((FAIL+1)); }
reach() { curl -sS --max-time 10 -o /dev/null -w '%{http_code}' "$1" 2>/dev/null; }

echo "=== normal-development regression suite ==="
for host in github.com bitbucket.org pypi.org files.pythonhosted.org \
            registry.npmjs.org archive.ubuntu.com stackoverflow.com \
            developer.mozilla.org nodejs.org; do
  ip=$(getent hosts "$host" | awk '{print $1}' | head -1)
  if [ -n "$ip" ] && [ "$ip" != "0.0.0.0" ]; then ok "DNS resolves $host ($ip)"; else no "DNS $host returned '$ip'"; fi
done

code=$(reach https://github.com); [ "${code:0:1}" = "2" ] || [ "${code:0:1}" = "3" ] && ok "HTTPS github.com ($code)" || no "HTTPS github.com ($code)"
code=$(reach https://pypi.org/simple/); [ "${code:0:1}" = "2" ] && ok "pip index reachable ($code)" || no "pip index ($code)"

command -v git >/dev/null && git ls-remote https://github.com/git/git >/dev/null 2>&1 && ok "git ls-remote works" || echo "  INFO  git test skipped/failed (network or git absent)"
command -v ssh >/dev/null && ok "ssh client present" || echo "  INFO  ssh absent"

echo "--- pass:$PASS fail:$FAIL ---"
[ $FAIL -eq 0 ]
