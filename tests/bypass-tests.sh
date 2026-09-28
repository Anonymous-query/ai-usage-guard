#!/usr/bin/env bash
# Bypass test suite — run ON a guarded machine (after install) as root.
# Each test prints: name · expected · actual · layer · limitation.
# "actual" is best-effort observation; some rows are DETECTED (allowed+logged),
# not BLOCKED — matching docs/BYPASS_ANALYSIS.md. Read that file alongside this.
set -u
PASS=0; FAIL=0; INFO=0
row() { printf '%-28s exp:%-9s act:%-9s [%s] %s\n' "$1" "$2" "$3" "$4" "$5"; }
blocked() { ! curl -sS --max-time 6 -o /dev/null "$1" 2>/dev/null; }  # true if request failed

echo "=== intern-ai-guard bypass suite ==="

# 1 hosts modification repaired
if grep -q 'intern-ai-guard BEGIN' /etc/hosts; then
  row "hosts-block-present" BLOCKED BLOCKED compliance "root can re-edit; repaired each cycle"; PASS=$((PASS+1))
else row "hosts-block-present" BLOCKED MISSING compliance "run apply"; FAIL=$((FAIL+1)); fi

# 2 DNS resolution of a denied domain (hosts layer)
IP=$(getent hosts chatgpt.com | awk '{print $1}' | head -1)
if [ "$IP" = "0.0.0.0" ] || [ "$IP" = "::" ] || [ -z "$IP" ]; then
  row "resolve-denied-domain" BLOCKED BLOCKED hosts "exact names only, no wildcards"; PASS=$((PASS+1))
else row "resolve-denied-domain" BLOCKED "$IP" hosts "check hosts block"; FAIL=$((FAIL+1)); fi

# 3 alternate public DNS
if command -v dig >/dev/null && ! dig +time=3 +tries=1 @8.8.8.8 example.com >/dev/null 2>&1; then
  row "alt-public-dns" BLOCKED BLOCKED nftables "LAN/RFC1918 resolver still allowed"; PASS=$((PASS+1))
else row "alt-public-dns" BLOCKED ALLOWED nftables "nft may be unsupported; or upstream is public"; INFO=$((INFO+1)); fi

# 4 DoT
if command -v nc >/dev/null && ! timeout 4 nc -z 1.1.1.1 853 2>/dev/null; then
  row "dns-over-tls-853" BLOCKED BLOCKED nftables "-"; PASS=$((PASS+1))
else row "dns-over-tls-853" BLOCKED ALLOWED nftables "verify nft table present"; INFO=$((INFO+1)); fi

# 5 DoH to known resolver
if blocked "https://1.1.1.1/dns-query?name=chatgpt.com"; then
  row "doh-known-resolver" BLOCKED BLOCKED nftables "unknown/self-hosted DoH = open"; PASS=$((PASS+1))
else row "doh-known-resolver" BLOCKED ALLOWED nftables "unknown/self-hosted DoH = open"; INFO=$((INFO+1)); fi

# 6 python request to denied API
if command -v python3 >/dev/null; then
  if ! python3 - <<'PY' 2>/dev/null
import socket; socket.setdefaulttimeout(5)
socket.create_connection(("api.openai.com",443))
PY
  then row "python-denied-api" BLOCKED BLOCKED hosts "unlisted mirror = open"; PASS=$((PASS+1))
  else row "python-denied-api" BLOCKED ALLOWED hosts "unlisted mirror = open"; FAIL=$((FAIL+1)); fi
fi

# 7 direct IP (documented OPEN by default)
row "direct-ip-connection" OPEN OPEN none "resolve_and_block_ips off (CDN collateral)"; INFO=$((INFO+1))

# 8 ollama runtime detection
if intern-ai-guard status 2>/dev/null | grep -qi 'AI runtimes:.*NONE'; then
  row "ollama-detection" DETECT "none-now" applications "detects if installed; offline model = open"; INFO=$((INFO+1))
else row "ollama-detection" DETECT DETECTED applications "offline model still runs"; PASS=$((PASS+1)); fi

# 9 service present
if systemctl is-enabled intern-ai-guard.timer >/dev/null 2>&1; then
  row "timer-enabled" ENABLED ENABLED compliance "root can disable — visible in logs"; PASS=$((PASS+1))
else row "timer-enabled" ENABLED DISABLED compliance "root disabled it (or --no-systemd)"; INFO=$((INFO+1)); fi

# 10 nft table integrity
if nft list table inet intern_ai_guard >/dev/null 2>&1; then
  row "nft-table-present" PRESENT PRESENT nftables "repaired each cycle"; PASS=$((PASS+1))
else row "nft-table-present" PRESENT MISSING nftables "nft unsupported or drift"; INFO=$((INFO+1)); fi

echo "--- pass:$PASS fail:$FAIL info/best-effort:$INFO ---"
echo "See docs/BYPASS_ANALYSIS.md for the full expected-vs-actual matrix incl. VPN/proxy/personal-device gaps."
[ $FAIL -eq 0 ]
