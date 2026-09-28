# Bypass analysis — the honest table

Legend: **Blocked** = stopped by an enforcement layer · **Detected** = allowed to
happen but visible in logs/status · **Open** = neither, by design or by limitation.
"Actual" column is filled from the automated suite (`tests/bypass-tests.sh`);
container results noted, re-run on a real laptop for full fidelity.

| # | Attempt | Expected | Layer | Known limitation |
|---|---|---|---|---|
| 1 | Edit /etc/hosts (remove block) | Repaired ≤ timer interval; drift logged | compliance/auto-repair | Root can re-edit forever; each repair is logged |
| 2 | `resolvectl`/NM DNS change to 8.8.8.8 | Blocked (public :53 dropped) | nftables | Pre-existing public upstreams are whitelisted at apply time |
| 3 | `dig chatgpt.com @9.9.9.9` | Blocked | nftables | LAN resolver (RFC1918) stays allowed — a home router resolves anything; hosts layer still covers listed names |
| 4 | Browser DoH | Blocked (policy DoH=off, locked) + known DoH IPs dropped | browser policy + nftables | Unknown/self-hosted DoH server = Open |
| 5 | DoT (:853) | Blocked | nftables | — |
| 6 | Direct IPv4 to AI endpoint | Open (default) | — | `resolve_and_block_ips` exists but is off: CDN collateral. Documented trade-off |
| 7 | IPv6 paths | Same as IPv4 (rules mirrored) | nftables | Same direct-IP gap |
| 8 | `curl https://<ip>` with Host header | Open | — | Needs SNI-filtering proxy (network-side, v2+) |
| 9 | Install another browser (deb/official) | Partially blocked: Chromium forks read /etc policy dirs; others Detected | browser policy + app scan | Non-Chromium/Firefox browser with no policy support = Open at browser layer; hosts+nft still apply |
| 10 | AppImage browser/app | Detected (name/desktop-file scan) | applications | Renamed binary evades name match; hosts+nft still apply to its traffic |
| 11 | Snap AI app | Detected (`snap list` scan) | applications | — |
| 12 | Flatpak AI app | Detected if flatpak present (scan) | applications | — |
| 13 | Python `requests` to AI API | Blocked for listed hosts (getaddrinfo honors hosts + DNS layer) | hosts + nftables | Unlisted mirrors/proxies = Open |
| 14 | Node fetch to AI API | Same as 13 | hosts + nftables | Same |
| 15 | AI CLI (claude/aider/…) | Blocked (API hosts listed) + Detected (name scan) | hosts + applications | New tool with unlisted API host = Detected-only until list updated |
| 16 | Ollama | Detected (binary, service, ~/.ollama); model pulls Blocked (registry hosts listed); optional terminate | applications + hosts | Already-downloaded model runs fully offline = Open (logged) |
| 17 | LM Studio | Detected (AppImage/dirs); download hosts listed | applications + hosts | Same offline gap |
| 18 | Local model via llama.cpp | Detected (binary names) | applications | Compiled-from-source with custom name = Open |
| 19 | VS Code AI extension | Detected; removed if `enforce: remove`; API hosts Blocked | vscode + hosts | Marketplace itself stays open by design (normal dev) |
| 20 | HTTP/SOCKS proxy to reach AI | Open | — | Local tool cannot see inside proxy tunnels; network-side control needed |
| 21 | VPN | Open (VPN tunnels bypass local DNS+hosts; nft sees only encrypted tunnel) | — | Blocking all VPNs would break legitimate use; Detected only if VPN client name is on deny list |
| 22 | `systemctl stop intern-ai-guard.timer` | Detected (status shows stale last-run + disabled units) | compliance | No auto-respawn by design; root can disable — visible, logged gap |
| 23 | Edit policy.yaml / config lists | Detected (policy hash change logged); invalid file → last-known-good refused + logged | policy engine | Root can legitimately edit — that's also how the company administers it |
| 24 | Delete nft table | Repaired ≤ timer interval; drift logged | compliance/auto-repair | Same as #1 |
| 25 | Phone on mobile data / personal device | Open | — | Out of scope for any endpoint tool; pair with review-time verification |

## Summary
Strong against: convenience use, browser use, stock AI tools, DNS trickery, drive-by
extension installs. Weak against: determined root user, VPN/proxy tunnels, direct-IP,
renamed binaries, pre-downloaded offline models, personal devices. Those weaknesses are
inherent to "user keeps root" and are compensated by logging + periodic human review.
