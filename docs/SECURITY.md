# Security model & threat model

## What this is
A **transparent company endpoint-policy tool** for company-owned Ubuntu laptops,
deployed with the knowledge of the device users. It is not spyware: no keystroke
capture, no screenshots, no document inspection, no credential access, no hiding
from the user, no exploits. Everything it does is visible via `systemctl`,
`journalctl -u intern-ai-guard`, `nft list table inet intern_ai_guard`, and the
marker block in /etc/hosts.

## Threat model (STRIDE-lite, attacker = the intern user)

| Threat | Response |
|---|---|
| Tampering: edit /etc/hosts, delete nft table, remove policy files | Every timer run re-applies (auto_repair) and logs `drift detected` + `compliance restored`. Root CAN win permanently by uninstalling — see "Root is root". |
| Bypass: alternate DNS, DoH, DoT | nftables drops public :53, :853, known DoH resolver IPs; browsers get DoH=off (locked). |
| Bypass: direct IP, VPN, proxy, unknown mirror sites | **Largely not blocked in v1** — documented honestly in BYPASS_ANALYSIS.md. |
| Bypass: new browser / AppImage / snap | Detected by application scan (denied names), logged; Chromium-family forks still read the /etc policy dirs. Unknown browsers are reported, not blocked. |
| Repudiation: "I never used AI" | journald audit trail: detections, drift, blocked-packet counters, with timestamps. |
| DoS of the guard itself: `systemctl stop/disable` | Detected on next manual `status`; timer disable is visible. No aggressive respawn loop by design (systemd best practice, and hiding/fighting the owner is out of scope). |

## Root is root — read this before trusting the tool

The user keeps administrator rights. Therefore **every control here can be
permanently removed by the user** (`sudo ./uninstall.sh` works for them too, as do
manual deletions). This tool's guarantees are:

1. **Friction** — casual/convenient AI use fails.
2. **Automatic repair** — casual tampering un-does itself within the timer interval.
3. **Evidence** — deliberate tampering leaves a journald/state trail (including the
   gap in logs if the service was stopped): the conversation moves from "did he?"
   to "the log says the guard was disabled Tuesday 14:02".

If the company needs enforcement a local admin cannot remove, that requires
removing admin rights or network-side controls (out of scope of this package;
see the companion `ai-lockdown` design).

## Data handling
Logs contain: domain/extension/process *names* from the deny lists, file paths of
detected AI software, rule counters, timestamps. Logs never contain: page contents,
credentials, tokens, keystrokes, document contents, or browsing history beyond
deny-list matches.
