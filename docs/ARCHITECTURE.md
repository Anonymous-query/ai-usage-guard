# Architecture

## Design constraints (from requirements)

1. The laptop user **remains root-capable**. Enforcement is therefore *practical*
   (multiple independent layers + drift repair + audit trail), never *absolute*.
2. Blocklist-only: everything not explicitly denied must keep working.
3. Transparent: no hiding, no persistence tricks, `systemctl status` shows everything.
4. Deployed as a package: clone → `sudo ./install.sh` → delete the clone.

## Layer diagram

```
                       Ubuntu Laptop
                            |
       +--------------------+--------------------+
       |                    |                    |
  Network Layer       Application Layer     Browser / IDE
       |                    |                    |
  /etc/hosts block     AI CLI detection     Firefox policy
  nftables (own        AI runtime           Chromium-family policy
    table only)          detection          AI extension blocklist
  DNS-escape blocks    process scan         VS Code extension
  (public 53/DoT/DoH)  optional terminate     detection / removal
       |                    |                    |
       +--------------------+--------------------+
                            |
                      Policy Engine  ←  /etc/intern-ai-guard/policy.yaml
                            |              + config/*.txt lists
                   intern-ai-guard.service (oneshot)
                   intern-ai-guard.timer   (15 min, randomized)
                            |
                    journald + state.json  →  `intern-ai-guard status`
```

## Ubuntu technology comparison (what we chose and why)

| Need | Options considered | Chosen | Why |
|---|---|---|---|
| Domain blocking | dnsmasq/unbound local resolver; systemd-resolved; /etc/hosts | **/etc/hosts managed block** | resolved has no per-domain deny; swapping the resolver stack (dnsmasq) violates "never blindly overwrite existing DNS config" and breaks NetworkManager setups. hosts is universal, reversible, marker-delimited. Wildcard gap documented and mitigated by the browser layer (which does wildcard-match) and nftables DNS-escape rules. |
| Firewall | ufw; iptables-legacy; nftables | **nftables, own table `inet intern_ai_guard`** | Native on all modern Ubuntu; a dedicated table means we never touch, flush, or conflict with ufw/user rules (ufw rules live in their own tables). |
| DNS-bypass control | resolved DNSOverTLS pinning; firewall | **firewall** (drop public :53, :853, known DoH IPs) + browser policy DoH=off | Works regardless of which resolver the machine uses; auto-whitelists currently configured upstreams at apply time. |
| Browser policy | per-user prefs; enterprise policy dirs | **enterprise policy dirs in /etc** | Applies to every profile incl. incognito; deb and snap builds both read them. |
| VS Code | marketplace block; extensions.allowed; scan+remove | **scan + report/remove of listed IDs** | Blocking the marketplace would break normal extension installs (requirement: VS Code must stay usable). `extensions.allowed` has no enforced policy channel on Linux. Copilot-class extensions also die at the network layer (their API hosts are in denied-domains; Node's getaddrinfo honors /etc/hosts). |
| Scheduling | cron; systemd timer | **systemd timer** | journald integration, `Persistent=true`, randomized delay, visible via systemctl. |
| Config mgmt | Ansible pull; plain files | **plain files + idempotent apply** | Single-machine package per requirement; every apply is a full converge, so the timer is the drift repairer. Future central pull hooks in `updater.py`. |

## Component map (improved from the spec's layout)

```
src/intern_ai_guard/
  policy.py         load + validate policy.yaml, parse categorized list files, hash for change detection
  network.py        hosts block render/apply/check, nftables ruleset render/apply/check, upstream-DNS discovery
  applications.py   filesystem/dpkg/snap/desktop-file/process scans; report or terminate
  browsers.py       Firefox + Chromium-family policy generation; installed-browser inventory
  vscode.py         per-user extension scan against denied IDs; report or remove
  compliance.py     runs all checks, repairs drift, writes state.json, renders `status`
  guardlog.py       journald/syslog-aware structured logging  (renamed from spec's `logging/` — that
                    package name would shadow the Python stdlib module)
  updater.py        v2 central-policy stub (interface + versioning only)
  cli.py            argparse: status | apply | check | show-policy | version
```
A single Python package (stdlib + python3-yaml only) installed to
`/usr/local/lib/intern-ai-guard/`, entry point `/usr/local/bin/intern-ai-guard`.

## Installation design

`install.sh`: detect (os-release, arch, systemd as PID 1, python3, python3-yaml, nft,
NetworkManager, ufw presence, current DNS upstreams) → back up every file it will touch
to `/var/lib/intern-ai-guard/backups/<ts>/` → copy package/config/units → first
`apply` → enable timer. Any failure triggers the rollback trap (restore backups, remove
installed files). Meaningful exit codes: 0 ok, 1 precondition, 2 apply failed (rolled back).

`uninstall.sh` / installed copy: stop+disable units, delete only table `inet
intern_ai_guard` (never `nft flush ruleset`), remove only the hosts marker block, remove
only our named policy files, restore the original backups where the file had pre-existed,
remove our directories. Never touches ufw, resolved config, or user data.

## Testing strategy

1. **Unit (pytest, no root)**: policy validation, list parsing, hosts/nft rendering,
   detection matchers, status formatting, script syntax.
2. **End-to-end (privileged container)**: real `install.sh` → `status` → bypass suite →
   normal-development regression suite → `uninstall.sh` → cleanliness check.
   Container caveats (no systemd PID 1, no journald) exercise the installer's degraded paths.
3. **Bypass suite** (`tests/bypass-tests.sh`) and **regression suite**
   (`tests/regression-tests.sh`) are shipped so the company can re-run them on real laptops.
