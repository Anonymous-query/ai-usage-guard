# intern-ai-guard

Transparent, blocklist-only AI-usage policy enforcement for **company-owned Ubuntu
laptops**. Multiple independent local layers block/detect AI websites, APIs, CLI
tools, coding assistants, local runtimes, and known browser/VS Code extensions —
while **everything not explicitly denied keeps working normally**.

This is an authorized company endpoint-control tool. It does **not** hide itself,
capture keystrokes/screens, read documents, or use exploits. The device user keeps
administrator rights, so enforcement is **strong-but-practical**: multiple controls,
automatic drift repair, and useful audit logs — not an unbreakable wall. See
[`docs/SECURITY.md`](docs/SECURITY.md) ("Root is root") and
[`docs/BYPASS_ANALYSIS.md`](docs/BYPASS_ANALYSIS.md) for the honest limits.

## Layers

| Layer | Enforcement | Strength | Limit |
|---|---|---|---|
| /etc/hosts | Null-route denied domains (IPv4+IPv6) | Universal (curl/python/node/IDEs) | Exact names, no wildcards |
| nftables (own table) | Drop public :53, DoT :853, known DoH IPs; optional QUIC/denied-IP | Closes DNS escape hatches | Direct-IP/VPN/proxy not covered |
| Browser policy | Firefox + Chromium-family blocklist + DoH off + AI extension IDs | Every profile incl. private | Non-policy browsers detect-only |
| Application scan | Detect AI CLIs/apps/runtimes; optional terminate | Robust multi-source detection | Renamed binaries evade |
| VS Code | Detect/remove denied extension IDs | Marketplace stays usable | User can reinstall (re-logged) |
| Compliance service | 15-min timer: check → repair drift → detect → log | Self-healing + audit trail | Root can disable (visible) |

## Install

```bash
git clone <company-repository> intern-ai-guard
cd intern-ai-guard
sudo ./install.sh          # detects OS/arch/systemd/DNS, backs up, applies, enables timer
cd ..
rm -rf intern-ai-guard     # repo no longer needed — everything lives in /etc, /usr/local, systemd
```

Exit codes: `0` success · `1` precondition failed (nothing changed) · `2` apply
failed (auto-rolled-back). The installer never blindly overwrites an existing
firewall/DNS config or an existing `policy.yaml`.

## Usage

```bash
sudo intern-ai-guard status        # enforcement + detection summary (see below)
sudo intern-ai-guard apply         # re-apply/repair all layers
sudo intern-ai-guard check         # read-only drift check (exit 2 if drift)
sudo intern-ai-guard show-policy    # summarize loaded policy
sudo ./status.sh                   # status + recent journald events
```

Sample `status`:

```
Intern AI Guard
---------------

Status: ACTIVE

Network policy:      OK
Firewall policy:     OK
Browser policy:      OK

AI applications:     NONE DETECTED
AI runtimes:         NONE DETECTED
AI extensions:       NONE DETECTED

Policy version:      1
Last compliance:     2026-09-28 17:00:00
```

## Modify policy

All policy lives in `/etc/intern-ai-guard/`:

- `policy.yaml` — toggles (see [`policy.yaml.example`](policy.yaml.example) for the full schema)
- `denied-domains.txt`, `denied-applications.txt`, `denied-processes.txt`,
  `denied-vscode-extensions.txt`, `denied-browser-extensions.txt` — categorized lists
- `allowed-domains.txt` — exceptions carved out of the deny set (never a full allowlist)

Add/remove entries (one per line, `# [Category]` headers, `# inline comments` ok), then:

```bash
sudo intern-ai-guard apply     # or: sudo ./update.sh
```

The timer re-applies automatically every ~15 min, so manual tampering with
`/etc/hosts` or the nft table self-heals and is logged.

## Logs

```bash
journalctl -u intern-ai-guard              # all events
journalctl -u intern-ai-guard | grep event=ai_runtime_detected
```

Logged events include: `policy_changed`, `firewall_rule_changed`,
`configuration_drift_detected`, `compliance_restored`, `ai_application_detected`,
`ai_runtime_detected`, `ai_process_terminated`, `ai_extension_removed`,
`compliance_check_failed`. Logs contain only policy/deny-list names, paths of
detected AI software, and counters — never page contents, credentials, or keystrokes.

**Disk space:** logging is quiet by design and cannot fill the disk.
- Each event is logged **only when it changes** — a persistent AI install is
  logged once when first seen, not every 15-minute cycle. Routine "all clear"
  runs write nothing at the default log level.
- Logs go to **journald**, which self-caps and rotates automatically (default
  ~10% of disk); the tool never writes an unbounded flat log file.
- `state.json` is overwritten each run (fixed size). Install backups in
  `/var/lib/intern-ai-guard/backups/` are pruned to the **5 most recent**.

For an even smaller footprint, set a journald cap in `/etc/systemd/journald.conf`
(e.g. `SystemMaxUse=200M`) — this is a standard system setting the tool leaves to
you rather than overwriting.

## Testing

```bash
# On any machine (no root) — unit tests:
python3 -m pytest tests/

# On a guarded machine (as root) — behavior suites:
sudo bash tests/bypass-tests.sh        # AI-blocking attempts (see BYPASS_ANALYSIS.md)
sudo bash tests/regression-tests.sh    # confirms git/pip/npm/etc. still work
```

## Uninstall

```bash
sudo intern-ai-guard uninstall         # or: sudo ./uninstall.sh
```

Stops/removes the service+timer, removes our nft table (targeted delete — never a
whole-ruleset wipe), strips our `/etc/hosts` marker block and browser policy files,
removes program files. Never touches ufw, resolved config, or user data. Backups
from install time remain in `/var/lib/intern-ai-guard/backups/` for audit.

## Known limitations (read before deploying)

Not blocked in v1 (documented in [`docs/BYPASS_ANALYSIS.md`](docs/BYPASS_ANALYSIS.md)):
direct-IP connections, VPN/proxy tunnels, unknown AI mirror sites, self-hosted DoH,
renamed binaries, already-downloaded offline models, and — inherently — the user's
personal phone/laptop on mobile data. A root-capable user can also remove the tool
entirely; every such action is visible and logged. Pair this tool with periodic
human review (e.g. live code walkthroughs) for the gaps no endpoint tool can close.

## Future central management

`policy.yaml` reserves a `central:` block and `updater.py` stubs the interface for a
v2 that pulls **signed** policy from a company server, keyed by policy `version`.
Not implemented in v1 (local YAML only).

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the layer diagram, the Ubuntu
technology comparison (why hosts+nftables+policy-files over dnsmasq/ufw/resolver
swaps), the component map, and the installation/testing design.
