# Troubleshooting

**A legitimate site broke after install**
Most likely a deny-list overreach or (if you enabled `resolve_and_block_ips`) CDN
collateral. Check: `journalctl -u intern-ai-guard | tail`, then remove the domain from
`/etc/intern-ai-guard/denied-domains.txt` (or add an exception to `allowed-domains.txt`)
and run `sudo intern-ai-guard apply`.

**DNS stopped working entirely**
`sudo nft list table inet intern_ai_guard` — check the `dns_upstreams` set contains your
resolver. If your network uses a *public* DNS server configured after install, re-run
`sudo intern-ai-guard apply` (it re-discovers upstreams). Worst case:
`sudo nft delete table inet intern_ai_guard` restores full connectivity instantly.

**Status says DRIFT every run**
Something is re-writing a managed file (another config tool?). `journalctl -u
intern-ai-guard | grep drift` shows which layer. 

**VS Code extension keeps coming back**
`vscode.enforce: remove` only removes on service runs; the user can reinstall in between.
That reinstall is logged each cycle — decide via HR, not more tooling.

**Firefox/Chrome not blocking**
Verify the browser actually loaded the policy: `about:policies` (Firefox) or
`chrome://policy`. Snap browsers need a restart after first install.

**Service failed**
`journalctl -u intern-ai-guard -n 50`. Policy syntax errors are refused with the line
number; the previous enforcement state stays active (nothing is torn down on a bad policy).

**Emergency full removal**
`sudo /usr/local/lib/intern-ai-guard/uninstall.sh` (or from a fresh clone). Restores
backed-up originals, removes only our rules/files.
