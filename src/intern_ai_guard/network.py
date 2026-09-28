"""Network layer: managed /etc/hosts block + nftables table `inet intern_ai_guard`.

Strengths/limits (see docs/BYPASS_ANALYSIS.md):
- hosts: universal (glibc getaddrinfo → curl, python, node, IDEs), but exact
  names only (www. auto-added for 2-label domains). No wildcards.
- nftables: closes the DNS escape hatches (public :53, DoT, known DoH IPs).
  Own table only — never touches ufw or other rulesets.
- Direct-IP / VPN / proxy traffic is NOT blocked in v1 (documented).
"""
import ipaddress
import json
import os
import re
import socket
import subprocess
import tempfile

HOSTS_BEGIN = "# >>> intern-ai-guard BEGIN (managed block — do not edit; edits are repaired and logged)"
HOSTS_END = "# <<< intern-ai-guard END"
NFT_TABLE = "inet intern_ai_guard"

PRIVATE_V4 = "{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16 }"
PRIVATE_V6 = "{ fc00::/7, fe80::/10, ::1 }"

# Well-known public DoH/DoT resolver anycast IPs (blocking :443/:853 to these
# breaks nothing else — they serve only DNS).
DOH_V4 = ["8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "149.112.112.112",
          "94.140.14.14", "94.140.15.15", "208.67.222.222", "208.67.220.220"]
DOH_V6 = ["2001:4860:4860::8888", "2001:4860:4860::8844", "2606:4700:4700::1111",
          "2606:4700:4700::1001", "2620:fe::fe", "2620:fe::9"]


# ── /etc/hosts layer ─────────────────────────────────────────────────────────

def render_hosts_block(domains):
    lines = [HOSTS_BEGIN]
    seen = set()
    for d in domains:
        expand = [d]
        if d.count(".") == 1 and not d.startswith("www."):
            expand.append("www." + d)
        for name in expand:
            if name in seen:
                continue
            seen.add(name)
            lines.append(f"0.0.0.0 {name}")
            lines.append(f":: {name}")
    lines.append(HOSTS_END)
    return "\n".join(lines) + "\n"


def _strip_hosts_block(text):
    pattern = re.compile(re.escape(HOSTS_BEGIN) + r".*?" + re.escape(HOSTS_END) + r"\n?", re.S)
    return pattern.sub("", text)


def hosts_apply(domains, path="/etc/hosts"):
    with open(path, encoding="utf-8") as fh:
        current = fh.read()
    block = render_hosts_block(domains)
    desired = _strip_hosts_block(current).rstrip("\n") + "\n\n" + block
    if current == desired:
        return False
    _atomic_write(path, desired)
    return True


def hosts_remove(path="/etc/hosts"):
    with open(path, encoding="utf-8") as fh:
        current = fh.read()
    stripped = _strip_hosts_block(current)
    if stripped != current:
        _atomic_write(path, stripped)
        return True
    return False


def hosts_check(domains, path="/etc/hosts"):
    try:
        with open(path, encoding="utf-8") as fh:
            current = fh.read()
    except OSError as exc:
        return "DRIFT", f"cannot read {path}: {exc}"
    if render_hosts_block(domains).strip() in current:
        return "OK", ""
    return "DRIFT", "managed block missing or modified"


def _atomic_write(path, content):
    # Bind-mounted targets (e.g. /etc/hosts in containers, some managed hosts)
    # cannot be atomically replaced — os.replace swaps the inode but the mount
    # still points at the old one. Detect that and rewrite in place instead.
    if os.path.ismount(path):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return
    d = os.path.dirname(path) or "/"
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".iag-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


# ── DNS upstream discovery (never blindly break the machine's own resolver) ──

def discover_dns_upstreams():
    """IPs the system currently uses for DNS — whitelisted on :53 so we never
    cut off a network whose (possibly public) resolver was already in use."""
    ips = set()
    try:
        out = subprocess.run(["resolvectl", "dns"], capture_output=True, text=True, timeout=10)
        if out.returncode == 0:
            ips.update(re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,})\b", out.stdout))
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        with open("/etc/resolv.conf", encoding="utf-8") as fh:
            for line in fh:
                m = re.match(r"^\s*nameserver\s+(\S+)", line)
                if m:
                    ips.add(m.group(1))
    except OSError:
        pass
    valid = set()
    for ip in ips:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not addr.is_loopback:
            valid.add(str(addr))
    return sorted(valid)


# ── nftables layer ───────────────────────────────────────────────────────────

def resolve_denied_ips(domains, timeout=2):
    """Only used when network.resolve_and_block_ips is true (CDN-collateral risk)."""
    v4, v6 = set(), set()
    socket.setdefaulttimeout(timeout)
    for d in domains:
        try:
            for fam, _, _, _, sockaddr in socket.getaddrinfo(d, 443, proto=socket.IPPROTO_TCP):
                (v4 if fam == socket.AF_INET else v6).add(sockaddr[0])
        except OSError:
            continue
    return sorted(v4), sorted(v6)


def render_nft(cfg, upstreams=None, denied_ips=None):
    net = cfg["network"]
    upstreams = upstreams if upstreams is not None else []
    ups4 = [u for u in upstreams if ":" not in u]
    ups6 = [u for u in upstreams if ":" in u]
    L = []
    add = L.append
    # declare-empty + delete + declare-full = atomic idempotent replace of OUR table only
    add(f"table {NFT_TABLE} {{}}")
    add(f"delete table {NFT_TABLE}")
    add(f"table {NFT_TABLE} {{")
    for c in ("cnt_public_dns", "cnt_dot", "cnt_doh", "cnt_quic", "cnt_denied_ip"):
        add(f"  counter {c} {{}}")
    if net["block_doh_resolvers"]:
        add("  set doh_v4 { type ipv4_addr; elements = { " + ", ".join(DOH_V4) + " } }")
        if net["ipv6"]:
            add("  set doh_v6 { type ipv6_addr; elements = { " + ", ".join(DOH_V6) + " } }")
    if net["resolve_and_block_ips"] and denied_ips:
        v4, v6 = denied_ips
        if v4:
            add("  set ai_v4 { type ipv4_addr; elements = { " + ", ".join(v4) + " } }")
        if v6 and net["ipv6"]:
            add("  set ai_v6 { type ipv6_addr; elements = { " + ", ".join(v6) + " } }")
    add("  chain output {")
    add("    type filter hook output priority 0; policy accept;")
    if net["block_public_dns"]:
        for proto in ("udp", "tcp"):
            add(f'    ip daddr {PRIVATE_V4} {proto} dport 53 accept comment "iag:dns-private"')
            if net["ipv6"]:
                add(f'    ip6 daddr {PRIVATE_V6} {proto} dport 53 accept comment "iag:dns-private6"')
            if ups4:
                add(f'    ip daddr {{ {", ".join(ups4)} }} {proto} dport 53 accept comment "iag:dns-upstream"')
            if ups6 and net["ipv6"]:
                add(f'    ip6 daddr {{ {", ".join(ups6)} }} {proto} dport 53 accept comment "iag:dns-upstream6"')
            add(f'    {proto} dport 53 counter name cnt_public_dns drop comment "iag:public_dns"')
    if net["block_dot"]:
        add('    tcp dport 853 counter name cnt_dot drop comment "iag:dot"')
        add('    udp dport 853 counter name cnt_dot drop comment "iag:dot"')
    if net["block_doh_resolvers"]:
        add('    ip daddr @doh_v4 tcp dport 443 counter name cnt_doh drop comment "iag:doh"')
        add('    ip daddr @doh_v4 udp dport 443 counter name cnt_doh drop comment "iag:doh"')
        if net["ipv6"]:
            add('    ip6 daddr @doh_v6 tcp dport 443 counter name cnt_doh drop comment "iag:doh6"')
            add('    ip6 daddr @doh_v6 udp dport 443 counter name cnt_doh drop comment "iag:doh6"')
    if net["block_quic"]:
        add('    udp dport 443 counter name cnt_quic drop comment "iag:quic"')
    if net["resolve_and_block_ips"] and denied_ips and denied_ips[0]:
        add('    ip daddr @ai_v4 meta l4proto { tcp, udp } th dport { 80, 443 } counter name cnt_denied_ip drop comment "iag:denied_ip"')
        if denied_ips[1] and net["ipv6"]:
            add('    ip6 daddr @ai_v6 meta l4proto { tcp, udp } th dport { 80, 443 } counter name cnt_denied_ip drop comment "iag:denied_ip6"')
    add("  }")
    add("}")
    return "\n".join(L) + "\n"


def nft_available():
    try:
        return subprocess.run(["nft", "--version"], capture_output=True, timeout=10).returncode == 0
    except OSError:
        return False


def nft_apply(ruleset_text):
    res = subprocess.run(["nft", "-f", "-"], input=ruleset_text, text=True,
                         capture_output=True, timeout=30)
    if res.returncode != 0:
        raise RuntimeError(f"nft -f failed: {res.stderr.strip()}")


def nft_remove():
    subprocess.run(["nft", "delete", "table", "inet", "intern_ai_guard"],
                   capture_output=True, text=True, timeout=30)


def nft_check(cfg):
    if not nft_available():
        return "UNSUPPORTED", "nft binary not available"
    res = subprocess.run(["nft", "list", "table", "inet", "intern_ai_guard"],
                         capture_output=True, text=True, timeout=30)
    if res.returncode != 0:
        return "DRIFT", "table inet intern_ai_guard missing"
    live = res.stdout
    expected_markers = []
    net = cfg["network"]
    if net["block_public_dns"]:
        expected_markers.append("iag:public_dns")
    if net["block_dot"]:
        expected_markers.append("iag:dot")
    if net["block_doh_resolvers"]:
        expected_markers.append("iag:doh")
    if net["block_quic"]:
        expected_markers.append("iag:quic")
    missing = [m for m in expected_markers if m not in live]
    if missing:
        return "DRIFT", f"missing rules: {', '.join(missing)}"
    return "OK", ""


def nft_counters():
    """{counter_name: packets} for our table; {} when unavailable."""
    try:
        res = subprocess.run(["nft", "-j", "list", "table", "inet", "intern_ai_guard"],
                             capture_output=True, text=True, timeout=30)
        if res.returncode != 0:
            return {}
        data = json.loads(res.stdout)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return {}
    out = {}
    for item in data.get("nftables", []):
        c = item.get("counter")
        if isinstance(c, dict) and "name" in c:
            out[c["name"]] = c.get("packets", 0)
    return out
