"""Browser layer: enterprise policy files for Firefox + the Chromium family.

Applies to every profile including private windows; deb and snap builds read the
same /etc paths. Blocklist only (URLBlocklist / WebsiteFilter.Block) plus DoH off
and AI extension IDs blocked. Never sets an allowlist, so normal browsing is
untouched. Policy alone is not sufficient (documented) — it pairs with the
network layer.
"""
import json
import os

CHROMIUM_POLICY_DIRS = [
    "/etc/opt/chrome/policies/managed",
    "/etc/chromium/policies/managed",
    "/etc/chromium-browser/policies/managed",
    "/etc/brave/policies/managed",
    "/etc/opt/edge/policies/managed",
]
FIREFOX_POLICY_DIR = "/etc/firefox/policies"
POLICY_FILENAME = "intern-ai-guard.json"

# Browsers we know how to police via policy files.
POLICY_CAPABLE = {"firefox", "google-chrome", "chromium", "chromium-browser", "brave", "microsoft-edge"}
# Browsers with no supported Linux enterprise-policy channel — detect, don't police.
POLICY_INCAPABLE = {"opera", "vivaldi", "tor-browser", "librewolf", "waterfox", "epiphany", "midori"}


def _atomic_write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".iag-tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
    os.chmod(tmp, 0o644)
    os.replace(tmp, path)


def chromium_policy(domains, blocked_ext_ids):
    return {
        "URLBlocklist": list(domains),
        "DnsOverHttpsMode": "off",
        "BuiltInDnsClientEnabled": False,
        "ExtensionInstallBlocklist": list(blocked_ext_ids) or ["_none_"],
    }


def firefox_policy(domains, blocked_ext_ids):
    # *://*.name/* also matches the bare host under MDN match-pattern semantics.
    block = [f"*://*.{d}/*" for d in domains]
    ext_settings = {"*": {"installation_mode": "allowed"}}  # do NOT block all extensions
    for ext in blocked_ext_ids:
        ext_settings[ext] = {"installation_mode": "blocked"}
    return {
        "policies": {
            "WebsiteFilter": {"Block": block},
            "DNSOverHTTPS": {"Enabled": False, "Locked": True},
            "ExtensionSettings": ext_settings,
        }
    }


def apply(domains, chromium_ext_ids, firefox_ext_ids):
    """Write policy files. Returns True if anything changed."""
    changed = False
    chromium = chromium_policy(domains, chromium_ext_ids)
    for d in CHROMIUM_POLICY_DIRS:
        # Only manage families whose base dir tree can exist; create managed/ dir regardless.
        path = os.path.join(d, POLICY_FILENAME)
        if _differs(path, chromium):
            _atomic_write_json(path, chromium)
            changed = True
    ff = firefox_policy(domains, firefox_ext_ids)
    ff_path = os.path.join(FIREFOX_POLICY_DIR, "policies.json")
    if _differs(ff_path, ff):
        _atomic_write_json(ff_path, ff)
        changed = True
    return changed


def _differs(path, obj):
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh) != obj
    except (OSError, ValueError):
        return True


def check(domains):
    """OK if every managed policy file exists and carries the blocklist."""
    missing = []
    for d in CHROMIUM_POLICY_DIRS:
        path = os.path.join(d, POLICY_FILENAME)
        try:
            with open(path, encoding="utf-8") as fh:
                pol = json.load(fh)
            if set(pol.get("URLBlocklist", [])) != set(domains):
                missing.append(path)
        except (OSError, ValueError):
            missing.append(path)
    ff = os.path.join(FIREFOX_POLICY_DIR, "policies.json")
    if not os.path.exists(ff):
        missing.append(ff)
    if missing:
        return "DRIFT", f"{len(missing)} policy file(s) missing/stale"
    return "OK", ""


def remove():
    for d in CHROMIUM_POLICY_DIRS:
        _rm(os.path.join(d, POLICY_FILENAME))
    _rm(os.path.join(FIREFOX_POLICY_DIR, "policies.json"))


def _rm(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def installed_browsers():
    """Inventory installed browsers, flagging any we cannot police."""
    found, unsupported = [], []
    search = ["/usr/bin", "/usr/local/bin", "/snap/bin"]
    names = POLICY_CAPABLE | POLICY_INCAPABLE
    for d in search:
        if not os.path.isdir(d):
            continue
        try:
            entries = set(os.listdir(d))
        except OSError:
            continue
        for name in names:
            if name in entries:
                found.append(name)
                if name in POLICY_INCAPABLE:
                    unsupported.append(name)
    return sorted(set(found)), sorted(set(unsupported))
