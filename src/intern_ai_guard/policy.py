"""Policy engine: load + validate policy.yaml, parse categorized list files.

Fails closed on bad config: a PolicyError leaves existing enforcement untouched.
"""
import hashlib
import os
import re

import yaml

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
CHROME_EXT_RE = re.compile(r"^[a-p]{32}$")

DEFAULTS = {
    "version": 1,
    "network": {
        "hosts_blocking": True,
        "block_public_dns": True,
        "block_dot": True,
        "block_doh_resolvers": True,
        "block_quic": False,
        "resolve_and_block_ips": False,
        "ipv6": True,
    },
    "domains": {"deny_files": ["denied-domains.txt"], "allow_files": ["allowed-domains.txt"]},
    "applications": {
        "enforce": "report",
        "deny_files": ["denied-applications.txt"],
        "process_deny_files": ["denied-processes.txt"],
    },
    "vscode": {"enforce": "report", "deny_files": ["denied-vscode-extensions.txt"]},
    "browsers": {"manage_policies": True, "extension_deny_files": ["denied-browser-extensions.txt"]},
    "compliance": {"auto_repair": True, "interval_minutes": 15},
    "logging": {"level": "info"},
}

ENUMS = {
    ("applications", "enforce"): {"report", "terminate"},
    ("vscode", "enforce"): {"report", "remove"},
}


class PolicyError(Exception):
    pass


def _merge(base, override):
    out = dict(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            out[k] = _merge(base[k], v)
        else:
            out[k] = v
    return out


def parse_list_file(path):
    """Return [{'value':..., 'category':...}]. `# [Name]` lines set the category;
    inline comments after whitespace are stripped; first token is the value."""
    entries, category = [], "uncategorized"
    with open(path, encoding="utf-8") as fh:
        for ln, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            m = re.match(r"^#\s*\[(.+)\]\s*$", line)
            if m:
                category = m.group(1)
                continue
            if line.startswith("#"):
                continue
            # Whole pre-comment text (stripped), lower-cased. Keeping it intact
            # means malformed multi-token lines fail validation instead of being
            # silently truncated to their first token.
            value = line.split("#", 1)[0].strip().lower()
            if value:
                entries.append({"value": value, "category": category, "line": ln})
    return entries


def _validate(cfg):
    v = cfg.get("version")
    if not isinstance(v, int) or v < 1:
        raise PolicyError("policy.yaml: 'version' must be a positive integer")
    for section, key in ENUMS:
        val = cfg.get(section, {}).get(key)
        if val not in ENUMS[(section, key)]:
            raise PolicyError(
                f"policy.yaml: {section}.{key} must be one of {sorted(ENUMS[(section, key)])}, got {val!r}"
            )
    for key, val in cfg.get("network", {}).items():
        if not isinstance(val, bool):
            raise PolicyError(f"policy.yaml: network.{key} must be true/false, got {val!r}")


def load(etc_dir="/etc/intern-ai-guard"):
    """Load and fully resolve policy. Raises PolicyError on any problem."""
    path = os.path.join(etc_dir, "policy.yaml")
    if not os.path.exists(path):
        raise PolicyError(f"{path} not found")
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
        data = yaml.safe_load(raw) or {}
    except yaml.YAMLError as exc:
        raise PolicyError(f"policy.yaml: invalid YAML: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("policy.yaml: top level must be a mapping")
    cfg = _merge(DEFAULTS, data)
    _validate(cfg)

    hasher = hashlib.sha256(raw.encode())

    def load_files(names, kind):
        out = []
        for name in names:
            p = os.path.join(etc_dir, os.path.basename(name))  # no path escape
            if not os.path.exists(p):
                raise PolicyError(f"list file missing: {p}")
            with open(p, "rb") as fh:
                hasher.update(fh.read())
            for e in parse_list_file(p):
                e["source"] = name
                _check_entry(kind, e, name)
                out.append(e)
        return out

    cfg["_lists"] = {
        "domains_deny": load_files(cfg["domains"]["deny_files"], "domain"),
        "domains_allow": load_files(cfg["domains"]["allow_files"], "domain"),
        "apps_deny": load_files(cfg["applications"]["deny_files"], "pattern"),
        "procs_deny": load_files(cfg["applications"]["process_deny_files"], "pattern"),
        "vscode_deny": load_files(cfg["vscode"]["deny_files"], "extension"),
        "browser_ext_deny": load_files(cfg["browsers"]["extension_deny_files"], "chrome_ext"),
    }
    allow = {e["value"] for e in cfg["_lists"]["domains_allow"]}
    cfg["_effective_domains"] = [e for e in cfg["_lists"]["domains_deny"] if e["value"] not in allow]
    cfg["_hash"] = hasher.hexdigest()
    return cfg


def _check_entry(kind, entry, source):
    v = entry["value"]
    if kind == "domain" and not DOMAIN_RE.match(v):
        raise PolicyError(f"{source}:{entry['line']}: invalid domain {v!r}")
    if kind == "chrome_ext" and not CHROME_EXT_RE.match(v):
        raise PolicyError(f"{source}:{entry['line']}: invalid Chrome extension id {v!r}")
    if kind == "extension" and "." not in v:
        raise PolicyError(f"{source}:{entry['line']}: extension id must be publisher.name, got {v!r}")


def effective_domains(cfg):
    return [e["value"] for e in cfg["_effective_domains"]]
