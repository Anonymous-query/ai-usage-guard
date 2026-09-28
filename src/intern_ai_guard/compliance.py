"""Compliance orchestrator: apply enforcement, check drift, repair, render status.

Called by the CLI (`apply`, `check`, `status`) and by the systemd service.
Writes /var/lib/intern-ai-guard/state.json for fast `status` output.
"""
import json
import os
import time

import applications
import browsers
import guardlog
import network
import policy
import vscode
from constants import STATE_DIR

STATE_FILE = os.path.join(STATE_DIR, "state.json")


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


def _write_state(state):
    os.makedirs(STATE_DIR, exist_ok=True)
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(state, fh, indent=2)
    os.replace(tmp, STATE_FILE)


def read_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def detect(cfg):
    """Run all detectors; returns a dict of hit-lists (no enforcement)."""
    app_patterns = [e["value"] for e in cfg["_lists"]["apps_deny"]]
    proc_patterns = [e["value"] for e in cfg["_lists"]["procs_deny"]]
    vscode_ids = [e["value"] for e in cfg["_lists"]["vscode_deny"]]
    return {
        "apps": applications.scan_filesystem(app_patterns) + applications.scan_packages(app_patterns),
        "runtimes": applications.scan_runtime_markers(),
        "processes": applications.scan_processes(proc_patterns),
        "vscode": vscode.scan(vscode_ids),
    }


def apply(cfg, lg, repair=True):
    """Apply/repair every enforcement layer. Returns per-layer status dict."""
    domains = policy.effective_domains(cfg)
    results = {}

    # Network: hosts
    if cfg["network"]["hosts_blocking"]:
        try:
            changed = network.hosts_apply(domains)
            results["hosts"] = "OK"
            if changed:
                guardlog.event(lg, "firewall_rule_changed", layer="hosts", domains=len(domains))
        except OSError as exc:
            results["hosts"] = "ERROR"
            guardlog.event(lg, "compliance_check_failed", level="error", layer="hosts", err=str(exc))
    else:
        network.hosts_remove()
        results["hosts"] = "DISABLED"

    # Network: nftables
    if network.nft_available():
        try:
            upstreams = network.discover_dns_upstreams()
            denied_ips = None
            if cfg["network"]["resolve_and_block_ips"]:
                denied_ips = network.resolve_denied_ips(domains)
            ruleset = network.render_nft(cfg, upstreams=upstreams, denied_ips=denied_ips)
            network.nft_apply(ruleset)
            results["nftables"] = "OK"
        except (RuntimeError, OSError) as exc:
            results["nftables"] = "ERROR"
            guardlog.event(lg, "compliance_check_failed", level="error", layer="nftables", err=str(exc))
    else:
        results["nftables"] = "UNSUPPORTED"

    # Browser policy
    if cfg["browsers"]["manage_policies"]:
        try:
            chromium_ext = [e["value"] for e in cfg["_lists"]["browser_ext_deny"]]
            changed = browsers.apply(domains, chromium_ext, chromium_ext)
            results["browsers"] = "OK"
            if changed:
                guardlog.event(lg, "policy_changed", layer="browsers")
        except OSError as exc:
            results["browsers"] = "ERROR"
            guardlog.event(lg, "compliance_check_failed", level="error", layer="browsers", err=str(exc))
    else:
        results["browsers"] = "DISABLED"

    # Detection + optional active enforcement. Log a detection only the FIRST
    # time it appears (compared to the previous run's state) so a persistent
    # install is not re-logged every cycle — that is what caused log growth.
    prev_sigs = _detection_sigs(read_state().get("detections", {}))
    det = detect(cfg)
    results["_detections"] = det
    for hit in det["runtimes"]:
        if ("runtime", hit["name"], hit["path"]) not in prev_sigs:
            guardlog.event(lg, "ai_runtime_detected", level="warning", tool=hit["name"], path=hit["path"])
    for hit in det["apps"]:
        if ("app", hit["name"], hit["kind"]) not in prev_sigs:
            guardlog.event(lg, "ai_application_detected", level="warning", tool=hit["name"], kind=hit["kind"])

    if cfg["applications"]["enforce"] == "terminate" and det["processes"]:
        killed = applications.terminate(det["processes"])
        for k in killed:
            guardlog.event(lg, "ai_process_terminated", level="warning", tool=k["name"], pid=k["pid"])

    if cfg["vscode"]["enforce"] == "remove" and det["vscode"]:
        removed = vscode.remove(det["vscode"])
        for r in removed:
            guardlog.event(lg, "ai_extension_removed", level="warning", id=r["id"], user=r["user"])
        det["vscode"] = vscode.scan([e["value"] for e in cfg["_lists"]["vscode_deny"]])

    state = {
        "updated": _now(),
        "policy_version": cfg["version"],
        "policy_hash": cfg["_hash"],
        "layers": {k: v for k, v in results.items() if not k.startswith("_")},
        "detections": {
            "apps": det["apps"], "runtimes": det["runtimes"],
            "processes": det["processes"], "vscode": det["vscode"],
        },
        "counters": network.nft_counters(),
    }
    _write_state(state)
    # Routine "all clear" heartbeat is debug-level, so at the default info level a
    # quiet machine writes nothing per cycle — only real events (drift, new
    # detections, repairs, errors) reach the journal.
    guardlog.event(lg, "compliance_check_completed", level="debug",
                   ai_detected=bool(det["apps"] or det["runtimes"] or det["vscode"]))
    return state


def _detection_sigs(detections):
    """Signature set of a state's detections, for first-seen change detection."""
    sigs = set()
    for hit in detections.get("runtimes", []):
        sigs.add(("runtime", hit.get("name"), hit.get("path")))
    for hit in detections.get("apps", []):
        sigs.add(("app", hit.get("name"), hit.get("kind")))
    return sigs


def check(cfg, lg):
    """Read-only drift check across layers. Repairs nothing. Returns status dict."""
    domains = policy.effective_domains(cfg)
    layers = {}
    if cfg["network"]["hosts_blocking"]:
        layers["hosts"] = network.hosts_check(domains)
    if network.nft_available():
        layers["nftables"] = network.nft_check(cfg)
    if cfg["browsers"]["manage_policies"]:
        layers["browsers"] = browsers.check(domains)
    for name, (status, detail) in layers.items():
        if status == "DRIFT":
            guardlog.event(lg, "configuration_drift_detected", level="warning",
                           layer=name, detail=detail)
    return layers


def service_run(cfg, lg):
    """One systemd invocation: check → repair if drift & auto_repair → detect."""
    pre = check(cfg, lg)
    drift = [n for n, (s, _) in pre.items() if s == "DRIFT"]
    if drift and cfg["compliance"]["auto_repair"]:
        guardlog.event(lg, "compliance_repair_started", layers=",".join(drift))
        apply(cfg, lg)
        guardlog.event(lg, "compliance_restored", layers=",".join(drift))
    else:
        apply(cfg, lg)
    return read_state()
