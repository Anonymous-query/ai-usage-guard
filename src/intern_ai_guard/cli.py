"""Command-line entry point: intern-ai-guard {status|apply|check|show-policy|version|uninstall}."""
import argparse
import sys

import compliance
import guardlog
import policy
from constants import __version__

GREEN, RED, YEL, DIM, RST = "\033[32m", "\033[31m", "\033[33m", "\033[2m", "\033[0m"


def _c(text, color):
    return f"{color}{text}{RST}" if sys.stdout.isatty() else text


def _load(args):
    try:
        return policy.load(args.etc)
    except policy.PolicyError as exc:
        print(_c(f"policy error: {exc}", RED), file=sys.stderr)
        sys.exit(1)


def cmd_apply(args):
    cfg = _load(args)
    lg = guardlog.get_logger(cfg["logging"]["level"])
    guardlog.event(lg, "policy_loaded", level="debug", version=cfg["version"])
    compliance.apply(cfg, lg)
    print("applied. run 'intern-ai-guard status' to review.")
    return 0


def cmd_check(args):
    cfg = _load(args)
    lg = guardlog.get_logger(cfg["logging"]["level"])
    layers = compliance.check(cfg, lg)
    drift = False
    for name, (status, detail) in sorted(layers.items()):
        mark = _c(status, GREEN if status == "OK" else YEL)
        print(f"{name:12} {mark}  {detail}")
        drift = drift or status == "DRIFT"
    return 2 if drift else 0


def _fmt_layer(status):
    color = {"OK": GREEN, "DISABLED": DIM, "UNSUPPORTED": DIM}.get(status, RED)
    return _c(status, color)


def cmd_status(args):
    cfg = _load(args)
    lg = guardlog.get_logger(cfg["logging"]["level"])
    live = compliance.check(cfg, lg)          # fresh drift read
    state = compliance.read_state()
    layers = state.get("layers", {})
    det = state.get("detections", {})

    print("Intern AI Guard")
    print("---------------\n")
    active = bool(layers)
    print(f"Status: {_c('ACTIVE' if active else 'NOT APPLIED', GREEN if active else RED)}\n")

    def line(label, key):
        drift = live.get(key, (None, ""))[0] == "DRIFT"
        base = layers.get(key, "NOT APPLIED")
        shown = "DRIFT DETECTED" if drift else base
        print(f"{label:20} {_fmt_layer('DRIFT' if drift else base) if not drift else _c(shown, RED)}")

    line("Network policy:", "hosts")
    line("Firewall policy:", "nftables")
    line("Browser policy:", "browsers")
    print()

    def det_line(label, items):
        if items:
            names = ", ".join(sorted({i.get("name") or i.get("id") for i in items}))
            print(f"{label:20} {_c('DETECTED', RED)}  ({names})")
        else:
            print(f"{label:20} {_c('NONE DETECTED', GREEN)}")

    det_line("AI applications:", det.get("apps", []))
    det_line("AI runtimes:", det.get("runtimes", []))
    det_line("AI extensions:", det.get("vscode", []))
    print()
    print(f"Policy version:      {state.get('policy_version', '?')}")
    print(f"Last compliance:     {state.get('updated', 'never')}")
    counters = state.get("counters", {})
    if counters:
        blocked = sum(counters.values())
        print(f"Blocked packets:     {blocked} {DIM}(DNS-escape attempts since last apply){RST}"
              if sys.stdout.isatty() else f"Blocked packets:     {blocked}")
    return 0


def cmd_show_policy(args):
    cfg = _load(args)
    print(f"version: {cfg['version']}")
    print(f"denied domains (effective): {len(policy.effective_domains(cfg))}")
    for key, lst in cfg["_lists"].items():
        print(f"  {key}: {len(lst)}")
    return 0


def cmd_version(args):
    print(f"intern-ai-guard {__version__}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="intern-ai-guard",
                                description="Transparent AI-usage policy enforcement (company-owned devices).")
    p.add_argument("--etc", default="/etc/intern-ai-guard", help="config directory")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn, help_ in (
        ("status", cmd_status, "show enforcement + detection status"),
        ("apply", cmd_apply, "apply/repair all enforcement layers (root)"),
        ("check", cmd_check, "read-only drift check"),
        ("show-policy", cmd_show_policy, "summarize loaded policy"),
        ("version", cmd_version, "print version"),
    ):
        sp = sub.add_parser(name, help=help_)
        sp.set_defaults(func=fn)
    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
