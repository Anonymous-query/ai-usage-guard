"""Structured logging: stderr (journald captures it under systemd) + syslog for CLI runs.

Never logs page contents, credentials, keystrokes, or documents — only policy
events, deny-list matches, file paths of detected AI software, and counters.
"""
import logging
import logging.handlers
import sys

# A flaky syslog socket must never dump handler tracebacks at the admin.
logging.raiseExceptions = False

_LOGGER = None


def get_logger(level: str = "info") -> logging.Logger:
    global _LOGGER
    if _LOGGER is not None:
        return _LOGGER
    lg = logging.getLogger("intern-ai-guard")
    lg.setLevel(getattr(logging, level.upper(), logging.INFO))
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    lg.addHandler(h)
    try:  # journal/syslog record for interactive runs; fail-soft (containers etc.)
        sh = logging.handlers.SysLogHandler(address="/dev/log")
        sh.setFormatter(logging.Formatter("intern-ai-guard: %(levelname)s %(message)s"))
        # Probe: only keep it if it can actually emit (a bound socket with no
        # consumer passes construction but fails emit — skip it then).
        sh.emit(logging.LogRecord("intern-ai-guard", logging.DEBUG, __file__, 0,
                                  "syslog probe", None, None))
        lg.addHandler(sh)
    except (OSError, RuntimeError):
        pass
    _LOGGER = lg
    return lg


def event(lg: logging.Logger, name: str, level: str = "info", **fields):
    """Emit `event=<name> k=v ...` — grep-able in journalctl."""
    parts = [f"event={name}"] + [f"{k}={v}" for k, v in fields.items()]
    getattr(lg, level)(" ".join(parts))
