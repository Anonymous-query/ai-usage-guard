"""Application layer: detect (and optionally terminate) AI tools and runtimes.

Detection sources: system bin dirs, /opt, desktop files, dpkg, snap, flatpak,
process table, known runtime data dirs. Name-based matching — a renamed binary
evades it (documented); the network layer still applies to its traffic.
"""
import fnmatch
import os
import pwd
import signal
import subprocess

SYSTEM_BIN_DIRS = ["/usr/local/bin", "/opt", "/snap/bin", "/usr/share/applications"]
USER_REL_DIRS = [".local/bin", "bin", ".npm-global/bin", ".cargo/bin", "Downloads",
                 "Desktop", "Applications", ".local/share/applications"]
# Known AI runtime data dirs (presence = the runtime has been installed/used).
RUNTIME_MARKERS = {
    "ollama": ["~/.ollama", "/usr/share/ollama", "/var/lib/ollama"],
    "lm-studio": ["~/.cache/lm-studio", "~/.lmstudio"],
    "gpt4all": ["~/.local/share/nomic.ai"],
    "jan": ["~/.config/Jan", "~/jan"],
    "cursor": ["~/.config/Cursor", "~/.cursor"],
    "windsurf": ["~/.config/Windsurf", "~/.windsurf"],
    "aider": ["~/.aider"],
    "continue": ["~/.continue"],
}


def human_users():
    out = []
    for p in pwd.getpwall():
        if 1000 <= p.pw_uid < 60000 and os.path.isdir(p.pw_dir) and "nologin" not in p.pw_shell:
            out.append(p)
    return out


def _match(name, patterns):
    n = name.lower()
    return any(fnmatch.fnmatch(n, pat) for pat in patterns)


def scan_filesystem(patterns):
    hits = []
    dirs = list(SYSTEM_BIN_DIRS)
    for u in human_users():
        dirs += [os.path.join(u.pw_dir, rel) for rel in USER_REL_DIRS]
    for d in dirs:
        if not os.path.isdir(d):
            continue
        try:
            with os.scandir(d) as it:
                for entry in it:
                    base = entry.name
                    stem = base[:-8] if base.endswith(".desktop") else base
                    if _match(base, patterns) or _match(stem, patterns):
                        hits.append({"kind": "file", "name": base, "path": entry.path})
        except OSError:
            continue
    return hits


def scan_packages(patterns):
    hits = []
    try:
        res = subprocess.run(["dpkg-query", "-W", "-f", "${Package}\n"],
                             capture_output=True, text=True, timeout=60)
        for name in res.stdout.splitlines():
            if _match(name, patterns):
                hits.append({"kind": "dpkg", "name": name, "path": "dpkg"})
    except (OSError, subprocess.TimeoutExpired):
        pass
    for mgr, cmd, skip in (("snap", ["snap", "list"], 1),
                           ("flatpak", ["flatpak", "list", "--columns=application"], 0)):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if res.returncode != 0:
                continue
            for line in res.stdout.splitlines()[skip:]:
                parts = line.split()
                name = parts[0] if parts else ""
                if name and _match(name, patterns):
                    hits.append({"kind": mgr, "name": name, "path": mgr})
        except (OSError, subprocess.TimeoutExpired):
            continue
    return hits


def scan_processes(proc_patterns):
    hits = []
    self_pid = os.getpid()
    for pid_s in os.listdir("/proc"):
        if not pid_s.isdigit() or int(pid_s) in (1, self_pid):
            continue
        try:
            with open(f"/proc/{pid_s}/comm", encoding="utf-8") as fh:
                comm = fh.read().strip()
            with open(f"/proc/{pid_s}/cmdline", "rb") as fh:
                raw = fh.read().split(b"\0")[0]
            argv0 = os.path.basename(raw.decode(errors="replace")) if raw else ""
        except OSError:
            continue
        if _match(comm, proc_patterns) or (argv0 and _match(argv0, proc_patterns)):
            hits.append({"kind": "process", "name": comm or argv0, "pid": int(pid_s)})
    return hits


def scan_runtime_markers():
    hits = []
    homes = [u.pw_dir for u in human_users()]
    for runtime, paths in RUNTIME_MARKERS.items():
        for p in paths:
            candidates = [p.replace("~", h, 1) for h in homes] if p.startswith("~") else [p]
            for c in candidates:
                if os.path.exists(c):
                    hits.append({"kind": "runtime", "name": runtime, "path": c})
    try:
        res = subprocess.run(["systemctl", "is-active", "ollama"], capture_output=True,
                             text=True, timeout=10)
        if res.stdout.strip() == "active":
            hits.append({"kind": "runtime", "name": "ollama", "path": "systemd unit active"})
    except (OSError, subprocess.TimeoutExpired):
        pass
    return hits


def terminate(process_hits):
    """SIGTERM matching processes (applications.enforce: terminate). Returns killed list."""
    killed = []
    for h in process_hits:
        try:
            os.kill(h["pid"], signal.SIGTERM)
            killed.append(h)
        except (OSError, ProcessLookupError):
            continue
    return killed
