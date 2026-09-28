"""VS Code layer: detect (and optionally remove) prohibited AI extensions.

Scans each human user's extension dirs for the denied publisher.name IDs. The
marketplace and unrelated extensions are left fully working. `enforce: remove`
deletes only the matching extension directories; the user (root-capable) can
reinstall — each reinstall is re-detected and logged.
"""
import os
import shutil

import applications  # human_users()

EXT_REL_DIRS = [
    ".vscode/extensions",
    ".vscode-server/extensions",
    ".vscode-oss/extensions",
    ".config/Code/User/extensions",
    ".cursor/extensions",
    ".windsurf/extensions",
]


def _iter_ext_dirs():
    for u in applications.human_users():
        for rel in EXT_REL_DIRS:
            path = os.path.join(u.pw_dir, rel)
            if os.path.isdir(path):
                yield u.pw_name, path


def _dir_matches_id(dirname, denied_ids):
    # Extension dirs are named "publisher.name-<version>"; strip trailing version.
    low = dirname.lower()
    for ext_id in denied_ids:
        if low == ext_id or low.startswith(ext_id + "-"):
            return ext_id
    return None


def scan(denied_ids):
    denied = [e.lower() for e in denied_ids]
    hits = []
    for user, ext_dir in _iter_ext_dirs():
        try:
            entries = os.listdir(ext_dir)
        except OSError:
            continue
        for name in entries:
            matched = _dir_matches_id(name, denied)
            if matched:
                hits.append({"user": user, "id": matched, "path": os.path.join(ext_dir, name)})
    return hits


def remove(hits):
    removed = []
    for h in hits:
        try:
            shutil.rmtree(h["path"])
            removed.append(h)
        except OSError:
            continue
    return removed
