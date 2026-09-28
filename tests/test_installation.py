"""Static installation-artifact tests: shell syntax, unit files, layout. No root."""
import glob
import os
import subprocess

ROOT = os.path.join(os.path.dirname(__file__), "..")


def test_shell_scripts_syntax():
    for script in ["install.sh", "uninstall.sh", "update.sh", "status.sh",
                   "tests/bypass-tests.sh", "tests/regression-tests.sh"]:
        path = os.path.join(ROOT, script)
        r = subprocess.run(["bash", "-n", path], capture_output=True, text=True)
        assert r.returncode == 0, f"{script}: {r.stderr}"


def test_uninstall_never_flushes_ruleset():
    text = open(os.path.join(ROOT, "uninstall.sh")).read()
    assert "flush ruleset" not in text
    assert "delete table inet intern_ai_guard" in text


def test_install_has_rollback_trap():
    text = open(os.path.join(ROOT, "install.sh")).read()
    assert "trap rollback ERR" in text
    assert "exit 1" in text and "exit 2" in text  # meaningful exit codes


def test_service_is_oneshot_no_restart_loop():
    text = open(os.path.join(ROOT, "systemd/intern-ai-guard.service")).read()
    assert "Type=oneshot" in text
    assert "Restart=always" not in text  # no aggressive respawn


def test_service_uses_enforce_entrypoint():
    # The service must call 'enforce' (check+repair+drift audit), not bare 'apply'.
    text = open(os.path.join(ROOT, "systemd/intern-ai-guard.service")).read()
    assert "intern-ai-guard enforce" in text


def test_timer_has_persistent_and_jitter():
    text = open(os.path.join(ROOT, "systemd/intern-ai-guard.timer")).read()
    assert "Persistent=true" in text
    assert "RandomizedDelaySec" in text


def test_required_repo_files_present():
    for f in ["README.md", "LICENSE", "install.sh", "uninstall.sh",
              "policy.yaml.example", "docs/ARCHITECTURE.md", "docs/BYPASS_ANALYSIS.md",
              "docs/SECURITY.md", "docs/TROUBLESHOOTING.md"]:
        assert os.path.exists(os.path.join(ROOT, f)), f"missing {f}"


def test_all_python_modules_parse():
    import ast
    for f in glob.glob(os.path.join(ROOT, "src/intern_ai_guard/*.py")):
        ast.parse(open(f).read(), f)


def test_config_lists_nonempty():
    for f in ["denied-domains.txt", "denied-applications.txt",
              "denied-vscode-extensions.txt"]:
        path = os.path.join(ROOT, "config", f)
        lines = [l for l in open(path).read().splitlines()
                 if l.strip() and not l.strip().startswith("#")]
        assert len(lines) >= 1, f"{f} empty"
