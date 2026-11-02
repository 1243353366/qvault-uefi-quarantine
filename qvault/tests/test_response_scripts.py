"""The endpoint response tools: tested where they can be tested, and honest where they cannot.

The Linux twin runs end to end here - a decoy implant is planted, suspended, quarantined and restored.
The PowerShell script cannot execute on this host, so it is parsed by a real PowerShell parser and its
two load-bearing functions are executed out of the shipped file; the rest of it is reviewed, not run.
That distinction is the point of this module.
"""
from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
BASH = REPO / "response" / "crush-klog.sh"
PS1 = REPO / "response" / "Crush-Klog.ps1"
HARNESS = REPO / "qvault" / "tests" / "support" / "run_ps_function.ps1"


def _pwsh():
    for candidate in (os.environ.get("QVAULT_PWSH"), shutil.which("pwsh"),
                      shutil.which("powershell"), "/tmp/pwsh/pwsh"):
        if candidate and Path(candidate).exists():
            return candidate
    return None


PWSH = _pwsh()
posix_only = pytest.mark.skipif(sys.platform != "linux", reason="process control differs per platform")
need_pwsh = pytest.mark.skipif(PWSH is None, reason="no PowerShell here; script is parsed, not run")


# ---------------------------------------------------------------- shipped invariants

def test_the_dry_run_is_the_default():
    text = BASH.read_text()
    assert "APPLY=0" in text
    assert text.index("if [[ $APPLY -eq 0 ]]") < text.index("kill -STOP"), \
        "the dry-run exit must come before any suspension"


def test_neither_script_deletes_anything():
    for path in (BASH, PS1):
        text = path.read_text()
        assert "rm -rf" not in text
        assert "Remove-Item -Recurse" not in text
        assert "Remove-Item -LiteralPath" not in text
    # PowerShell's only mutation removals are a registry value, a task registration and a firewall
    # rule - all reversible, all recorded.


def test_linux_refuses_to_rename_a_system_directory():
    text = BASH.read_text()
    assert "/usr/bin" in text and "REFUSE" in text.upper()
    assert "is a system directory" in text


def test_powershell_refuses_system_and_shared_directories():
    text = PS1.read_text()
    assert "$protected -contains" in text
    assert "REFUSED to rename" in text


def test_both_generate_a_restore_path():
    assert "RESTORE.sh" in BASH.read_text()
    assert "RESTORE.ps1" in PS1.read_text()


def test_time_warp_is_refused_rather_than_implemented():
    text = PS1.read_text()
    assert "REFUSED: -TimeWarp is not implemented" in text
    assert "Set-Date" not in text, "skewing the clock destroys the timeline the run is meant to keep"
    assert "Set-Date" not in BASH.read_text()


def test_both_record_hashes_for_the_chain_of_custody():
    assert "sha256sum" in BASH.read_text() and "MANIFEST.sha256" in BASH.read_text()
    assert "Get-FileHash" in PS1.read_text() and "MANIFEST.sha256" in PS1.read_text()


def test_both_capture_evidence_before_mutating():
    bash = BASH.read_text()
    assert bash.index("== evidence ==") < bash.index("[1] suspending")
    ps1 = PS1.read_text()
    assert ps1.index("== Evidence ==") < ps1.index("[1] Suspending")


# ---------------------------------------------------------------- PowerShell, parsed and executed

def _call_ps_function(name, params):
    out = subprocess.run([PWSH, "-NoProfile", "-File", str(HARNESS), "-ScriptPath", str(PS1),
                          "-FunctionName", name, "-ParamsJson", json.dumps(params)],
                         capture_output=True, text=True, timeout=90)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout.strip())


@need_pwsh
def test_the_powershell_script_parses():
    out = subprocess.run([PWSH, "-NoProfile", "-Command",
                          f'$e=$null; $null=[System.Management.Automation.Language.Parser]::ParseFile("{PS1}",'
                          '[ref]$null,[ref]$e); if($e){$e[0].Message}else{"PARSE OK"}'],
                         capture_output=True, text=True, timeout=90)
    assert "PARSE OK" in out.stdout


@need_pwsh
def test_powershell_suspends_children_before_parents():
    order = _call_ps_function("Get-OrderedTree",
                              {"Edges": {"1": [2, 3], "2": [4], "4": [5]}, "Roots": [1]})
    assert order[-1] == 1, "the root must be suspended last"
    for child, parent in ((2, 1), (3, 1), (4, 2), (5, 4)):
        assert order.index(child) < order.index(parent), f"{child} must precede its parent {parent}"
    assert sorted(order) == [1, 2, 3, 4, 5]


@need_pwsh
def test_powershell_name_matching_is_a_whole_word():
    script = "/opt/klog/klog.sh"
    leaf = "klog.sh"
    assert _call_ps_function("Test-PathHit",
                             {"Value": f"ExecStart={script} --verbose", "Paths": [script], "Leafs": [leaf]}) is True
    # the two false positives that the loose matcher produced: an interpreter path and a name that
    # merely contains the substring
    assert _call_ps_function("Test-PathHit",
                             {"Value": "ExecStart=/bin/bash", "Paths": [script], "Leafs": [leaf]}) is False
    assert _call_ps_function("Test-PathHit",
                             {"Value": "ExecStart=/usr/bin/myklog.shx", "Paths": [script], "Leafs": [leaf]}) is False


# ---------------------------------------------------------------- Linux, end to end

@posix_only
def _plant(tmp_path):
    app = tmp_path / "app"
    app.mkdir()
    exe = app / "klog.sh"
    exe.write_text("#!/usr/bin/env bash\nwhile :; do sleep 1; done\n")
    exe.chmod(0o755)
    home = tmp_path / "home"
    (home / ".config" / "autostart").mkdir(parents=True)
    (home / ".config" / "autostart" / "klog.desktop").write_text(f"[Desktop Entry]\nExec={exe}\n")
    # start_new_session, not an external setsid: setsid forks and exits, so the pid we would hold is
    # a zombie rather than the decoy.
    proc = subprocess.Popen([str(exe)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)
    time.sleep(1.2)
    return exe, home, proc


@posix_only
def _state(pid):
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
    except FileNotFoundError:
        return "gone"
    return stat.split(")")[1].split()[0]


@posix_only
def test_dry_run_changes_nothing(tmp_path):
    exe, home, proc = _plant(tmp_path)
    try:
        out = subprocess.run([str(BASH), str(exe)], capture_output=True, text=True, timeout=120,
                             env={**os.environ, "HOME": str(home)})
        assert "DRY RUN complete" in out.stdout
        assert exe.exists() and (home / ".config" / "autostart" / "klog.desktop").exists()
        assert _state(proc.pid) in ("S", "R"), "a dry run must not suspend anything"
        assert not list(home.glob("klog-crush-*/MANIFEST.sha256")), \
            "a dry run writes a report but never a manifest of applied changes"
    finally:
        os.kill(proc.pid, signal.SIGKILL)


@posix_only
def test_apply_suspends_quarantines_and_restore_undoes_it(tmp_path):
    exe, home, proc = _plant(tmp_path)
    app = exe.parent
    try:
        out = subprocess.run([str(BASH), str(exe), "--apply"], capture_output=True, text=True,
                             timeout=180, env={**os.environ, "HOME": str(home)})
        run_dirs = sorted(home.glob("klog-crush-*"))
        assert run_dirs, out.stdout + out.stderr
        run = run_dirs[-1]
        assert _state(proc.pid) == "T", "the decoy must still be frozen"
        assert not app.exists() and (app.parent / "app.quarantined").exists()
        assert not (home / ".config" / "autostart" / "klog.desktop").exists()
        assert (run / "RESTORE.sh").exists() and (run / "MANIFEST.sha256").exists()
        assert "note: pid" in out.stdout, "the interpreter should be called out, not silently used"

        subprocess.run([str(run / "RESTORE.sh")], capture_output=True, text=True, timeout=180,
                       env={**os.environ, "HOME": "/root"})   # a different operator
        assert app.exists(), "the directory must come back"
        assert (home / ".config" / "autostart" / "klog.desktop").exists(), \
            "restore must use the recorded path, not the restoring user's HOME"
        assert _state(proc.pid) in ("S", "R"), "restore must resume the process"
    finally:
        os.kill(proc.pid, signal.SIGKILL)
