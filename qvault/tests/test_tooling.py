"""The tooling that guards this repository, guarded in turn.

Three failures motivated these tests, and each one was invisible at the time:
  - a gate piped into `tail` reported success while a commit was broken,
  - the README advertised 0.5.0 for six releases because no gate compared it to the code,
  - a CI workflow was gitignored, so "we have CI" was never true.
"""
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import linkcheck  # noqa: E402
import sync_version  # noqa: E402


# --- the hook -----------------------------------------------------------------------------

def test_the_pre_push_hook_exists_and_is_executable():
    hook = ROOT / ".githooks" / "pre-push"
    assert hook.exists()
    assert hook.stat().st_mode & 0o111, "a hook that is not executable does nothing"


def test_the_hook_runs_the_gates_and_uses_pipefail():
    text = (ROOT / ".githooks" / "pre-push").read_text()
    assert "set -euo pipefail" in text
    assert "tools/gates.py" in text
    assert "exit 1" in text


def test_the_installer_sets_the_hooks_path_and_verifies_it():
    text = (ROOT / "tools" / "install_hooks.sh").read_text()
    assert "set -euo pipefail" in text
    assert "core.hooksPath .githooks" in text
    assert "failed to set core.hooksPath" in text


def test_the_hook_refuses_a_push_when_a_gate_fails(tmp_path):
    """Drive the hook for real with a gate that fails, and require a nonzero exit."""
    repo = tmp_path / "repo"
    (repo / ".githooks").mkdir(parents=True)
    (repo / "tools").mkdir()
    hook = (ROOT / ".githooks" / "pre-push").read_text()
    (repo / ".githooks" / "pre-push").write_text(hook)
    (repo / "tools" / "gates.py").write_text(
        "import sys\nprint('FAIL  G1  unit tests  deliberately broken')\nsys.exit(1)\n")
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    result = subprocess.run(["bash", ".githooks/pre-push"], cwd=repo,
                            capture_output=True, text=True)
    assert result.returncode != 0, "the hook must not let a failed gate through"
    assert "gates failed" in result.stdout


# --- version single-sourcing --------------------------------------------------------------

def test_the_version_check_passes_on_the_tree():
    assert sync_version.check() == 0


def test_drift_is_detected(monkeypatch, tmp_path):
    """The README at 0.5.0 against a package at 0.13.0 must fail, not pass quietly."""
    readme = tmp_path / "README.md"
    readme.write_text("**Version 0.5.0** · something\n")
    monkeypatch.setattr(sync_version, "TARGETS", [("README.md", r"\*\*Version (\S+?)\*\*")])
    monkeypatch.setattr(sync_version, "ROOT", tmp_path)
    assert sync_version.source_version() != "0.5.0"
    assert sync_version.claimed() == [("README.md", "0.5.0")]
    with pytest.raises(SystemExit):
        sync_version.claimed.__globals__["TARGETS"].append(("missing.md", "x"))
        sync_version.claimed()


def test_history_is_exempt_and_says_why():
    assert "CHANGELOG.md" in sync_version.EXEMPT
    assert "history" in sync_version.EXEMPT["CHANGELOG.md"]
    assert any(k.startswith("vendor") for k in sync_version.EXEMPT)


def test_packaging_does_not_pin_a_second_version():
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert not re.search(r'^version\s*=\s*["\']', pyproject, re.MULTILINE)
    assert 'attr = "qvault.__version__"' in pyproject


# --- link checking ------------------------------------------------------------------------

def test_internal_links_pass_on_the_published_site():
    assert linkcheck.check_internal() == []


def test_a_dead_relative_link_is_caught(monkeypatch, tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "index.html").write_text('<a href="index">home</a><a href="nope">gone</a>')
    monkeypatch.setattr(linkcheck, "DOCS", docs)
    problems = linkcheck.check_internal()
    assert any("nope" in p for p in problems)


def test_a_stray_markdown_link_is_caught(monkeypatch, tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "index.html").write_text('<a href="index">home</a><a href="report/thing.md">doc</a>')
    monkeypatch.setattr(linkcheck, "DOCS", docs)
    assert any(".md" in p for p in linkcheck.check_internal())


def test_placeholder_urls_are_not_probed():
    """A documented pattern such as <file>/<TimeDateStamp><SizeOfImage> is not a citation."""
    urls = linkcheck.external_urls()
    assert urls, "the sources cite external material"
    assert not any(set("<>{}") & set(u) for u in urls)


def test_policy_blockers_are_named_not_silently_ignored():
    assert "media.defense.gov" in linkcheck.POLICY_BLOCKERS
    source = (ROOT / "tools" / "linkcheck.py").read_text()
    assert "blocked" in source and "BROKEN" in source


# --- CI, and honesty about it -------------------------------------------------------------

def test_the_workflow_exists_and_covers_the_gates():
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "tools/gates.py" in workflow
    assert "tools/linkcheck.py" in workflow
    assert "pipefail" in workflow
    assert "tools/sync_version.py --check" in workflow


def test_the_readme_does_not_advertise_a_workflow_that_does_not_exist():
    readme = (ROOT / "README.md").read_text()
    assert "badge.svg" not in readme, "do not show a CI badge until CI actually runs"
    assert "Gates run locally, not yet in CI" in readme


def test_reproduce_runs_every_gate():
    text = (ROOT / "tools" / "reproduce.sh").read_text()
    assert "set -euo pipefail" in text
    assert "tools/gates.py" in text
