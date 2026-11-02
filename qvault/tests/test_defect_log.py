"""The defect log is only worth publishing if its own claims stay checkable."""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import tables  # noqa: E402
import gen_defect_log as G  # noqa: E402
from qvault import __version__  # noqa: E402
from qvault import findings as F  # noqa: E402

PAGE = ROOT / "report" / "DEFECT_LOG.md"
PHASES = {"tree", "push", "tag", "publish"}


@pytest.fixture(scope="module")
def text() -> str:
    return PAGE.read_text()


def test_the_page_matches_its_generator(text):
    assert text == tables.align(G.render()), "report/DEFECT_LOG.md is stale"


def test_the_page_names_the_current_version(text):
    assert f"Release **{__version__}**" in text


def test_every_event_is_complete():
    for event in G.EVENTS:
        for field in ("what", "found", "fix", "bought", "cost", "title"):
            assert event[field].strip(), f"{event['key']} has an empty {field}"


def test_every_event_names_an_artefact_that_exists():
    for event in G.EVENTS:
        assert event["artifacts"], f"{event['key']} names no artefact"
        for artifact in event["artifacts"]:
            assert (ROOT / artifact).exists(), f"{event['key']}: {artifact} does not exist"


def test_grades_are_from_the_shared_vocabulary():
    for event in G.EVENTS:
        assert event["bought_grade"] in F.GRADES, event["key"]
        assert event["cost_grade"] in F.GRADES, event["key"]


def test_benefits_are_never_graded_as_observation():
    """A fix preventing its class is a prediction, so the claim about benefit stays INFERRED."""
    for event in G.EVENTS:
        assert event["bought_grade"] != F.CONFIRMED, event["key"]


def test_every_cost_is_graded(text):
    for event in G.EVENTS:
        assert event["cost"] in text
        assert f"({event['cost_grade']})" in text


def test_every_phase_is_a_real_phase():
    for event in G.EVENTS:
        assert event["phase"] in PHASES, event["key"]


def test_the_page_states_the_hidden_defect_asymmetry(text):
    assert "whether a reader would have\nknown" in text or "whether a reader would have" in text
    assert "would have stayed hidden" in text


def test_the_page_does_not_declare_the_class_extinct(text):
    assert "does not claim the project is now free" in text


def test_all_published_reports_link_by_repository_path():
    """A relative .html link resolves on the site and 404s in the repository. D3 in one test."""
    for page in (ROOT / "report").glob("*.md"):
        for target in re.findall(r"\]\(([^)]+)\)", page.read_text()):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            assert not target.endswith(".html"), f"{page.name}: {target} is a site slug"


def test_the_readme_is_transparent_about_the_failures():
    readme = (ROOT / "README.md").read_text()
    assert "report/DEFECT_LOG.md" in readme
    assert "went wrong" in readme.lower()
