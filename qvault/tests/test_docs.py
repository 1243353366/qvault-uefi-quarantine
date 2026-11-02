"""The published documentation site, held to the repository.

Every page is a render of a Markdown file here, so a page that disagrees with its source means
the site is claiming something the code does not.
"""
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCS = ROOT / "docs"
sys.path.insert(0, str(ROOT / "tools"))

import build_docs  # noqa: E402


def test_every_declared_page_has_a_source_file():
    for src, _slug, _title, _section in build_docs.PAGES:
        assert (ROOT / src).exists(), src


def test_the_landing_page_exists():
    assert (DOCS / "index.html").exists()


def test_no_build_artefact_directory_is_missing():
    assert (DOCS / ".nojekyll").exists(), "Pages would run Jekyll over the output"


@pytest.mark.parametrize("slug", [p[1] for p in build_docs.PAGES])
def test_each_page_matches_its_markdown_source(slug):
    src = next(s for s, sl, _t, _x in build_docs.PAGES if sl == slug)
    expected = build_docs.render_page(src, slug,
                                     next(t for s, sl, t, _x in build_docs.PAGES if sl == slug))
    on_disk = (DOCS / slug).read_text()
    assert on_disk == expected, f"docs/{slug} is stale; run tools/build_docs.py"


def test_no_page_links_to_a_markdown_file():
    for path in DOCS.glob("*.html"):
        html = path.read_text()
        for href in re.findall(r'href="([^"]+)"', html):
            assert not href.endswith(".md"), f"{path.name} links to {href}"


def test_internal_links_resolve_to_published_pages():
    published = {p.name for p in DOCS.glob("*.html")}
    for path in DOCS.glob("*.html"):
        for href in re.findall(r'href="([^"]+)"', path.read_text()):
            if href.startswith(("http", "#", "mailto:")):
                continue
            target = href.split("#")[0]
            if not target:
                continue
            # GitHub Pages serves a bare slug as <slug>.html, which is what the nav emits
            candidates = {target, f"{target}.html"}
            assert candidates & published, f"{path.name} -> {href}"


def test_the_citations_page_covers_every_bibliography_entry():
    entries = build_docs.bibliography()
    assert len(entries) >= 60
    page = (ROOT / "CITATIONS.md").read_text()
    for entry in entries:
        assert f"| {entry['number']} |" in page, entry["number"]


def test_sources_without_a_link_are_labelled_rather_than_dropped():
    entries = build_docs.bibliography()
    unlinked = [e["number"] for e in entries if not e["url"]]
    page = (ROOT / "CITATIONS.md").read_text()
    for number in unlinked:
        row = next(line for line in page.splitlines() if line.startswith(f"| {number} |"))
        assert "cited by title" in row


def test_code_citations_appear_on_the_citations_page():
    usage = build_docs.cited_by()
    page = (ROOT / "CITATIONS.md").read_text()
    assert "qvault/behaviors.py" in page
    assert "qvault/telemetry.py" in page
    assert "evidence ledger" in page
    assert usage, "the citation index should not be empty"


def test_the_readme_advertises_the_live_site_and_the_right_version():
    readme = (ROOT / "README.md").read_text()
    from qvault import __version__

    assert "1243353366.github.io/qvault-uefi-quarantine" in readme
    assert f"Version {__version__}" in readme


def test_every_published_page_is_navigable_from_every_page():
    for path in DOCS.glob("*.html"):
        html = path.read_text()
        for _src, slug, _title, _section in build_docs.PAGES:
            assert f'href="{slug}"' in html, f"{path.name} does not link to {slug}"


def test_the_everything_page_lists_every_published_page():
    """A page that exists but is not listed on the index is a page nobody finds."""
    import importlib
    gen = importlib.import_module("gen_everything")
    text = (Path(__file__).resolve().parents[2] / "report" / "EVERYTHING.md").read_text()
    for source, slug, title, section in build_docs.PAGES:
        if source == gen.SELF:
            continue
        url = f"{build_docs.SITE}/" if slug == "index.html" else f"{build_docs.SITE}/{slug[:-5]}"
        assert f"[{title}]({url})" in text, f"{title} ({slug}) is published but not listed on the index"
        assert f"`{source}`" in text, f"{source} is published but its source path is not listed"
