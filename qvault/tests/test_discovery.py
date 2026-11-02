"""Discovery files: a sitemap that lists every page, and robots.txt that tells the truth about itself."""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))

import build_docs as B  # noqa: E402

NS = "{http://www.sitemaps.org/schemas/sitemap/0.9}"


@pytest.fixture(scope="module")
def pages() -> dict[str, str]:
    return B.build()


def test_the_sitemap_lists_every_published_page(pages):
    urls = B.sitemap_urls(pages)
    assert len(urls) == len(pages) + 1, "citations is the +1"
    for slug in pages:
        expected = f"{B.SITE}/" if slug == "index.html" else f"{B.SITE}/{slug[:-5]}"
        assert expected in urls, f"{slug} is missing from the sitemap"


def test_the_sitemap_is_well_formed_and_absolute(pages):
    root = ET.fromstring(B.render_sitemap(pages))
    locs = [el.text for el in root.iter(f"{NS}loc")]
    assert locs, "no <loc> entries"
    for loc in locs:
        assert loc.startswith("https://"), loc
        assert not loc.endswith(".html"), f"{loc} points at a source filename, not a page"


def test_the_sitemap_carries_no_clock(pages):
    """A lastmod would change on every build and make the docs-drift gate meaningless."""
    xml = B.render_sitemap(pages)
    assert "lastmod" not in xml
    assert "priority" not in xml


def test_robots_advertises_the_sitemap(pages):
    robots = B.render_robots()
    assert f"Sitemap: {B.SITE}/sitemap.xml" in robots
    assert "Allow: /" in robots


def test_robots_says_it_is_advisory_at_this_path(pages):
    """Honesty requirement: RFC 9309 has crawlers read the origin root, which is not writable here."""
    robots = B.render_robots()
    assert "advisory" in robots
    assert "RFC 9309" in robots or "origin root" in robots


def test_the_files_are_written_into_the_published_tree(pages):
    built = B.main()
    assert built == 0
    assert (ROOT / "docs" / "sitemap.xml").exists()
    assert (ROOT / "docs" / "robots.txt").exists()
