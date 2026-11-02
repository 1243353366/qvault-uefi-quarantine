"""Generate report/EVERYTHING.md: one live link per published page, plus the artefacts that are not pages.

Derived from the page list in `tools/build_docs.py`, which is the same list the builder publishes from,
so this page cannot describe a site that does not exist and cannot miss a page that does. A test fails
if an entry appears in the page list without appearing here.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import build_docs  # noqa: E402  (needs sys.path)

REPO = "https://github.com/1243353366/qvault-uefi-quarantine"
SELF = "report/EVERYTHING.md"


def sections() -> dict[str, list[tuple[str, str, str]]]:
    """Group pages by section, preserving the order the builder publishes them in."""
    grouped: dict[str, list[tuple[str, str, str]]] = {}
    for source, slug, title, section in build_docs.PAGES:
        if source == SELF:
            continue
        url = f"{build_docs.SITE}/" if slug == "index.html" else f"{build_docs.SITE}/{slug[:-5]}"
        grouped.setdefault(section, []).append((title, url, source))
    return grouped


def render() -> str:
    from qvault import __version__

    grouped = sections()
    total = sum(len(v) for v in grouped.values())
    out: list[str] = [
        "# Everything, linked",
        "",
        "Every page this project publishes, in one place. The list is generated from the same table",
        "`tools/build_docs.py` publishes from, so a page that exists is a page that appears here, and a",
        "test fails if that stops being true.",
        "",
        f"{total} pages in {len(grouped)} sections, built from the sources in this repository.",
        "Nothing on the site is written twice: each page is rendered from the Markdown file named beside it.",
        "",
    ]
    for section, pages in grouped.items():
        out += [f"## {section}", "", "| Page | Source |", "| --- | --- |"]
        for title, url, source in pages:
            out.append(f"| [{title}]({url}) | `{source}` |")
        out.append("")

    out += [
        "## Artefacts that are not pages",
        "",
        "| What | Where |",
        "| --- | --- |",
        f"| Source repository | <{REPO}> |",
        f"| Release {__version__} | <{REPO}/releases/tag/v{__version__}> |",
        f"| What changed, and when | <{REPO}/commits/main> |",
        f"| Every claim with its grade and source | <{REPO}/blob/main/report/CLAIMS_LEDGER.csv> |",
        f"| Endpoint response tools | <{REPO}/tree/main/response> |",
        f"| Sitemap | <{build_docs.SITE}/sitemap.xml> |",
        f"| Workflow runs, as GitHub reports them | <{REPO}/actions> |",
        "",
        "## Reading this site without trusting it",
        "",
        "The site is a build product. `tools/build_docs.py` renders it from the Markdown in the repository,",
        "a gate fails the push if the published HTML is stale against those sources, and a second gate",
        "fails if any claim lacks a source or a grade. Where a page and the code disagree, the code is",
        "what runs, and the disagreement is a defect worth reporting.",
        "",
    ]
    return "\n".join(out)


def main() -> None:
    target = ROOT / SELF
    text = render()
    if target.exists() and target.read_text() == text:
        print(f"{SELF} unchanged")
        return
    target.write_text(text)
    print(f"wrote {SELF}")


if __name__ == "__main__":
    main()
