#!/usr/bin/env python3
"""Build the documentation site in docs/ from the Markdown sources.

Every page is a render of a Markdown file in this repository, so the site cannot say
something the repository does not. `test_docs.py` fails if docs/ and the sources disagree.

CITATIONS.md is generated from the report bibliography plus the `source_bib` references in
the code and the evidence ledger, so a cited source that no longer exists is visible.
"""
import csv
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "docs"

#: Where the site is published. Absolute URLs here: a sitemap entry must be absolute to be useful.
SITE = "https://1243353366.github.io/qvault-uefi-quarantine"

#: Pages crawlers should know about, in site order. Derived from PAGES so a new page cannot be
#: published and forgotten; index.html becomes the bare site root.
def sitemap_urls(pages: dict[str, str]) -> list[str]:
    urls = []
    for slug in pages:
        path = "" if slug == "index.html" else slug[:-5]
        urls.append(f"{SITE}/{path}" if path else f"{SITE}/")
    urls.append(f"{SITE}/citations")
    return urls


def render_sitemap(pages: dict[str, str]) -> str:
    """No lastmod and no priority: both would need a clock, and a generated file that changes on
    every build makes the docs-drift gate meaningless."""
    out = ['<?xml version="1.0" encoding="UTF-8"?>\n',
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n']
    for url in sitemap_urls(pages):
        out.append(f"  <url><loc>{url}</loc></url>\n")
    out.append("</urlset>\n")
    return "".join(out)


def render_robots() -> str:
    """Advisory at this path, and the file says so.

    The robots exclusion standard (RFC 9309) has a crawler fetch `/robots.txt` at the host root,
    once per origin. On github.io the origin is shared, so this copy at a project path is not the
    file a crawler reads; the repo owner cannot write the host-root one. It is published anyway so
    the policy travels with the site and the sitemap sits at a stable advertised path.
    """
    return (
        "# Crawlers read /robots.txt at the origin root, not at this project path, so this copy is\n"
        "# advisory. It is published so the policy travels with the site and the sitemap is\n"
        "# discoverable. Everything here may be indexed.\n"
        "User-agent: *\n"
        "Allow: /\n"
        f"Sitemap: {SITE}/sitemap.xml\n"
    )
REPORT = ROOT / "report" / "UEFI_Malware_Deep_Dive_Report.md"

sys.path.insert(0, str(ROOT))

import markdown  # noqa: E402

EXTENSIONS = ["tables", "fenced_code", "toc", "sane_lists", "attr_list"]

PAGES = [
    ("README.md", "index.html", "Overview", "Overview"),
    ("report/UEFI_Malware_Deep_Dive_Report.md", "deep-dive.html",
     "UEFI malware deep dive", "Research"),
    ("report/IN_THE_WILD.md", "in-the-wild.html",
     "Zero-days in the wild", "Research"),
    ("report/THREAT_BEHAVIOR_MATRIX.md", "threat-behavior-matrix.html",
     "Behaviour to control", "Research"),
    ("report/TELEMETRY_MAP.md", "telemetry-map.html", "Telemetry map", "Research"),
    ("report/INPUT_CAPTURE.md", "input-capture.html",
     "Input capture: four tiers", "Analysis"),
    ("report/THREAT_INTEL.md", "threatintel.html",
     "Threat intelligence and disruption", "Analysis"),
    ("report/PERSISTENCE.md", "persistence.html", "Persistence detection", "Controls"),
    ("report/FINGERPRINTS.md", "fingerprints.html", "Family fingerprints", "Research"),
    ("SECURITY.md", "security-policy.html", "Security policy", "Assurance"),
    ("PROVENANCE.md", "provenance.html", "Provenance and verification", "Assurance"),
    ("CONTRIBUTING.md", "contributing.html", "Contributing", "Assurance"),
    ("report/TOOLING_RISK.md", "tooling-risk.html", "Tooling risk", "Assurance"),
    ("report/SECURITY_REPORT.md", "security-report.html",
     "Security report", "Assurance"),
    ("report/ACQUISITION_AND_ANALYSIS.md", "acquisition.html",
     "Acquisition and analysis", "Assurance"),
    ("report/LAN_LAYER.md", "lan-layer.html", "LAN containment", "Controls"),
    ("report/NETOBS_MODULE.md", "netobs.html", "Network observation", "Controls"),
    ("report/DEFECT_LOG.md", "defect-log.html", "Defect log", "Research"),
    ("report/DENIAL_MODEL.md", "denial-model.html", "Denial model", "Controls"),
    ("report/TRUST_MODEL.md", "trust-model.html", "Trust model", "Assurance"),
    ("report/THREAT_MODEL_REVIEW.md", "threat-model-review.html",
     "Threat model review", "Assurance"),
    ("report/ARCHITECTURAL_LIMITATIONS.md", "limitations.html",
     "Architectural limitations", "Assurance"),
    ("report/CAPABILITY_MAP.md", "capability-map.html", "Capability map", "Assurance"),
    ("report/EVIDENCE_POLICY.md", "evidence-policy.html", "Evidence policy", "Assurance"),
    ("report/OPERATING_MODEL.md", "operating-model.html", "Operating model", "Assurance"),
    ("report/REPRODUCE.md", "reproduce.html", "Reproduce the results", "Assurance"),
    ("report/HARDWARE_TEST_QUESTIONS.md", "hardware-questions.html",
     "Hardware test backlog", "Assurance"),
    ("CITATIONS.md", "citations.html", "Citations", "Sources"),
    ("CONTRIBUTORS.md", "contributors.html", "Contributors", "Sources"),
    ("CHANGELOG.md", "changelog.html", "Changelog", "Sources"),
]

SLUG_BY_SOURCE = {src: slug for src, slug, _, _ in PAGES}
SLUG_BY_NAME = {Path(src).name: slug for src, slug, _, _ in PAGES}

CITE_RE = re.compile(r"^(\d+)\.\s+(.*)$")
URL_RE = re.compile(r"https?://\S+")


def version() -> str:
    from qvault import __version__

    return __version__


def bibliography() -> list[dict]:
    """Parse the numbered source list out of the report's bibliography section.

    Entries are irregular by nature: some carry a URL, some are cited by title because the
    publisher blocks automated clients, and indentation varies between the older and newer
    additions. All of them are sources, so none are dropped for lacking a link.
    """
    text = REPORT.read_text()
    section = re.search(r"^## \d+\.\s+Bibliography\s*$(.*?)(?=^## \d+\.\s|\Z)",
                        text, re.MULTILINE | re.DOTALL)
    if not section:
        raise SystemExit("bibliography section not found in the report")

    entries: list[dict] = []
    current = None
    for raw in section.group(1).splitlines():
        numbered = re.match(r"^(\d+)\.\s+(.*)$", raw)
        if numbered:
            if current:
                entries.append(current)
            current = {"number": numbered.group(1), "lines": [numbered.group(2).strip()]}
            continue
        if not raw.strip():
            if current:
                entries.append(current)
                current = None
            continue
        if current and re.match(r"^\s+\S", raw):
            current["lines"].append(raw.strip())
            continue
        # a bold group heading such as **LoJax** ends the entry
        if current:
            entries.append(current)
            current = None
    if current:
        entries.append(current)

    parsed = []
    for entry in entries:
        body = " ".join(entry["lines"])
        found = URL_RE.search(body)
        url = found.group(0).rstrip(".,") if found else ""
        headline = (body[:found.start()] + body[found.end():]).strip() if found else body
        headline = re.sub(r"\s{2,}", " ", headline).strip()
        parsed.append({"number": entry["number"], "headline": headline, "url": url})
    return parsed


def cited_by() -> dict[str, list[str]]:
    """Where each bibliography number is actually used: code, ledger, docs."""
    usage: dict[str, list[str]] = {}
    from qvault import behaviors as B
    from qvault import telemetry as T

    for entry in B.BEHAVIOURS:
        usage.setdefault(entry.source_bib, []).append("`qvault/behaviors.py`")
    for source in T.SOURCES.values():
        usage.setdefault(source.source_bib, []).append("`qvault/telemetry.py`")
    for path in sorted((ROOT / "qvault").glob("*.py")):
        if path.name in ("behaviors.py", "telemetry.py"):
            continue
        for number in re.findall(r'source_bib="(\d+)"', path.read_text()):
            usage.setdefault(number, []).append(f"`qvault/{path.name}`")
    ledger = ROOT / "report" / "CLAIMS_LEDGER.csv"
    if ledger.exists():
        counts: dict[str, int] = {}
        with ledger.open(newline="") as fh:
            for row in csv.DictReader(fh):
                bib = (row.get("bibliography") or "").strip()
                if bib.isdigit():
                    counts[bib] = counts.get(bib, 0) + 1
        for number, count in counts.items():
            usage.setdefault(number, []).append(f"evidence ledger ({count} claims)")
    return usage


def render_citations() -> str:
    entries = bibliography()
    usage = cited_by()
    out = ["# Citations\n",
           "Generated by `tools/build_docs.py` from the bibliography in "
           "`report/UEFI_Malware_Deep_Dive_Report.md` and from the `source_bib` references in "
           "the code and the evidence ledger. `test_docs.py` fails if a cited source is missing "
           "from this page.\n\n",
           f"{len(entries)} sources. Each is cited by number in the reports and by "
           f"`source_bib` in the code, so a claim can be traced back to the document it came "
           f"from.\n\n",
           "| # | Source | Document | Cited by |\n|---|--------|----------|----------|\n"]
    for entry in entries:
        headline = entry["headline"].replace("|", "\\|")
        users = ", ".join(usage.get(entry["number"], [])) or "report bibliography"
        link = f"[link]({entry['url']})" if entry["url"] else "cited by title"
        out.append(f"| {entry['number']} | {headline} | {link} | {users} |\n")
    out.append("\n## How a source is held\n\n")
    out.append("A bibliography entry is not decoration. Where a source makes a factual claim, "
               "the claim appears in `report/CLAIMS_LEDGER.csv` with that bibliography number, "
               "a locator, and a falsifier describing what observation would break it. Gate G3 "
               "fails if a claim has no source.\n")
    return "".join(out)


def rewrite_links(html: str) -> str:
    def repl(match: re.Match) -> str:
        href = match.group(1)
        if href.startswith(("http://", "https://", "#", "mailto:")):
            return match.group(0)
        base, _, anchor = href.partition("#")
        name = Path(base).name
        slug = SLUG_BY_SOURCE.get(base) or SLUG_BY_NAME.get(name)
        if slug:
            return f'href="{slug}{"#" + anchor if anchor else ""}"'
        if "." in Path(base).name:
            # a file that is not published as a page (a CSV, a licence, an unpublished
            # document): link to it in the repository rather than leave a dead relative href
            return f'href="https://github.com/1243353366/qvault-uefi-quarantine/blob/main/{base}"'
        return match.group(0)

    return re.sub(r'href="([^"]+)"', repl, html)


def nav(current: str) -> str:
    items, sections = [], {}
    for src, slug, title, section in PAGES:
        sections.setdefault(section, []).append((slug, title))
    for section, entries in sections.items():
        items.append(f'<p class="nav-section">{section}</p><ul>')
        for slug, title in entries:
            cls = ' class="current"' if slug == current else ""
            items.append(f'<li><a href="{slug}"{cls}>{title}</a></li>')
        items.append("</ul>")
    return "".join(items)


TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · QVault</title>
<style>
:root {{ --bg:#14161a; --panel:#1b1e24; --text:#e7e9ee; --muted:#9aa3b2; --line:#2a2f38;
        --accent:#7fb2f0; --code:#0f1115; }}
@media (prefers-color-scheme: light) {{
  :root {{ --bg:#fbfbfc; --panel:#f2f3f6; --text:#1a1d22; --muted:#5b6472; --line:#dde0e6;
          --accent:#1c5fbf; --code:#f4f5f7; }}
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:var(--bg); color:var(--text);
  font:16px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }}
.layout {{ display:grid; grid-template-columns:250px minmax(0,1fr); min-height:100vh; }}
nav {{ background:var(--panel); border-right:1px solid var(--line); padding:20px 16px;
  position:sticky; top:0; height:100vh; overflow-y:auto; }}
nav .brand {{ font-weight:600; font-size:15px; letter-spacing:.02em; display:block;
  color:var(--text); text-decoration:none; margin-bottom:4px; }}
nav .ver {{ color:var(--muted); font-size:12px; margin:0 0 18px; }}
nav a {{ color:var(--muted); text-decoration:none; }}
nav a:hover {{ color:var(--accent); }}
nav a.current {{ color:var(--accent); font-weight:600; }}
.nav-section {{ color:var(--text); font-size:11px; text-transform:uppercase;
  letter-spacing:.08em; margin:16px 0 6px; opacity:.6; }}
nav ul {{ list-style:none; margin:0; padding:0; }}
nav li {{ margin:2px 0; font-size:14px; }}
main {{ padding:36px 44px 80px; max-width:980px; }}
h1 {{ font-size:30px; line-height:1.25; margin:0 0 8px; }}
h2 {{ font-size:21px; margin:34px 0 10px; padding-top:10px; border-top:1px solid var(--line); }}
h3 {{ font-size:17px; margin:24px 0 8px; }}
a {{ color:var(--accent); }}
p, li {{ max-width:78ch; }}
table {{ border-collapse:collapse; width:100%; margin:16px 0; font-size:14px;
  display:block; overflow-x:auto; }}
th, td {{ border:1px solid var(--line); padding:7px 10px; text-align:left; vertical-align:top; }}
th {{ background:var(--panel); font-weight:600; }}
code {{ background:var(--code); padding:1px 5px; border-radius:4px; font-size:13px;
  font-family:ui-monospace,SFMono-Regular,Menlo,monospace; }}
pre {{ background:var(--code); padding:14px 16px; border-radius:8px; overflow-x:auto;
  border:1px solid var(--line); }}
pre code {{ background:none; padding:0; }}
blockquote {{ margin:16px 0; padding:2px 16px; border-left:3px solid var(--accent);
  color:var(--muted); }}
footer {{ margin-top:48px; padding-top:16px; border-top:1px solid var(--line);
  color:var(--muted); font-size:13px; }}
@media (max-width:820px) {{
  .layout {{ grid-template-columns:1fr; }}
  nav {{ position:static; height:auto; border-right:none; border-bottom:1px solid var(--line); }}
  main {{ padding:24px 20px 60px; }}
}}
</style>
</head>
<body>
<div class="layout">
<nav>
  <a class="brand" href="index">QVault</a>
  <p class="ver">v{version} · prototype</p>
  {nav}
</nav>
<main>
{content}
<footer>Generated from the repository by <code>tools/build_docs.py</code>. Every page is a
render of a Markdown file in the repo, so the site cannot claim more than the code does.
Sources: <a href="citations">citations</a> · Code:
<a href="https://github.com/1243353366/qvault-uefi-quarantine">github.com/1243353366/qvault-uefi-quarantine</a></footer>
</main>
</div>
</body>
</html>
"""


def render_page(src: str, slug: str, title: str) -> str:
    text = (ROOT / src).read_text()
    html = markdown.markdown(text, extensions=EXTENSIONS)
    html = rewrite_links(html)
    return TEMPLATE.format(title=title, version=version(), nav=nav(slug), content=html)


def build() -> dict[str, str]:
    """Return the full site as {filename: html}, plus CITATIONS.md content."""
    (ROOT / "CITATIONS.md").write_text(render_citations())
    pages = {}
    for src, slug, title, _section in PAGES:
        if not (ROOT / src).exists():
            continue
        pages[slug] = render_page(src, slug, title)
    return pages


def main() -> int:
    DEST.mkdir(exist_ok=True)
    pages = build()
    for slug, html in pages.items():
        (DEST / slug).write_text(html)
    (DEST / ".nojekyll").write_text("")
    (DEST / "sitemap.xml").write_text(render_sitemap(pages))
    (DEST / "robots.txt").write_text(render_robots())
    print(f"built {len(pages)} pages into docs/ plus CITATIONS.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
