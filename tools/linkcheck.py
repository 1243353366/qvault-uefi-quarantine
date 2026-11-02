#!/usr/bin/env python3
"""Check the links in the published site and in the sources behind it.

Two different questions, so two different modes:

  --internal   every href in docs/*.html resolves to a published page or a repository file,
               with no dead relative hrefs and no stray .md links. Offline, deterministic,
               fast enough to be a gate.
  --external   every external http(s) URL cited anywhere in the docs and reports answers.
               Hits the network, so it is a CI job rather than a gate: a transient outage
               should not block a commit, but a 404 should not survive unnoticed either.

External results are classified rather than boolean, because "unreachable" has two meanings:
  ok      2xx, or a redirect that lands on 2xx
  blocked the host refuses automated clients (403/406/429/451, or a documented blocker)
  broken  404/410, a 5xx that survived a retry, or a connection that never established
"""
import argparse
import html
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"

#: Publishers that refuse automated clients by policy. The report says so in its own words:
#: "nsa.gov and media.defense.gov block automated clients". Recorded here rather than treated
#: as a broken citation, and never silently dropped.
POLICY_BLOCKERS = ("nsa.gov", "media.defense.gov", "dl.acm.org", "ieeexplore.ieee.org")
BLOCK_CODES = {403, 406, 418, 429, 451}
UA = "Mozilla/5.0 (compatible; qvault-linkcheck/1.0; +https://github.com/1243353366/qvault-uefi-quarantine)"
HREF_RE = re.compile(r'href="([^"]+)"')
BARE_URL_RE = re.compile(r"(?<!\()(https?://[^\s\)\]]+)")


def published() -> set[str]:
    return {p.name for p in DOCS.glob("*.html")}


def internal_links() -> list[tuple[str, str]]:
    """(page, href) for every non-external href in the site."""
    links = []
    for page in sorted(DOCS.glob("*.html")):
        for href in HREF_RE.findall(page.read_text()):
            if href.startswith(("http://", "https://", "#", "mailto:")):
                continue
            links.append((page.name, href))
    return links


def check_internal() -> list[str]:
    pages = published()
    problems = []
    if not pages:
        return ["docs/ is empty: run tools/build_docs.py"]
    for page, href in internal_links():
        if href.endswith(".md"):
            problems.append(f"{page}: dead markdown href {href}")
            continue
        target = href.split("#")[0]
        if not target:
            continue
        if {target, f"{target}.html"} & pages:
            continue
        problems.append(f"{page}: unresolved href {href}")
    for page in pages:
        text = (DOCS / page).read_text()
        if 'href="index"' not in text:
            problems.append(f"{page}: no link back to the index")
    return problems


def external_urls() -> list[str]:
    """Unique external citations, from the published pages and the Markdown sources."""
    found: set[str] = set()
    for page in DOCS.glob("*.html"):
        for href in HREF_RE.findall(page.read_text()):
            if href.startswith(("http://", "https://")):
                found.add(html.unescape(href))
    for path in list((ROOT / "report").glob("*.md")) + [ROOT / "CITATIONS.md",
                                                        ROOT / "README.md"]:
        for match in BARE_URL_RE.findall(path.read_text()):
            found.add(match.rstrip(".,;"))
    # the site itself is internal, not a citation; a placeholder pattern is not a URL to probe
    return sorted(u for u in found
                  if "1243353366.github.io" not in u and not set("<>{}") & set(u))


def probe(url: str) -> tuple[str, str, str]:
    """(url, status, detail). HEAD first, GET as a fallback for hosts that refuse HEAD."""
    for method in ("HEAD", "GET"):
        request = urllib.request.Request(url, method=method, headers={"User-Agent": UA})
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                return url, "ok", f"{response.status}"
        except urllib.error.HTTPError as exc:
            if exc.code in BLOCK_CODES:
                return url, "blocked", f"HTTP {exc.code}"
            if method == "GET":
                return url, "broken", f"HTTP {exc.code}"
        except Exception as exc:                             # noqa: BLE001 - network noise
            if method == "GET":
                host = url.split("/")[2]
                if any(b in host for b in POLICY_BLOCKERS):
                    return url, "blocked", f"{type(exc).__name__} (documented blocker)"
                return url, "broken", type(exc).__name__
    return url, "broken", "unreachable"


def check_external(workers: int = 8) -> list[tuple[str, str, str]]:
    urls = external_urls()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(probe, urls))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--internal", action="store_true")
    parser.add_argument("--external", action="store_true")
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args(argv)
    if not (args.internal or args.external or args.all):
        parser.print_help()
        return 2

    failures = 0
    if args.internal or args.all:
        problems = check_internal()
        total = len(internal_links())
        if problems:
            failures += len(problems)
            print(f"internal: {len(problems)} problem(s) across {total} links")
            for line in problems:
                print(f"  - {line}")
        else:
            print(f"internal: {total} links resolve across {len(published())} pages")

    if args.external or args.all:
        results = check_external(args.workers)
        buckets: dict[str, list[tuple[str, str, str]]] = {"ok": [], "blocked": [], "broken": []}
        for result in results:
            buckets[result[1]].append(result)
        print(f"external: {len(results)} unique citations "
              f"({len(buckets['ok'])} ok, {len(buckets['blocked'])} blocked, "
              f"{len(buckets['broken'])} broken)")
        for url, _status, detail in buckets["blocked"]:
            print(f"  blocked  {url}  [{detail}]")
        for url, _status, detail in buckets["broken"]:
            print(f"  BROKEN   {url}  [{detail}]")
        failures += len(buckets["broken"])

    print("FAIL" if failures else "PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
