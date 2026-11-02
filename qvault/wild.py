"""Zero-days exploited in the wild, as a pinned reference set.

Source: googleprojectzero/0days-in-the-wild at a pinned commit, Apache-2.0, vendored as a
derived index in `vendor/p0_0days/index.json`. Upstream is never read at run time: the commit
and per-file hashes are recorded so a future update is a deliberate audit, not a silent pull.

What this module is for: grounding. It answers "how much of the real in-the-wild record does
this project's boundary actually touch", and the honest answer is a small fraction. QVault
observes persistence and integrity; it does not detect exploitation. Treating a 0-day corpus
as evidence that a detection layer works would be the exact category error this project has
spent its gates refusing.
"""

import hashlib
import json
import re
from pathlib import Path

INDEX = Path(__file__).resolve().parents[1] / "vendor" / "p0_0days" / "index.json"

REQUIRED_FIELDS = ("cve", "year", "title", "product", "path", "sha256", "bytes")
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,7}$")

#: Coarse classes assigned by keyword match over title, product and affected versions. A
#: keyword match is an observation for a human to adjudicate, not a finding: the corpus was
#: not written for this purpose and the words are chosen by its authors.
CLASSES = {
    "firmware_boot": ("firmware", "uefi", "secure boot", "bootloader", "boot rom", "tpm", "baseband"),
    "kernel": ("kernel", "driver", "ioctl", "use-after-free in the kernel", "ebpf"),
    "browser_renderer": ("v8", "webkit", "renderer", "javascript engine", "blink"),
    "sandbox_escape": ("sandbox", "escape", "ipc", "broker"),
    "privilege_escalation": ("privilege", "escalation", "lpe", "elevation", "token"),
    "persistence": ("persistence", "autorun", "startup", "scheduled task", "service"),
}

class WildError(ValueError):
    """Raised when the pinned reference set is malformed or has been edited by hand."""


def load() -> dict:
    if not INDEX.exists():
        raise WildError(f"pinned index missing at {INDEX}")
    return json.loads(INDEX.read_text())


def entries() -> list[dict]:
    return load()["entries"]


def assert_dataset_integrity() -> None:
    """Structure, identity and provenance. Any failure means the anchor moved."""
    data = load()
    source = data["source"]
    if not re.fullmatch(r"[0-9a-f]{40}", source["commit"]):
        raise WildError("source commit must be a full 40-character sha, not a branch name")
    if source["license"] != "Apache-2.0":
        raise WildError(f"unexpected upstream license {source['license']!r}")
    if not re.fullmatch(r"[0-9a-f]{64}", source["tarball_sha256"]):
        raise WildError("tarball hash must be recorded")

    items = data["entries"]
    if len(items) != data["counts"]["entries"]:
        raise WildError("entry count disagrees with the recorded count")

    seen = set()
    for entry in items:
        for name in REQUIRED_FIELDS:
            if name not in entry:
                raise WildError(f"entry {entry.get('cve', '?')} is missing {name}")
        if not CVE_PATTERN.match(entry["cve"]):
            raise WildError(f"malformed CVE id {entry['cve']!r}")
        if entry["cve"] in seen:
            raise WildError(f"duplicate entry {entry['cve']}")
        seen.add(entry["cve"])
        if not entry["year"].isdigit() or len(entry["year"]) != 4:
            raise WildError(f"{entry['cve']}: year {entry['year']!r} is not a four-digit year")
        if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
            raise WildError(f"{entry['cve']}: source hash is not sha256")
        if not entry["path"].startswith("0day-RCAs/"):
            raise WildError(f"{entry['cve']}: path outside the RCA tree")
        if not entry["product"]:
            raise WildError(f"{entry['cve']}: no product recorded")
        if entry["bytes"] <= 0:
            raise WildError(f"{entry['cve']}: empty source document")

    by_year = {}
    for entry in items:
        by_year[entry["year"]] = by_year.get(entry["year"], 0) + 1
    if dict(sorted(by_year.items())) != data["counts"]["by_year"]:
        raise WildError("per-year counts disagree with the entries")


def year_is_exploitation_year() -> dict:
    """Cases where the folder year differs from the CVE year.

    The upstream layout files an entry by when it was found exploited, not by when the CVE
    was assigned, so the two can differ. Recorded rather than normalised away.
    """
    differences = {}
    for entry in entries():
        cve_year = entry["cve"].split("-")[1]
        if cve_year != entry["year"]:
            differences[entry["cve"]] = {"cve_year": cve_year, "exploited_year": entry["year"]}
    return differences


def classify(entry: dict) -> dict:
    """Coarse keyword classes with the matched terms kept as the evidence."""
    haystack = " ".join(str(entry.get(k) or "") for k in
                        ("title", "product", "affected_versions")).lower()
    matched: dict[str, list[str]] = {}
    for name, keywords in CLASSES.items():
        hits = [k for k in keywords if k in haystack]
        if hits:
            matched[name] = hits
    return {"cve": entry["cve"], "classes": sorted(matched),
            "evidence": matched, "basis": "keyword match over the RCA header; requires human "
                                          "adjudication, not a finding"}


def summary() -> dict:
    items = entries()
    by_year: dict[str, int] = {}
    by_product: dict[str, int] = {}
    for entry in items:
        by_year[entry["year"]] = by_year.get(entry["year"], 0) + 1
        by_product[entry["product"]] = by_product.get(entry["product"], 0) + 1
    return {
        "entries": len(items),
        "by_year": dict(sorted(by_year.items())),
        "products": len(by_product),
        "top_products": sorted(by_product.items(), key=lambda kv: (-kv[1], kv[0]))[:10],
        "year_folder_differs_from_cve_year": len(year_is_exploitation_year()),
    }


def boundary_assessment() -> dict:
    """What share of the real record this project's boundary can touch, stated plainly."""
    items = entries()
    classes: dict[str, int] = {}
    for entry in items:
        for name in classify(entry)["classes"]:
            classes[name] = classes.get(name, 0) + 1
    touching = sum(1 for entry in items
                   if {"persistence", "firmware_boot"} & set(classify(entry)["classes"]))
    return {
        "entries": len(items),
        "by_class": dict(sorted(classes.items())),
        "touching_persistence_or_boot": touching,
        "statement": ("QVault does not detect exploitation. Of the recorded in-the-wild 0-days, "
                      "only those involving persistence or boot artefacts fall near this "
                      "boundary, and for those the layer bounds blast radius and preserves "
                      "evidence rather than preventing the 0-day. The remainder is out of scope "
                      "and is not counted as coverage."),
    }


assert_dataset_integrity()
