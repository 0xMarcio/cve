#!/usr/bin/env python3
"""Synchronise CVE markdown entries with GitHub PoC listings.

This script scans `github.txt` for CVE → PoC mappings, ensures each CVE has a
markdown record under its year directory, refreshes metadata from the CVE
Program API (with local caching to limit HTTP volume), and regenerates the JSON
consumed by the website whenever new information is added.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple
from urllib import error, request
from urllib.parse import quote_plus

ROOT = Path(__file__).resolve().parents[1]
GITHUB_LIST = ROOT / "github.txt"
DOCS_DIR = ROOT / "docs"
JSON_SCRIPT = DOCS_DIR / "generate_cve_list.py"
DATA_DIR = ROOT / "data"
CACHE_FILE = DATA_DIR / "cve_cache.json"
DEFAULT_CACHE_TTL = 60 * 60 * 24 * 7  # one week

CVE_API_TEMPLATE = "https://cveawg.mitre.org/api/cve/{cve_id}"
GITHUB_LINE_RE = re.compile(r"^(CVE-\\d{4}-\\d{4,})\\s*-\\s*(https?://[^\\s]+)")


@dataclass
class CVEDetails:
    description: str
    references: List[str]
    products: List[str]
    versions: List[str]
    cwes: List[str]

    def to_dict(self) -> Dict[str, List[str] | str]:
        return {
            "description": self.description,
            "references": self.references,
            "products": self.products,
            "versions": self.versions,
            "cwes": self.cwes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, List[str] | str]) -> "CVEDetails":
        return cls(
            description=str(data.get("description", "")),
            references=list(data.get("references", [])),
            products=list(data.get("products", [])),
            versions=list(data.get("versions", [])),
            cwes=list(data.get("cwes", [])),
        )


class UpdateStats:
    def __init__(self) -> None:
        self.created: List[str] = []
        self.updated: List[str] = []
        self.skipped: List[str] = []

    def mark_created(self, cve_id: str) -> None:
        self.created.append(cve_id)

    def mark_updated(self, cve_id: str) -> None:
        self.updated.append(cve_id)

    def mark_skipped(self, cve_id: str, reason: str) -> None:
        self.skipped.append(f"{cve_id}: {reason}")

    @property
    def changed(self) -> bool:
        return bool(self.created or self.updated)


def parse_github_sources(path: Path) -> Dict[str, List[str]]:
    """Return a mapping of CVE IDs to ordered, de-duplicated PoC URLs."""
    mapping: Dict[str, List[str]] = defaultdict(list)
    if not path.exists():
        raise FileNotFoundError(f"Expected GitHub source list at {path}")

    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            match = GITHUB_LINE_RE.match(line)
            if not match:
                continue
            cve_id, url = match.groups()
            if not is_valid_cve(cve_id):
                continue
            urls = mapping[cve_id]
            if url not in urls:
                urls.append(url)
    return mapping


def is_valid_cve(cve_id: str) -> bool:
    parts = cve_id.split("-")
    if len(parts) != 3:
        return False
    _, year, sequence = parts
    if not (year.isdigit() and sequence.isdigit()):
        return False
    year_int = int(year)
    return 1999 <= year_int <= 2100


def load_cache(path: Path) -> Dict[str, Dict[str, object]]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(path: Path, cache: Dict[str, Dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(cache, handle, ensure_ascii=False, indent=2)


def fetch_cve_details_from_api(cve_id: str) -> Optional[CVEDetails]:
    url = CVE_API_TEMPLATE.format(cve_id=cve_id)
    try:
        with request.urlopen(url, timeout=15) as response:
            data = json.load(response)
    except error.HTTPError as err:
        if err.code == 404:
            return None
        raise
    except (error.URLError, TimeoutError, json.JSONDecodeError):
        return None

    containers = data.get("containers", {})
    cna = containers.get("cna", {})
    descriptions = cna.get("descriptions", []) or []

    description = ""
    for entry in descriptions:
        if entry.get("lang", "").lower() == "en" and entry.get("value"):
            description = entry["value"].strip()
            break
    if not description:
        return None

    references: List[str] = []
    for ref in cna.get("references", []) or []:
        url = ref.get("url")
        if url and url not in references:
            references.append(url)

    products: List[str] = []
    versions: List[str] = []
    for affected in cna.get("affected", []) or []:
        vendor = affected.get("vendor") or ""
        product = affected.get("product") or ""
        label = " ".join(part for part in (vendor, product) if part).strip()
        if label and label not in products:
            products.append(label)

        for version_info in affected.get("versions", []) or []:
            version = version_info.get("version")
            if version and version not in {"*", "-", "unspecified", "n/a"} and version not in versions:
                versions.append(version)

    cwes: List[str] = []
    for problem in cna.get("problemTypes", []) or []:
        for desc in problem.get("descriptions", []) or []:
            text = desc.get("description") or desc.get("cweId")
            if text and text not in cwes:
                cwes.append(text)

    return CVEDetails(
        description=description,
        references=references,
        products=products,
        versions=versions,
        cwes=cwes,
    )


def get_cve_details(
    cve_id: str,
    cache: Dict[str, Dict[str, object]],
    ttl_seconds: int,
    refresh: bool,
) -> Tuple[Optional[CVEDetails], bool]:
    now = time.time()
    cache_hit = cache.get(cve_id)

    if cache_hit and not refresh:
        fetched_at = float(cache_hit.get("fetched_at", 0))
        if now - fetched_at < ttl_seconds:
            return CVEDetails.from_dict(cache_hit.get("data", {})), False

    details = fetch_cve_details_from_api(cve_id)
    if details:
        cache[cve_id] = {"fetched_at": now, "data": details.to_dict()}
        return details, True

    if cache_hit:
        # Fall back to stale cache if re-fetch fails.
        return CVEDetails.from_dict(cache_hit.get("data", {})), False

    return None, False


def ensure_markdown(
    cve_id: str,
    details: CVEDetails,
    poc_links: Iterable[str],
    stats: UpdateStats,
) -> None:
    year = cve_id.split("-")[1]
    target_dir = ROOT / year
    target_dir.mkdir(parents=True, exist_ok=True)
    target_file = target_dir / f"{cve_id}.md"

    sorted_links = list(poc_links)

    if not target_file.exists():
        content = build_markdown(cve_id, details, sorted_links)
        target_file.write_text(content, encoding="utf-8")
        stats.mark_created(cve_id)
        return

    if update_existing_markdown(target_file, sorted_links, details):
        stats.mark_updated(cve_id)


def build_markdown(cve_id: str, details: CVEDetails, poc_links: List[str]) -> str:
    description = details.description.strip().replace("\r\n", "\n")

    product_label = summarise_values(details.products, fallback="n/a")
    version_label = summarise_values(details.versions, fallback="Multiple")
    vulnerability_label = summarise_values(details.cwes, fallback="n/a")

    lines = [
        f"### [{cve_id}](https://www.cve.org/CVERecord?id={cve_id})",
        build_badge("Product", product_label, "blue"),
        build_badge("Version", version_label, "blue"),
        build_badge("Vulnerability", vulnerability_label, "brighgreen"),
        "",
        "### Description",
        "",
        description,
        "",
        "### POC",
        "",
        "#### Reference",
    ]

    if details.references:
        lines.extend(f"- {ref}" for ref in details.references)
    else:
        lines.append("No PoCs from references.")

    lines.extend([
        "",
        "#### Github",
    ])

    if poc_links:
        lines.extend(f"- {link}" for link in poc_links)
    else:
        lines.append("No PoCs from references.")

    lines.append("")
    return "\n".join(lines)


GITHUB_SECTION_RE = re.compile(r"(#### Github\s*\n)(.*?)(\n### |\Z)", re.DOTALL)
REFERENCE_SECTION_RE = re.compile(r"(#### Reference\s*\n)(.*?)(\n#### |\n### |\Z)", re.DOTALL)
DESCRIPTION_SECTION_RE = re.compile(r"(### Description\s*\n)(.*?)(\n### |\Z)", re.DOTALL)


def update_existing_markdown(path: Path, poc_links: Iterable[str], details: CVEDetails) -> bool:
    text = path.read_text(encoding="utf-8")
    updated_text = text

    updated_text, poc_changed = upsert_github_section(updated_text, poc_links)
    updated_text, ref_changed = upsert_reference_section(updated_text, details.references)
    updated_text, desc_changed = upsert_description_section(updated_text, details.description)
    updated_text, badge_changed = upsert_badges(updated_text, details)

    if poc_changed or ref_changed or desc_changed or badge_changed:
        if not updated_text.endswith("\n"):
            updated_text += "\n"
        path.write_text(updated_text, encoding="utf-8")
        return True

    return False


def upsert_github_section(text: str, poc_links: Iterable[str]) -> Tuple[str, bool]:
    match = GITHUB_SECTION_RE.search(text)
    incoming_links = [link for link in poc_links if link]
    new_links = list(dict.fromkeys(incoming_links))

    if not new_links:
        desired = "No PoCs from references.\n"
    else:
        desired = "\n".join(f"- {link}" for link in new_links) + "\n"

    if not match:
        addition_lines = ["#### Github", desired.rstrip(), ""]
        addition = "\n".join(addition_lines)
        if "### POC" in text:
            updated = text.rstrip() + "\n\n" + addition + "\n"
        else:
            updated = text.rstrip() + "\n\n### POC\n\n#### Reference\nNo PoCs from references.\n\n" + addition + "\n"
        return updated, True

    start, end = match.start(2), match.end(2)
    current = text[start:end]
    existing_links = parse_links(current)
    desired_links = existing_links[:]
    for link in new_links:
        if link not in desired_links:
            desired_links.append(link)

    replacement = (
        "\n".join(f"- {link}" for link in desired_links) + "\n"
        if desired_links
        else "No PoCs from references.\n"
    )

    if current == replacement:
        return text, False

    updated = text[:start] + replacement + text[end:]
    return updated, True


def upsert_reference_section(text: str, references: List[str]) -> Tuple[str, bool]:
    desired_refs = list(dict.fromkeys(references)) if references else []

    match = REFERENCE_SECTION_RE.search(text)
    if match:
        start, end = match.start(2), match.end(2)
        current = text[start:end]
        existing_refs = parse_links(current)
        if existing_refs:
            for ref in existing_refs:
                if ref not in desired_refs:
                    desired_refs.append(ref)
        desired_block = (
            "\n".join(f"- {ref}" for ref in desired_refs) + "\n"
            if desired_refs
            else "No PoCs from references.\n"
        )
        if current == desired_block:
            return text, False
        updated = text[:start] + desired_block + text[end:]
        return updated, True

    desired_block = (
        "\n".join(f"- {ref}" for ref in desired_refs) + "\n"
        if desired_refs
        else "No PoCs from references.\n"
    )
    insertion = "\n#### Reference\n" + desired_block + "\n"
    if "### POC" in text:
        idx = text.index("### POC") + len("### POC")
        updated = text[:idx] + "\n\n" + insertion + text[idx:]
    else:
        updated = text.rstrip() + "\n\n### POC\n\n" + insertion
    return updated, True


def upsert_description_section(text: str, description: str) -> Tuple[str, bool]:
    desired = description.strip().replace("\r\n", "\n") + "\n"
    match = DESCRIPTION_SECTION_RE.search(text)
    if match:
        start, end = match.start(2), match.end(2)
        current = text[start:end]
        if current == desired:
            return text, False
        updated = text[:start] + desired + text[end:]
        return updated, True

    insertion = "\n### Description\n\n" + desired + "\n"
    return text.rstrip() + insertion, True


def upsert_badges(text: str, details: CVEDetails) -> Tuple[str, bool]:
    desired_product = build_badge("Product", summarise_values(details.products, fallback="n/a"), "blue")
    desired_version = build_badge("Version", summarise_values(details.versions, fallback="Multiple"), "blue")
    desired_vuln = build_badge("Vulnerability", summarise_values(details.cwes, fallback="n/a"), "brighgreen")

    lines = text.splitlines()
    changed = False

    for idx, line in enumerate(lines[:4]):
        if line.startswith("![](https://img.shields.io/static/v1?label=Product") and line != desired_product:
            lines[idx] = desired_product
            changed = True
        elif line.startswith("![](https://img.shields.io/static/v1?label=Version") and line != desired_version:
            lines[idx] = desired_version
            changed = True
        elif line.startswith("![](https://img.shields.io/static/v1?label=Vulnerability") and line != desired_vuln:
            lines[idx] = desired_vuln
            changed = True

    if not changed:
        return text, False

    updated = "\n".join(lines)
    if text.endswith("\n"):
        updated += "\n"
    return updated, True


def parse_links(block: str) -> List[str]:
    links: List[str] = []
    for line in block.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("- "):
            url = line[2:].strip()
        else:
            url = line
        if url and url not in links and url != "No PoCs from references.":
            links.append(url)
    return links


def summarise_values(values: List[str], *, fallback: str) -> str:
    if not values:
        return fallback
    if len(values) == 1:
        return values[0]
    if len(values) == 2:
        return " & ".join(values)
    return f"{values[0]} +{len(values) - 1} more"


def build_badge(label: str, message: str, color: str) -> str:
    safe_label = quote_plus(label)
    safe_message = quote_plus(message) if message else "n%2Fa"
    return f"![](https://img.shields.io/static/v1?label={safe_label}&message={safe_message}&color={color})"


def regenerate_json() -> None:
    subprocess.run([sys.executable, JSON_SCRIPT.name], cwd=DOCS_DIR, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Synchronise CVE markdown entries with PoC listings")
    parser.add_argument(
        "--cve",
        dest="cve_filter",
        nargs="+",
        help="Limit processing to the provided CVE identifiers",
    )
    parser.add_argument(
        "--skip-json",
        action="store_true",
        help="Skip regenerating docs/CVE_list.json even if updates occur",
    )
    parser.add_argument(
        "--refresh-cache",
        action="store_true",
        help="Force refetching CVE metadata instead of using the local cache",
    )
    parser.add_argument(
        "--cache-ttl",
        type=int,
        default=DEFAULT_CACHE_TTL,
        help="Cache lifetime in seconds for CVE metadata (default: one week)",
    )
    parser.add_argument(
        "--cache-path",
        type=Path,
        default=CACHE_FILE,
        help="Location for the CVE metadata cache file",
    )
    args = parser.parse_args()

    stats = UpdateStats()
    cve_to_links = parse_github_sources(GITHUB_LIST)

    if args.cve_filter:
        requested = {cve.upper() for cve in args.cve_filter if is_valid_cve(cve.upper())}
        cve_to_links = {cve: cve_to_links.get(cve, []) for cve in requested if cve in cve_to_links}

    cache = load_cache(args.cache_path)
    cache_modified = False

    for cve_id in sorted(cve_to_links):
        details, updated_cache = get_cve_details(cve_id, cache, args.cache_ttl, args.refresh_cache)
        cache_modified = cache_modified or updated_cache

        if not details:
            stats.mark_skipped(cve_id, "missing description from CVE API")
            continue

        ensure_markdown(cve_id, details, cve_to_links[cve_id], stats)

    if stats.changed and not args.skip_json:
        regenerate_json()

    if cache_modified:
        save_cache(args.cache_path, cache)

    print(f"Created: {len(stats.created)} | Updated: {len(stats.updated)} | Skipped: {len(stats.skipped)}")
    if stats.skipped:
        for entry in stats.skipped:
            print(f"Skipped {entry}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
