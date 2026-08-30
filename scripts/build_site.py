from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Collection, Dict, List, Optional
from urllib.parse import urlparse

from utils import DOCS_DIR, ensure_dirs, load_blacklist, parse_trending_from_readme, is_blacklisted_repo

ROOT = DOCS_DIR.parent
README_PATH = ROOT / "README.md"
CVE_OUTPUT = DOCS_DIR / "CVE_list.json"
TRENDING_OUTPUT = DOCS_DIR / "trending_poc.json"


def normalise_block(text: str) -> str:
    text = text.replace("\r\n", "\n")
    text = re.sub(r"\n{2,}", "\n", text.strip())
    lines = [line.lstrip("- ").rstrip() for line in text.split("\n")]
    return "\n".join(line for line in lines if line)


def parse_sections(content: str) -> Dict[str, str]:
    sections: Dict[str, str] = {}
    current_header: Optional[str] = None
    buffer: List[str] = []

    for line in content.splitlines():
        header = line.strip()
        if header.startswith("### ") or header.startswith("#### "):
            if current_header is not None:
                sections[current_header] = "\n".join(buffer).strip()
            current_header = header
            buffer = []
        else:
            buffer.append(line)

    if current_header is not None:
        sections[current_header] = "\n".join(buffer).strip()

    return sections


def repo_from_url(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = (parsed.netloc or "").lower()
        if host and "github" not in host:
            return ""
        path = parsed.path or url
    except Exception:
        path = url
    parts = path.strip("/").split("/")
    if len(parts) >= 2:
        return "/".join(parts[:2]).lower()
    return (parts[-1] if parts else "").lower()


def is_blacklisted(url: str, blacklist: Collection[str]) -> bool:
    full_name = repo_from_url(url)
    if not full_name:
        return False
    return full_name in blacklist


def link_key(url: str) -> str:
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() not in {"github.com", "www.github.com"}:
        return url
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return url
    repo = f"{parts[0]}/{parts[1]}".lower()
    suffix = "/" + "/".join(parts[2:]) if len(parts) > 2 else ""
    return f"github:{repo}{suffix}?{parsed.query}#{parsed.fragment}"


def collect_links(block: str, *, blacklist: Optional[Collection[str]] = None) -> List[str]:
    links: List[str] = []
    blacklist = blacklist or set()
    for raw in block.splitlines():
        entry = raw.strip()
        if not entry or "No PoCs" in entry:
            continue
        if entry.startswith("- "):
            entry = entry[2:].strip()
        if not entry:
            continue
        if is_blacklisted(entry, blacklist):
            continue
        if entry not in links:
            links.append(entry)
    return links


def build_cve_list(blacklist: Collection[str]) -> List[Dict[str, object]]:
    cve_entries = []

    for md_path in sorted(ROOT.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        content = md_path.read_text(encoding="utf-8")
        sections = parse_sections(content)
        description = normalise_block(sections.get("### Description", ""))
        references = collect_links(sections.get("#### Reference", ""), blacklist=blacklist)
        github_links = collect_links(sections.get("#### Github", ""), blacklist=blacklist)

        poc_entries: List[str] = []
        seen = set()
        for link in references + github_links:
            key = link_key(link)
            if key not in seen:
                poc_entries.append(link)
                seen.add(key)

        cve_id = md_path.stem
        if not poc_entries:
            continue

        cve_entries.append({
            "cve": cve_id,
            "desc": description,
            "poc": poc_entries,
        })

    return cve_entries


def build_trending(blacklist: Collection[str]) -> List[Dict[str, object]]:
    rows = parse_trending_from_readme(README_PATH)
    if not rows:
        return []

    by_year: Dict[int, List[Dict[str, object]]] = {}
    for row in rows:
        year_text = row.get("year") or ""
        if not str(year_text).isdigit():
            continue
        year = int(year_text)
        url = (row.get("url") or "").strip()
        if url and is_blacklisted_repo(url, blacklist):
            continue
        stars_text = str(row.get("stars") or "").strip()
        stars = int(re.sub(r"\D", "", stars_text) or 0)
        item = {
            "year": year,
            "stars": stars,
            "updated": (row.get("updated") or "").strip(),
            "name": (row.get("name") or "").strip(),
            "url": url,
            "desc": (row.get("desc") or "").strip(),
        }
        by_year.setdefault(year, []).append(item)

    if not by_year:
        return []

    current_year = datetime.now(timezone.utc).year
    target_year = current_year if current_year in by_year else max(by_year)
    return by_year.get(target_year, [])


def write_json(path: Path, data, *, indent: Optional[int] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=indent)


def main() -> int:
    argparse.ArgumentParser(description="Build the CVE PoC site data files").parse_args()

    ensure_dirs(DOCS_DIR)
    blacklist = load_blacklist()

    cve_payload = build_cve_list(blacklist)
    write_json(CVE_OUTPUT, cve_payload)

    trending_items = build_trending(blacklist)
    write_json(
        TRENDING_OUTPUT,
        {
            "generated": datetime.now(timezone.utc).isoformat(),
            "items": trending_items,
        },
        indent=2,
    )

    print(f"Wrote {CVE_OUTPUT.name} ({len(cve_payload)} CVEs) and {TRENDING_OUTPUT.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
