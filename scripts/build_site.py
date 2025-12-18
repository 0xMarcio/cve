from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape

from utils import DOCS_DIR, TEMPLATES_DIR, ensure_dirs, load_blacklist, parse_trending_from_readme, is_blacklisted_repo

ROOT = DOCS_DIR.parent
README_PATH = ROOT / "README.md"
CVE_OUTPUT = DOCS_DIR / "CVE_list.json"
REMOVED_OUTPUT = DOCS_DIR / "CVE_blacklist_removed.json"
TRENDING_OUTPUT = DOCS_DIR / "trending_poc.json"


def build_env() -> Environment:
    loader = FileSystemLoader(str(TEMPLATES_DIR))
    env = Environment(loader=loader, autoescape=select_autoescape(["html", "xml"]))
    env.trim_blocks = True
    env.lstrip_blocks = True
    return env


def render(env: Environment, template_name: str, context: Dict, output_path: Path) -> None:
    html = env.get_template(template_name).render(**context)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


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
        return parts[1].lower()
    return (parts[-1] if parts else "").lower()


def is_blacklisted(url: str, blacklist: List[str]) -> bool:
    repo = repo_from_url(url)
    if not repo:
        return False
    for entry in blacklist:
        slug = entry.lower()
        if not slug:
            continue
        if slug.endswith("*"):
            if repo.startswith(slug[:-1]):
                return True
        elif repo == slug:
            return True
    return False


def collect_links(block: str, *, blacklist: Optional[List[str]] = None, removed: Optional[List[str]] = None) -> List[str]:
    links: List[str] = []
    blacklist = blacklist or []
    if removed is None:
        removed = []
    for raw in block.splitlines():
        entry = raw.strip()
        if not entry or "No PoCs" in entry:
            continue
        if entry.startswith("- "):
            entry = entry[2:].strip()
        if not entry:
            continue
        if is_blacklisted(entry, blacklist):
            removed.append(entry)
            continue
        if entry not in links:
            links.append(entry)
    return links


def build_cve_list(blacklist: List[str]) -> Dict[str, object]:
    cve_entries = []
    removed_by_cve: Dict[str, List[str]] = {}
    removed_seen: set[str] = set()

    for md_path in sorted(ROOT.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        content = md_path.read_text(encoding="utf-8")
        sections = parse_sections(content)
        description = normalise_block(sections.get("### Description", ""))
        removed_links: List[str] = []
        references = collect_links(sections.get("#### Reference", ""), blacklist=blacklist, removed=removed_links)
        github_links = collect_links(sections.get("#### Github", ""), blacklist=blacklist, removed=removed_links)

        poc_entries: List[str] = []
        seen = set()
        for link in references + github_links:
            if link not in seen:
                poc_entries.append(link)
                seen.add(link)

        cve_id = md_path.stem
        if removed_links:
            removed_by_cve[cve_id] = sorted(set(removed_links))
            removed_seen.update(removed_links)

        if not poc_entries:
            continue

        cve_entries.append({
            "cve": cve_id,
            "desc": description,
            "poc": poc_entries,
        })

    return {
        "entries": cve_entries,
        "removed": {
            "removed": sorted(removed_seen),
            "by_cve": removed_by_cve,
        },
    }


def build_trending(blacklist: List[str]) -> List[Dict[str, object]]:
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
    parser = argparse.ArgumentParser(description="Build CVE PoC site")
    parser.add_argument(
        "--html-mode",
        choices=["none", "summary", "all"],
        default="summary",
        help="Render HTML or skip it.",
    )
    args = parser.parse_args()

    ensure_dirs(DOCS_DIR)
    blacklist = load_blacklist()

    cve_payload = build_cve_list(blacklist)
    write_json(CVE_OUTPUT, cve_payload["entries"])
    write_json(REMOVED_OUTPUT, cve_payload["removed"], indent=2)

    trending_items = build_trending(blacklist)
    write_json(
        TRENDING_OUTPUT,
        {
            "generated": datetime.now(timezone.utc).isoformat(),
            "items": trending_items,
        },
        indent=2,
    )

    if args.html_mode != "none":
        env = build_env()
        render(env, "index.html", {"trending": trending_items}, DOCS_DIR / "index.html")

    print("Site generated under docs/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
