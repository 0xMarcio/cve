#!/usr/bin/python3
import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = Path(__file__).resolve().with_name("CVE_list.json")
REMOVED_OUTPUT = Path(__file__).resolve().with_name("CVE_blacklist_removed.json")
BLACKLIST = ROOT / "blacklist.txt"


def load_blacklist(path: Path = BLACKLIST) -> List[str]:
    if not path.exists():
        return []
    items: List[str] = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        entry = raw.strip()
        if entry and not entry.startswith("#"):
            items.append(entry)
    return items


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


def normalise_block(text: str) -> str:
    text = text.replace("\r\n", "\n")
    text = re.sub(r"\n{2,}", "\n", text.strip())
    lines = [line.lstrip("- ").rstrip() for line in text.split("\n")]
    return "\n".join(line for line in lines if line)


def parse_sections(content: str) -> Dict[str, str]:
    sections: Dict[str, str] = {}
    current_header: str | None = None
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


def main() -> None:
    blacklist = load_blacklist()
    cve_entries = []
    removed_by_cve: Dict[str, List[str]] = {}
    removed_seen: set[str] = set()
    years = [entry for entry in os.listdir(ROOT) if entry.isdigit()]
    years.sort(reverse=True)

    for year in years:
        year_dir = ROOT / year
        for filename in sorted(os.listdir(year_dir)):
            if not filename.endswith(".md"):
                continue
            with open(year_dir / filename, "r", encoding="utf-8") as handle:
                content = handle.read()

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

            cve_id = filename.replace(".md", "")
            if removed_links:
                removed_by_cve[cve_id] = sorted(set(removed_links))
                removed_seen.update(removed_links)

            # Skip CVEs with zero PoCs (both sections empty) to keep lookup clean
            if not poc_entries:
                continue

            cve_entries.append({
                "cve": cve_id,
                "desc": description,
                "poc": poc_entries,
            })

    with open(OUTPUT, "w", encoding="utf-8") as outfile:
        json.dump(cve_entries, outfile, ensure_ascii=False)

    with open(REMOVED_OUTPUT, "w", encoding="utf-8") as removed_file:
        json.dump(
            {
                "removed": sorted(removed_seen),
                "by_cve": removed_by_cve,
            },
            removed_file,
            ensure_ascii=False,
            indent=2,
        )

    print("CVE list saved to CVE_list.json")


if __name__ == "__main__":
    main()
