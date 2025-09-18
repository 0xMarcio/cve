#!/usr/bin/python3
import json
import os
import re
from pathlib import Path
from typing import Dict, List

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = Path(__file__).resolve().with_name("CVE_list.json")


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


def collect_links(block: str) -> List[str]:
    links: List[str] = []
    for raw in block.splitlines():
        entry = raw.strip()
        if not entry or "No PoCs" in entry:
            continue
        if entry.startswith("- "):
            entry = entry[2:].strip()
        if entry and entry not in links:
            links.append(entry)
    return links


def main() -> None:
    cve_entries = []
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
            references = collect_links(sections.get("#### Reference", ""))
            github_links = collect_links(sections.get("#### Github", ""))

            poc_entries: List[str] = []
            seen = set()
            for link in references + github_links:
                if link not in seen:
                    poc_entries.append(link)
                    seen.add(link)

            cve_entries.append({
                "cve": filename.replace(".md", ""),
                "desc": description,
                "poc": poc_entries,
            })

    with open(OUTPUT, "w", encoding="utf-8") as outfile:
        json.dump(cve_entries, outfile, ensure_ascii=False)

    print("CVE list saved to CVE_list.json")


if __name__ == "__main__":
    main()
