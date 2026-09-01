from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Collection, Dict, List, Optional
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = ROOT / "docs"
BLACKLIST = ROOT / "blacklist.txt"
TRENDING_INPUT = ROOT / "trending.json"
CVE_OUTPUT = DOCS_DIR / "CVE_list.json"
TRENDING_OUTPUT = DOCS_DIR / "trending_poc.json"
REPO_META = ROOT / "repo_meta.json"
REPO_META_OUTPUT = DOCS_DIR / "repo_meta.json"
KEV_INPUT = ROOT / "kev.json"
KEV_OUTPUT = DOCS_DIR / "kev.json"
NUCLEI_INPUT = ROOT / "nuclei.json"
NUCLEI_OUTPUT = DOCS_DIR / "nuclei.json"
def load_blacklist() -> set[str]:
    if not BLACKLIST.exists():
        return set()
    return {
        line.strip().lower()
        for line in BLACKLIST.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def normalise_block(text: str) -> str:
    text = text.replace("\r\n", "\n")
    text = re.sub(r"\n{2,}", "\n", text.strip())
    lines = [
        re.sub(r"^#{1,6}\s+", "", line.lstrip("- ")).rstrip()
        for line in text.split("\n")
    ]
    return "\n".join(line for line in lines if line)


SECTION_HEADERS = ("### Description", "### POC", "#### Reference", "#### Github", "#### Nuclei")


def parse_sections(content: str) -> Dict[str, str]:
    """Split an entry on its own headings only.

    CVE text lifted from a GitHub advisory often opens with "### Impact" or
    "### Summary"; treating any heading as a boundary let a description end
    itself and vanish from the index.
    """
    sections: Dict[str, str] = {}
    current_header: Optional[str] = None
    buffer: List[str] = []

    for line in content.splitlines():
        header = line.strip()
        if header in SECTION_HEADERS:
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
        return url.rstrip("/")
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


def build_cve_list(blacklist: Collection[str]) -> tuple[List[Dict[str, object]], int]:
    cve_entries = []
    total = 0

    for md_path in sorted(ROOT.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        total += 1
        content = md_path.read_text(encoding="utf-8")
        sections = parse_sections(content)
        description = normalise_block(sections.get("### Description", ""))
        references = collect_links(sections.get("#### Reference", ""), blacklist=blacklist)
        github_links = collect_links(sections.get("#### Github", ""), blacklist=blacklist)
        # Nuclei templates stay in their own list: they are runnable checks
        # rather than somebody's repository, and the site labels them as such.
        nuclei = collect_links(sections.get("#### Nuclei", ""), blacklist=blacklist)

        poc_entries: List[str] = []
        seen = set()
        for link in references + github_links:
            key = link_key(link)
            if key not in seen:
                poc_entries.append(link)
                seen.add(key)

        cve_id = md_path.stem
        if not poc_entries and not nuclei:
            continue

        entry = {
            "cve": cve_id,
            "desc": description,
            "poc": poc_entries,
        }
        if nuclei:
            entry["nuclei"] = nuclei
        cve_entries.append(entry)

    return cve_entries, total


def build_repo_meta(cve_entries: List[Dict[str, object]]) -> Dict[str, object]:
    """Star count and last-push date for the repositories the index actually links."""
    try:
        stored = json.loads(REPO_META.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    linked = {
        repo_from_url(url)
        for entry in cve_entries
        for url in entry["poc"]
        if repo_from_url(url)
    }
    return {name: value for name, value in stored.items() if name in linked}


def build_kev(cve_entries: List[Dict[str, object]]) -> Dict[str, object]:
    """CISA's known-exploited entries, limited to CVEs the index carries."""
    try:
        stored = json.loads(KEV_INPUT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    have = {str(entry["cve"]) for entry in cve_entries}
    return {cve: value for cve, value in stored.items() if cve in have}


def build_nuclei(cve_entries: List[Dict[str, object]]) -> Dict[str, object]:
    """Severity, CVSS, EPSS and CWE per CVE, limited to the ones indexed."""
    try:
        stored = json.loads(NUCLEI_INPUT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    have = {str(entry["cve"]) for entry in cve_entries}
    keep = ("severity", "cvss", "cvss_vector", "epss", "epss_pct", "cwe")
    return {
        cve: {field: value[field] for field in keep if field in value}
        for cve, value in stored.items()
        if cve in have
    }


def build_trending(blacklist: Collection[str]) -> List[Dict[str, object]]:
    """The trending job's own output, minus anything the blacklist covers."""
    try:
        rows = json.loads(TRENDING_INPUT.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    return [
        row for row in rows
        if row.get("url") and not is_blacklisted(str(row["url"]), blacklist)
    ]


def write_json(path: Path, data, *, indent: Optional[int] = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=indent,
                  separators=None if indent else (",", ":"))


def main() -> int:
    argparse.ArgumentParser(description="Build the CVE PoC site data files").parse_args()

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    blacklist = load_blacklist()

    cve_payload, total_cves = build_cve_list(blacklist)
    write_json(CVE_OUTPUT, cve_payload)

    repo_meta = build_repo_meta(cve_payload)
    write_json(REPO_META_OUTPUT, repo_meta)

    kev = build_kev(cve_payload)
    write_json(KEV_OUTPUT, kev)

    nuclei = build_nuclei(cve_payload)
    write_json(NUCLEI_OUTPUT, nuclei)

    trending_items = build_trending(blacklist)
    write_json(
        TRENDING_OUTPUT,
        {
            "generated": datetime.now(timezone.utc).isoformat(),
            "total_cves": total_cves,
            "with_pocs": len(cve_payload),
            "items": trending_items,
        },
        indent=2,
    )

    print(
        f"Wrote {CVE_OUTPUT.name} ({len(cve_payload)} of {total_cves} CVEs), "
        f"{REPO_META_OUTPUT.name} ({len(repo_meta)} repositories), "
        f"{KEV_OUTPUT.name} ({len(kev)} known-exploited), "
        f"{NUCLEI_OUTPUT.name} ({len(nuclei)} rated) and {TRENDING_OUTPUT.name}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
