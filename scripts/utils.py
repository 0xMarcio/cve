from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import requests

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
DOCS_DIR = ROOT / "docs"
API_DIR = DOCS_DIR / "api" / "v1"
SNAPSHOT_DIR = API_DIR / "snapshots"
DIFFS_DIR = API_DIR / "diffs"
TOP_DIR = API_DIR / "top"
TEMPLATES_DIR = ROOT / "templates"
ASSETS_DIR = DOCS_DIR / "assets"
CACHE_DIR = DATA_DIR / "cache"
STATE_DIR = DATA_DIR / "state"
EVIDENCE_DIR = DATA_DIR / "evidence"


def ensure_dirs(*paths: Path) -> None:
    for path in paths:
        path.mkdir(parents=True, exist_ok=True)


def load_json(path: Path, default=None):
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def save_json(path: Path, data, *, sort_keys: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=sort_keys)


def fetch_json(url: str, *, timeout: int = 30, headers: Optional[Dict[str, str]] = None):
    response = requests.get(url, timeout=timeout, headers=headers or {})
    response.raise_for_status()
    return response.json()


def today_str() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def isoformat(dt: datetime | None = None) -> str:
    return (dt or now_utc()).isoformat()


def parse_date(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def slugify(text: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "-", text.strip().lower())
    cleaned = cleaned.strip("-")
    return cleaned or "unknown"


def stable_unique(items: Iterable[str]) -> List[str]:
    seen = set()
    output = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            output.append(item)
    return output


def maybe_float(value: str | float | int | None) -> Optional[float]:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# --- PoC data helpers ----------------------------------------------------


CVE_SECTION_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def load_poc_index() -> Dict[str, Dict[str, object]]:
    """Load CVE → {desc, poc} mapping from docs/CVE_list.json or markdown files."""
    cve_json = DOCS_DIR / "CVE_list.json"
    blacklist = load_blacklist()
    if cve_json.exists():
        data = load_json(cve_json, default=[]) or []
        mapping = {}
        for entry in data:
            cve = str(entry.get("cve", "")).upper()
            if not is_valid_cve(cve):
                continue
            desc = (entry.get("desc") or "").strip()
            poc_links = stable_unique(entry.get("poc", []) or [])
            poc_links = filter_links_by_blacklist(poc_links, blacklist)
            if not desc or not poc_links:
                continue
            mapping[cve] = {
                "desc": desc,
                "poc": poc_links,
            }
        return mapping

    return build_poc_index_from_markdown(blacklist=blacklist)


def build_poc_index_from_markdown(*, blacklist: Optional[List[str]] = None) -> Dict[str, Dict[str, object]]:
    mapping: Dict[str, Dict[str, object]] = {}
    for md_path in sorted(ROOT.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        cve = md_path.stem.upper()
        if not is_valid_cve(cve):
            continue
        desc, poc_links = parse_cve_markdown(md_path, blacklist=blacklist)
        mapping[cve] = {"desc": desc, "poc": poc_links}
    return mapping


def parse_cve_markdown(path: Path, *, blacklist: Optional[List[str]] = None) -> Tuple[str, List[str]]:
    text = path.read_text(encoding="utf-8")
    sections = parse_sections(text)
    description = normalise_block(sections.get("### Description", ""))
    blacklist = blacklist or []
    references = collect_links(sections.get("#### Reference", ""), blacklist=blacklist)
    github_links = collect_links(sections.get("#### Github", ""), blacklist=blacklist)
    poc_links = stable_unique([*references, *github_links])
    return description, poc_links


def normalise_block(text: str) -> str:
    text = text.replace("\r\n", "\n")
    text = re.sub(r"\n{2,}", "\n", text.strip())
    lines = [line.lstrip("- ").rstrip() for line in text.split("\n")]
    return "\n".join(line for line in lines if line)


def parse_sections(content: str) -> Dict[str, str]:
    sections: Dict[str, str] = {}
    current: Optional[str] = None
    buffer: List[str] = []

    for raw_line in content.splitlines():
        line = raw_line.strip()
        if line.startswith("### ") or line.startswith("#### "):
            if current is not None:
                sections[current] = "\n".join(buffer).strip()
            current = line
            buffer = []
        else:
            buffer.append(raw_line)

    if current is not None:
        sections[current] = "\n".join(buffer).strip()

    return sections


def collect_links(block: str, *, blacklist: Optional[List[str]] = None) -> List[str]:
    links: List[str] = []
    for raw in block.splitlines():
        entry = raw.strip()
        if not entry or "No PoCs" in entry:
            continue
        if entry.startswith("- "):
            entry = entry[2:].strip()
        if entry and entry not in links:
            links.append(entry)
    return filter_links_by_blacklist(links, blacklist or [])


def is_valid_cve(cve_id: str) -> bool:
    parts = cve_id.split("-")
    if len(parts) != 3:
        return False
    year = parts[1]
    return year.isdigit() and parts[2].isdigit()


def cve_year(cve_id: str) -> int | None:
    if not is_valid_cve(cve_id):
        return None
    try:
        return int(cve_id.split("-")[1])
    except (TypeError, ValueError):
        return None


# --- Trending PoCs -------------------------------------------------------

TREND_ROW_RE = re.compile(r"^\|\s*(?P<stars>\d+)\s*⭐\s*\|\s*(?P<updated>[^|]+)\|\s*\[(?P<name>[^\]]+)\]\((?P<url>[^)]+)\)\s*\|\s*(?P<desc>.*)\|$")


def parse_trending_from_readme(readme_path: Path) -> List[Dict[str, str]]:
    if not readme_path.exists():
        return []
    results: List[Dict[str, str]] = []
    current_year: Optional[str] = None
    for line in readme_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("## ") and line[3:].strip().isdigit():
            current_year = line[3:].strip()
            continue
        match = TREND_ROW_RE.match(line)
        if match and current_year:
            entry = match.groupdict()
            entry["year"] = current_year
            results.append(entry)
    # Keep deterministic order (README already ordered newest first)
    return results


# --- Misc helpers --------------------------------------------------------


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8") if path.exists() else ""


def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


# --- New helpers for PoC discovery -------------------------------------------------


def clamp(value: float, minimum: float = 0, maximum: float = 100) -> float:
    return max(minimum, min(maximum, value))


def chunked(iterable: Iterable, size: int) -> Iterable[List]:
    chunk: List = []
    for item in iterable:
        chunk.append(item)
        if len(chunk) >= size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


def hash_key(text: str) -> str:
    import hashlib

    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_blacklist(path: Path | None = None) -> List[str]:
    target = path or ROOT / "blacklist.txt"
    if not target.exists():
        return []
    entries: List[str] = []
    for raw in target.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            entries.append(line)
    return entries


def extract_repo_from_url(url: str) -> str:
    """Return repository name segment from a URL (best effort)."""
    try:
        from urllib.parse import urlparse

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
    if parts:
        return parts[-1].lower()
    return ""


def is_blacklisted_repo(url: str, blacklist: List[str]) -> bool:
    repo = extract_repo_from_url(url)
    if not repo:
        return False
    for entry in blacklist:
        slug = entry.strip().lower()
        if not slug:
            continue
        if slug.endswith("*"):
            prefix = slug[:-1]
            if prefix and repo.startswith(prefix):
                return True
        elif repo == slug:
            return True
    return False


def filter_links_by_blacklist(links: List[str], blacklist: List[str]) -> List[str]:
    if not blacklist:
        return links
    filtered: List[str] = []
    for link in links:
        if is_blacklisted_repo(link, blacklist):
            continue
        filtered.append(link)
    return filtered
