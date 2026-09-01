#!/usr/bin/env python3
"""Sync authoritative CVSS scores and advisory links from NVD.

NVD publishes CVSS v2.0, v3.0, v3.1 and v4.0 in one normalized feed and
adds human-curated tags to references from the CVE List. The compact year
shards written here keep every distinct published assessment and order each
generation deterministically: a Primary assessment first, then NVD, then the
source name. No score is calculated when a published vector is absent.
"""

from __future__ import annotations

import argparse
import gzip
import json
import re
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
CVES = ROOT / "cves"
INDEX = ROOT / "index"
OUTPUT = INDEX / "metadata"
ADVISORY_FILE = INDEX / "advisory_hosts.txt"
FEED_ROOT = "https://nvd.nist.gov/feeds/json/cve/2.0"
USER_AGENT = "0xMarcio-cve-metadata"
CVE = re.compile(r"^CVE-(\d{4})-(\d{4,})$")

# Newest CVSS generation first. The first valid row is the score displayed by
# the site; all generations remain available in the payload and tooltip.
METRIC_FIELDS = (
    ("cvssMetricV40", "4.0"),
    ("cvssMetricV31", "3.1"),
    ("cvssMetricV30", "3.0"),
    ("cvssMetricV2", "2.0"),
)

ADVISORY_TAGS = {
    "vendor advisory",
    "third party advisory",
    "mitigation",
    "patch",
    "release notes",
    "product",
    "issue tracking",
}
PRESERVED_TAGS = ADVISORY_TAGS | {"exploit"}
TAG_ORDER = {
    "Vendor Advisory": 0,
    "Third Party Advisory": 1,
    "Mitigation": 2,
    "Patch": 3,
    "Release Notes": 4,
    "Product": 5,
    "Issue Tracking": 6,
    "Advisory": 7,
    "Exploit": 8,
}
TAG_NAMES = {tag.lower(): tag for tag in TAG_ORDER}
SEVERITIES = {"NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def local_cves() -> set[str]:
    return {
        path.stem.upper()
        for path in CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md")
        if CVE.fullmatch(path.stem.upper())
    }


def load_advisory_rules() -> tuple[str, ...]:
    try:
        lines = ADVISORY_FILE.read_text(encoding="utf-8").splitlines()
    except OSError:
        return ()
    return tuple(
        line.strip().lower()
        for line in lines
        if line.strip() and not line.lstrip().startswith("#")
    )


def matches_advisory_rule(url: str, rules: Iterable[str]) -> bool:
    target = re.sub(r"^https?://(?:www\.)?", "", url.strip().lower())
    return any(target.startswith(rule) for rule in rules)


def qualitative_severity(version: str, score: float) -> str:
    if score == 0 and version != "2.0":
        return "NONE"
    if score < 4:
        return "LOW"
    if score < 7:
        return "MEDIUM"
    if version == "2.0" or score < 9:
        return "HIGH"
    return "CRITICAL"


def normalize_metric(metric: dict[str, Any], version: str) -> list[Any] | None:
    data = metric.get("cvssData") or {}
    vector = str(data.get("vectorString") or "").strip()
    try:
        score = round(float(data["baseScore"]), 1)
    except (KeyError, TypeError, ValueError):
        return None
    if not vector or not 0 <= score <= 10:
        return None
    supplied_version = str(data.get("version") or version).strip()
    if supplied_version != version:
        return None
    severity = str(data.get("baseSeverity") or metric.get("baseSeverity") or "").upper()
    if severity not in SEVERITIES:
        severity = qualitative_severity(version, score)
    source = str(metric.get("source") or "").strip()
    assessment = str(metric.get("type") or "").strip()
    return [version, score, severity, vector, source, assessment]


def metric_rank(row: list[Any]) -> tuple[int, int, str, str]:
    source = str(row[4]).lower()
    assessment = str(row[5]).lower()
    return (
        0 if assessment == "primary" else 1,
        0 if source == "nvd@nist.gov" else 1,
        source,
        str(row[3]),
    )


def cvss_metrics(cve: dict[str, Any]) -> list[list[Any]]:
    metrics = cve.get("metrics") or {}
    selected: list[list[Any]] = []
    for field, version in METRIC_FIELDS:
        rows = [
            normalized
            for item in metrics.get(field) or []
            if isinstance(item, dict)
            if (normalized := normalize_metric(item, version)) is not None
        ]
        seen: set[tuple[Any, ...]] = set()
        for row in sorted(rows, key=metric_rank):
            key = tuple(row)
            if key not in seen:
                selected.append(row)
                seen.add(key)
    return selected


def advisory_links(cve: dict[str, Any], rules: Iterable[str]) -> list[list[Any]]:
    links: dict[str, set[str]] = {}
    for reference in cve.get("references") or []:
        if not isinstance(reference, dict):
            continue
        url = str(reference.get("url") or "").strip()
        if not url.startswith(("http://", "https://")):
            continue
        raw_tags = [str(tag).strip() for tag in reference.get("tags") or []]
        advisory_tags = [TAG_NAMES[tag.lower()] for tag in raw_tags if tag.lower() in ADVISORY_TAGS]
        if not advisory_tags and not matches_advisory_rule(url, rules):
            continue
        tags = {TAG_NAMES[tag.lower()] for tag in raw_tags if tag.lower() in PRESERVED_TAGS}
        if not advisory_tags:
            tags.add("Advisory")
        links.setdefault(url.rstrip("/"), set()).update(tags)
    return [
        [url, sorted(tags, key=lambda tag: (TAG_ORDER.get(tag, 99), tag))]
        for url, tags in sorted(
            links.items(),
            key=lambda item: (
                min(TAG_ORDER.get(tag, 99) for tag in item[1]),
                item[0],
            ),
        )
    ]


def metadata_entry(cve: dict[str, Any], rules: Iterable[str]) -> dict[str, Any] | None:
    if str(cve.get("vulnStatus") or "").lower() == "rejected":
        return {"rejected": True}
    entry: dict[str, Any] = {}
    scores = cvss_metrics(cve)
    advisories = advisory_links(cve, rules)
    if scores:
        entry["cvss"] = scores
    if advisories:
        entry["advisories"] = advisories
    return entry or None


def feed_url(name: str) -> str:
    return f"{FEED_ROOT}/nvdcve-2.0-{name}.json.gz"


def load_feed(name: str) -> list[dict[str, Any]]:
    request = urllib.request.Request(feed_url(name), headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=900) as response:
        with gzip.GzipFile(fileobj=response) as compressed:
            payload = json.load(compressed)
    if payload.get("format") != "NVD_CVE" or payload.get("version") != "2.0":
        raise RuntimeError(f"{name}: unexpected NVD feed format")
    vulnerabilities = payload.get("vulnerabilities")
    if not isinstance(vulnerabilities, list):
        raise RuntimeError(f"{name}: NVD feed has no vulnerability list")
    return vulnerabilities


def load_shards() -> dict[str, dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    if not OUTPUT.exists():
        return entries
    for path in sorted(OUTPUT.glob("[12][0-9][0-9][0-9].json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as problem:
            raise RuntimeError(f"Cannot read {path}: {problem}") from problem
        if not isinstance(payload, dict):
            raise RuntimeError(f"{path} is not a CVE metadata object")
        entries.update(payload)
    return entries


def write_shards(entries: dict[str, dict[str, Any]], *, dry_run: bool) -> tuple[int, int]:
    by_year: dict[str, dict[str, Any]] = {}
    for cve_id, entry in entries.items():
        match = CVE.fullmatch(cve_id)
        if match:
            by_year.setdefault(match.group(1), {})[cve_id] = entry

    changed = 0
    removed = 0
    existing = set(OUTPUT.glob("[12][0-9][0-9][0-9].json")) if OUTPUT.exists() else set()
    for year, payload in sorted(by_year.items()):
        path = OUTPUT / f"{year}.json"
        rendered = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"
        try:
            current = path.read_text(encoding="utf-8")
        except OSError:
            current = ""
        if current == rendered:
            existing.discard(path)
            continue
        changed += 1
        existing.discard(path)
        if dry_run:
            continue
        OUTPUT.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=OUTPUT, delete=False) as handle:
            handle.write(rendered)
            temporary = Path(handle.name)
        temporary.replace(path)

    for path in existing:
        removed += 1
        if not dry_run:
            path.unlink()
    return changed, removed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sync NVD CVSS and advisory metadata")
    parser.add_argument("--full", action="store_true", help="process every yearly NVD feed")
    parser.add_argument("--year", action="append", type=int, default=[], help="process one NVD feed year")
    parser.add_argument("--dry-run", action="store_true", help="report without writing files")
    args = parser.parse_args()
    if args.full and args.year:
        parser.error("--full and --year cannot be combined")
    return args


def main() -> int:
    args = parse_args()
    held = local_cves()
    rules = load_advisory_rules()
    entries = {} if args.full else load_shards()
    if args.year:
        feed_names = sorted({str(max(2002, year)) for year in args.year})
    elif args.full:
        feed_names = [str(year) for year in range(2002, datetime.now(timezone.utc).year + 1)]
    else:
        feed_names = ["modified", "recent"]

    seen: set[str] = set()
    processed = 0
    for name in feed_names:
        vulnerabilities = load_feed(name)
        matched = 0
        for wrapper in vulnerabilities:
            cve = wrapper.get("cve") if isinstance(wrapper, dict) else None
            if not isinstance(cve, dict):
                continue
            cve_id = str(cve.get("id") or "").upper()
            if cve_id not in held:
                continue
            entry = metadata_entry(cve, rules)
            if entry is None:
                entries.pop(cve_id, None)
            else:
                entries[cve_id] = entry
            seen.add(cve_id)
            matched += 1
        processed += len(vulnerabilities)
        print(f"{name}: {len(vulnerabilities):,} NVD records, {matched:,} held CVEs")
        del vulnerabilities

    # A targeted year run replaces only CVEs present in those NVD feed years.
    # A complete run starts from an empty map, so withdrawn metadata disappears.
    entries = {cve: value for cve, value in entries.items() if cve in held}
    changed, removed = write_shards(entries, dry_run=args.dry_run)
    scored = sum(bool(entry.get("cvss")) for entry in entries.values())
    advised = sum(bool(entry.get("advisories")) for entry in entries.values())
    rejected = sum(bool(entry.get("rejected")) for entry in entries.values())
    print(
        f"metadata: {len(entries):,} CVEs, {scored:,} scored, {advised:,} with advisories, "
        f"{rejected:,} rejected | {changed:,} shards changed, {removed:,} removed"
    )
    print(f"processed {processed:,} NVD records; {len(seen):,} matched local CVEs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
