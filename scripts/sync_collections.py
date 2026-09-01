#!/usr/bin/env python3
"""Index CVE-specific paths inside curated multi-CVE repositories."""

from __future__ import annotations

import argparse
import io
import re
import tarfile
import urllib.request
from collections import defaultdict
from pathlib import Path
from urllib.parse import quote

from update_cves import CVES, ensure_cve_entries

SECTION = "#### Collections"
USER_AGENT = "0xMarcio-cve-collections"
CVE = re.compile(r"(?i)CVE[-_](\d{4})[-_](\d{4,7})")
AFROG_PASSIVE = re.compile(
    r"(?im)^\s{2}name:\s*.*\b(?:version|protocol|service)\s+detection\b"
)

SOURCES = (
    ("afrog", "zan8in/afrog", "main"),
    ("vulnerability", "tzwlhack/Vulnerability", "main"),
    ("0day", "helloexp/0day", "master"),
    ("xray", "chaitin/xray", "master"),
)


def download(repo: str, branch: str) -> bytes:
    url = f"https://codeload.github.com/{repo}/tar.gz/refs/heads/{branch}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=900) as response:
        return response.read()


def cve_ids(value: str) -> set[str]:
    return {
        f"CVE-{year}-{number}"
        for year, number in CVE.findall(value)
        if 1999 <= int(year) <= 2100
    }


def github_link(repo: str, branch: str, kind: str, path: str) -> str:
    encoded = quote(path, safe="/()[]-_.")
    return f"https://github.com/{repo}/{kind}/{branch}/{encoded}"


def collect(repo: str, branch: str, archive: bytes) -> dict[str, list[str]]:
    rows: dict[str, set[str]] = defaultdict(set)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            parts = Path(member.name).parts
            if len(parts) < 2:
                continue
            relative = "/".join(parts[1:])
            suffix = parts[-1].lower()

            if repo == "zan8in/afrog":
                if "pocs/afrog-pocs/CVE/" not in relative or not suffix.endswith((".yaml", ".yml")):
                    continue
                handle = tar.extractfile(member)
                text = handle.read().decode("utf-8", "replace") if handle else ""
                if AFROG_PASSIVE.search(text):
                    continue
                target = github_link(repo, branch, "blob", relative)
                ids = cve_ids(parts[-1])
            elif repo == "tzwlhack/Vulnerability":
                if not suffix.endswith(".md"):
                    continue
                target = github_link(repo, branch, "blob", relative)
                ids = cve_ids(parts[-1])
            elif repo == "helloexp/0day":
                relative_parts = parts[1:]
                indexed = next(
                    (
                        (index, ids)
                        for index, part in enumerate(relative_parts)
                        if (ids := cve_ids(part))
                    ),
                    None,
                )
                if indexed is None:
                    continue
                index, ids = indexed
                target_path = "/".join(relative_parts[: index + 1])
                kind = "tree" if index < len(relative_parts) - 1 else "blob"
                target = github_link(repo, branch, kind, target_path)
            else:
                if not relative.startswith("pocs/") or not suffix.endswith((".yaml", ".yml")):
                    continue
                target = github_link(repo, branch, "blob", relative)
                ids = cve_ids(parts[-1])

            for cve_id in ids:
                rows[cve_id].add(target)
    return {cve: sorted(urls) for cve, urls in rows.items()}


def section_bounds(text: str) -> tuple[int, int, int] | None:
    marker = "\n" + SECTION
    head = text.find(marker)
    if head < 0:
        return None
    body = head + len(marker)
    end = text.find("\n#", body)
    return head, body, len(text) if end < 0 else end


def apply_links(cve: str, urls: list[str], *, dry_run: bool) -> str:
    path = CVES / cve.split("-")[1] / f"{cve}.md"
    if not path.exists():
        return "absent"
    original = path.read_text(encoding="utf-8")
    block = "\n" + "\n".join(f"- {url}" for url in urls) + "\n"
    bounds = section_bounds(original)
    if bounds:
        _, start, end = bounds
        if original[start:end] == block:
            return "unchanged"
        updated = original[:start] + block + original[end:]
    else:
        updated = original.rstrip("\n") + f"\n\n{SECTION}" + block
    if not dry_run:
        path.write_text(updated, encoding="utf-8")
    return "written"


def drop_section(path: Path, *, dry_run: bool) -> bool:
    original = path.read_text(encoding="utf-8")
    bounds = section_bounds(original)
    if not bounds:
        return False
    head, _, end = bounds
    updated = (original[:head] + original[end:]).rstrip("\n") + "\n"
    if not dry_run:
        path.write_text(updated, encoding="utf-8")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync path-level CVE PoC collections")
    parser.add_argument("--dry-run", action="store_true", help="report without writing")
    parser.add_argument("--cvelist-dir", type=Path, help="local CVE List V5 root for a large backfill")
    args = parser.parse_args()

    combined: dict[str, set[str]] = defaultdict(set)
    for name, repo, branch in SOURCES:
        try:
            found = collect(repo, branch, download(repo, branch))
        except Exception as problem:
            print(f"{repo}: unavailable ({problem})")
            return 1
        for cve, urls in found.items():
            combined[cve].update(urls)
        print(f"{name}: {len(found):,} CVEs, {sum(map(len, found.values())):,} path links")

    links = {cve: sorted(urls) for cve, urls in combined.items()}
    created, unavailable = ensure_cve_entries(
        links,
        dry_run=args.dry_run,
        cvelist_dir=args.cvelist_dir,
    )
    if created or unavailable:
        verb = "would create" if args.dry_run else "created"
        print(f"base entries: {len(created):,} {verb}, {len(unavailable):,} unpublished or unavailable")

    tally = {"written": 0, "unchanged": 0, "absent": 0}
    for cve, urls in sorted(links.items()):
        tally[apply_links(cve, urls, dry_run=args.dry_run)] += 1

    stale = 0
    for path in CVES.glob("[12][0-9][0-9][0-9]/CVE-*.md"):
        if path.stem not in links and ("\n" + SECTION) in path.read_text(
            encoding="utf-8", errors="replace"
        ):
            stale += drop_section(path, dry_run=args.dry_run)

    print(
        f"collections: {len(links):,} CVEs | {tally['written']:,} written, "
        f"{tally['unchanged']:,} unchanged, {tally['absent']:,} absent, {stale:,} stale removed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
