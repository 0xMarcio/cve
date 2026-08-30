#!/usr/bin/env python3
"""Prune PoC links to deleted repositories and refresh the metadata the site shows."""

from __future__ import annotations

import argparse
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable
from urllib import error, request
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

from update_cves import (
    GITHUB_GRAPHQL_URL,
    USER_AGENT,
    GitHubClient,
    github_repo_from_url,
    http_json,
    replace_section,
    section_links,
)

ROOT = Path(__file__).resolve().parents[1]
STATE_FILE = ROOT / ".github" / "link_audit_state.json"
GITHUB_LIST = ROOT / "github.txt"
REFERENCE_LIST = ROOT / "references.txt"
REPO_META = ROOT / "repo_meta.json"
KEV_FILE = ROOT / "kev.json"
KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
GITHUB_SECTION = "#### Github"
REFERENCE_SECTION = "#### Reference"
SECTION_EMPTY = {
    GITHUB_SECTION: "No PoCs found on GitHub currently.",
    REFERENCE_SECTION: "No PoCs from references.",
}
GITHUB_EMPTY = "No PoCs found on GitHub currently."
BATCH = 20


def collect_repositories() -> tuple[dict[str, list[tuple[Path, str]]], set[str]]:
    """Map prunable links to their entries, and name every repository the site shows.

    Only the GitHub section is prunable; a reference comes from the CVE record
    itself, so it stays even when it rots. Both sections need star counts.
    """
    prunable: dict[str, list[tuple[Path, str]]] = {}
    referenced: set[str] = set()
    for path in sorted(ROOT.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for url in section_links(text, GITHUB_SECTION):
            full_name = github_repo_from_url(url)
            if full_name and "/" in full_name:
                prunable.setdefault(full_name, []).append((path, url))
                referenced.add(full_name)
        for url in section_links(text, REFERENCE_SECTION):
            full_name = github_repo_from_url(url)
            if full_name and "/" in full_name:
                referenced.add(full_name)
    return prunable, referenced


def survey(client: GitHubClient, names: list[str]) -> tuple[set[str], dict[str, list]]:
    """Return the repositories GitHub reports as NOT_FOUND, and stars/last push for the rest.

    Anything else — a network error, a throttle, an unexpected response — leaves
    the repository out of both results, so an audit failure never drops a link.
    """
    batches = [names[index : index + BATCH] for index in range(0, len(names), BATCH)]
    missing: set[str] = set()
    metadata: dict[str, list] = {}
    checked = 0

    def check(batch: list[str]) -> tuple[set[str], dict[str, list]]:
        aliases = " ".join(
            f"r{index}: repository(owner: {json.dumps(name.split('/', 1)[0])}, "
            f"name: {json.dumps(name.split('/', 1)[1])}) "
            "{ nameWithOwner stargazerCount pushedAt }"
            for index, name in enumerate(batch)
        )
        payload = http_json(
            GITHUB_GRAPHQL_URL,
            headers=client.headers,
            data={"query": "query { " + aliases + " rateLimit { remaining resetAt } }"},
        )
        gone: set[str] = set()
        for entry in payload.get("errors") or []:
            path = entry.get("path") or []
            if str(entry.get("type") or "") == "NOT_FOUND" and path:
                index = str(path[0])[1:]
                if index.isdigit() and int(index) < len(batch):
                    gone.add(batch[int(index)])
        found: dict[str, list] = {}
        data = payload.get("data") or {}
        for index, name in enumerate(batch):
            repo = data.get(f"r{index}")
            if not repo:
                continue
            pushed = str(repo.get("pushedAt") or "")[:10]
            found[name.lower()] = [
                int(repo.get("stargazerCount") or 0),
                pushed,
            ]
        return gone, found

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(check, batch): batch for batch in batches}
        for future in as_completed(futures):
            batch = futures[future]
            try:
                gone, found = future.result()
                missing |= gone
                metadata.update(found)
            except Exception as exc:
                print(f"Kept {len(batch)} repositories after a failed check: {exc}", file=sys.stderr)
            checked += len(batch)
            if checked % 5000 < len(batch):
                print(f"Checked {checked} of {len(names)} repositories")
    return missing, metadata


def save_metadata(metadata: dict[str, list], alive: set[str], *, dry_run: bool) -> int:
    """Merge this run's readings over the stored ones and forget deleted repositories."""
    try:
        stored = json.loads(REPO_META.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        stored = {}
    stored.update(metadata)
    stored = {name: value for name, value in stored.items() if name.lower() in alive}
    if not dry_run:
        REPO_META.write_text(
            json.dumps(stored, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    return len(stored)


def prune_entries(
    references: dict[str, list[tuple[Path, str]]],
    missing: Iterable[str],
    *,
    dry_run: bool,
) -> tuple[int, int, set[str]]:
    dead_by_path: dict[Path, set[str]] = {}
    dead_urls: set[str] = set()
    for full_name in missing:
        for path, url in references.get(full_name, []):
            dead_by_path.setdefault(path, set()).add(url)
            dead_urls.add(url)

    for path, urls in sorted(dead_by_path.items()):
        with path.open("r", encoding="utf-8", newline="") as handle:
            text = handle.read()
        kept = [url for url in section_links(text, GITHUB_SECTION) if url not in urls]
        updated, changed = replace_section(text, GITHUB_SECTION, kept, GITHUB_EMPTY)
        if changed and not dry_run:
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(updated)
    removals = sum(len(urls) for urls in dead_by_path.values())
    return len(dead_by_path), removals, dead_urls


def prune_inventory(dead_urls: set[str], *, dry_run: bool) -> int:
    if not GITHUB_LIST.exists() or not dead_urls:
        return 0
    lines = GITHUB_LIST.read_text(encoding="utf-8").splitlines()
    kept = [line for line in lines if line.rsplit(" - ", 1)[-1].strip() not in dead_urls]
    if not dry_run and len(kept) != len(lines):
        GITHUB_LIST.write_text("\n".join(kept) + "\n", encoding="utf-8")
    return len(lines) - len(kept)


def collect_references() -> dict[str, list[tuple[Path, str]]]:
    """Every link that is not a GitHub repository, and where it appears."""
    references: dict[str, list[tuple[Path, str]]] = {}
    for path in sorted(ROOT.glob("[12][0-9][0-9][0-9]/CVE-*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        for header in (REFERENCE_SECTION, GITHUB_SECTION):
            for url in section_links(text, header):
                if not github_repo_from_url(url):
                    references.setdefault(url, []).append((path, header))
    return references


def interleave_by_host(urls: list[str]) -> list[str]:
    """Round-robin the hosts so a slice does not hammer one server in a burst."""
    hosts: dict[str, list[str]] = {}
    for url in urls:
        host = urlsplit(url).netloc.lower()
        hosts.setdefault(host, []).append(url)
    queues = list(hosts.values())
    ordered: list[str] = []
    while queues:
        for queue in list(queues):
            ordered.append(queue.pop(0))
            if not queue:
                queues.remove(queue)
    return ordered


def dead_references(urls: list[str], *, workers: int, timeout: int) -> set[str]:
    """URLs the web answers 404 or 410 for. Everything else keeps its link."""
    dead: set[str] = set()
    checked = 0

    def check(url: str) -> tuple[str, bool]:
        for method in ("HEAD", "GET"):
            request_headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}
            try:
                req = request.Request(url, method=method, headers=request_headers)
                with request.urlopen(req, timeout=timeout) as response:
                    if method == "GET":
                        response.read(1)
                    return url, False
            except error.HTTPError as exc:
                code = exc.code
                exc.close()
                # a server that dislikes HEAD is not a server without the page
                if method == "GET" or code not in {403, 405, 501}:
                    return url, code in {404, 410}
            except Exception:
                if method == "GET":
                    return url, False
        return url, False

    with ThreadPoolExecutor(max_workers=workers) as executor:
        for url, gone in executor.map(check, urls):
            if gone:
                dead.add(url)
            checked += 1
            if checked % 2000 == 0:
                print(f"Checked {checked} of {len(urls)} references")
    return dead


def prune_references(
    references: dict[str, list[tuple[Path, str]]],
    dead: set[str],
    *,
    dry_run: bool,
) -> tuple[int, int]:
    by_path: dict[Path, dict[str, set[str]]] = {}
    for url in dead:
        for path, header in references.get(url, []):
            by_path.setdefault(path, {}).setdefault(header, set()).add(url)

    removed = 0
    for path, headers in sorted(by_path.items()):
        with path.open("r", encoding="utf-8", newline="") as handle:
            text = path_text = handle.read()
        for header, urls in headers.items():
            empty = SECTION_EMPTY[header]
            kept = [url for url in section_links(text, header) if url not in urls]
            removed += len(section_links(text, header)) - len(kept)
            text, _ = replace_section(text, header, kept, empty)
        if text != path_text and not dry_run:
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(text)

    lines = REFERENCE_LIST.read_text(encoding="utf-8").splitlines() if REFERENCE_LIST.exists() else []
    kept_lines = [line for line in lines if line.rsplit(" - ", 1)[-1].strip() not in dead]
    if not dry_run and len(kept_lines) != len(lines):
        REFERENCE_LIST.write_text("\n".join(kept_lines) + "\n", encoding="utf-8")
    return removed, len(lines) - len(kept_lines)


def refresh_kev(*, dry_run: bool) -> int:
    """Store CISA's known-exploited catalogue: the CVEs attackers actually use.

    Keeps only what the page shows, so the whole catalogue costs a few tens of
    kilobytes. A failure leaves the previous file in place rather than
    dropping the badge off every entry.
    """
    try:
        payload = http_json(KEV_URL)
    except Exception as exc:
        print(f"Kept the stored KEV catalogue after a failed fetch: {exc}", file=sys.stderr)
        return 0
    entries = {}
    for item in (payload or {}).get("vulnerabilities") or []:
        cve_id = str(item.get("cveID") or "").upper()
        if cve_id:
            entries[cve_id] = [
                str(item.get("dateAdded") or "")[:10],
                1 if str(item.get("knownRansomwareCampaignUse") or "").lower() == "known" else 0,
            ]
    if entries and not dry_run:
        KEV_FILE.write_text(
            json.dumps(entries, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
    return len(entries)


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def save_state(state: dict, *, dry_run: bool) -> None:
    if dry_run:
        return
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def slice_after(items: list[str], cursor: str, limit: int) -> list[str]:
    """The next `limit` items after the cursor, wrapping at the end."""
    if not limit:
        return items
    start = next((i for i, item in enumerate(items) if item > cursor), 0) if cursor else 0
    window = items[start : start + limit]
    if len(window) < limit:
        window += items[: limit - len(window)]
    return window


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Drop PoC links to deleted repositories and refresh repo_meta.json"
    )
    parser.add_argument("--limit", type=int, default=0, help="Repositories to check this run")
    parser.add_argument("--references", type=int, default=0, help="Reference links to check this run")
    parser.add_argument("--workers", type=int, default=16, help="Concurrent reference requests")
    parser.add_argument("--timeout", type=int, default=12, help="Seconds per reference request")
    parser.add_argument("--dry-run", action="store_true", help="Report without writing files")
    args = parser.parse_args()

    references, referenced = collect_repositories()
    names = sorted(referenced)
    print(
        f"{sum(len(v) for v in references.values())} prunable links | "
        f"{len(names)} repositories to survey"
    )

    state = load_state()
    scope = slice_after(names, str(state.get("cursor") or ""), args.limit)
    print(f"Checking {len(scope)} repositories starting after {state.get('cursor') or 'the beginning'}")

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    missing, metadata = survey(GitHubClient(token), scope)
    print(f"{len(missing)} repositories no longer exist")

    entries, links, dead_urls = prune_entries(references, missing, dry_run=args.dry_run)
    inventory = prune_inventory(dead_urls, dry_run=args.dry_run)
    alive = {name.lower() for name in names if name not in missing}
    tracked = save_metadata(metadata, alive, dry_run=args.dry_run)
    state["cursor"] = scope[-1] if scope else ""

    print(f"Removed {links} links from {entries} entries | {inventory} inventory lines")
    print(f"Refreshed stars and last-push for {len(metadata)} repositories | {tracked} tracked")

    if args.references:
        references = collect_references()
        urls = sorted(references)
        window = slice_after(urls, str(state.get("reference_cursor") or ""), args.references)
        print(f"Checking {len(window)} of {len(urls)} reference links")
        gone = dead_references(
            interleave_by_host(window), workers=args.workers, timeout=args.timeout
        )
        ref_links, ref_lines = prune_references(references, gone, dry_run=args.dry_run)
        state["reference_cursor"] = window[-1] if window else ""
        print(f"Reference links returning 404 or 410: {len(gone)} | "
              f"removed {ref_links} links, {ref_lines} inventory lines")

    save_state(state, dry_run=args.dry_run)
    print(f"KEV catalogue: {refresh_kev(dry_run=args.dry_run)} known-exploited CVEs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
