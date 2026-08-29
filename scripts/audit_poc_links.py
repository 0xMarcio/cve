#!/usr/bin/env python3
"""Locally validate and deduplicate CVE PoC links."""

from __future__ import annotations

import argparse
import bisect
import hashlib
import json
import re
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib import error, request
from urllib.parse import urlsplit, urlunsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))

import update_cves

ROOT = Path(__file__).resolve().parents[1]
STATE_FILE = ROOT / "data" / "link_audit_state.json"
INVENTORY_FILES = (ROOT / "github.txt", ROOT / "references.txt")
SECTION_EMPTY_TEXT = {
    "#### Reference": "No PoCs from references.",
    "#### Github": "No PoCs found on GitHub currently.",
}
GITHUB_RESERVED_OWNERS = {
    "about",
    "advisories",
    "apps",
    "collections",
    "codespaces",
    "events",
    "explore",
    "features",
    "login",
    "marketplace",
    "notifications",
    "orgs",
    "pricing",
    "search",
    "security",
    "settings",
    "site",
    "sponsors",
    "topics",
    "users",
}
USER_AGENT = "0xMarcio-cve-link-audit"


@dataclass(frozen=True)
class GitHubIdentity:
    key: str
    full_name: str
    suffix: str


@dataclass
class ApplyStats:
    markdown_files: int = 0
    inventory_files: int = 0
    removed: int = 0
    rewritten: int = 0
    deduplicated: int = 0


class HostThrottle:
    def __init__(self, interval: float) -> None:
        self.interval = interval
        self.guard = threading.Lock()
        self.locks: dict[str, threading.Lock] = {}
        self.last_start: dict[str, float] = {}

    def run(self, url: str, operation: Callable[[], str]) -> str:
        host = (urlsplit(url).hostname or "").lower()
        with self.guard:
            lock = self.locks.setdefault(host, threading.Lock())
        with lock:
            elapsed = time.monotonic() - self.last_start.get(host, 0.0)
            if elapsed < self.interval:
                time.sleep(self.interval - elapsed)
            self.last_start[host] = time.monotonic()
        return operation()


def raw_section_links(block: str) -> list[str]:
    links: list[str] = []
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if line.startswith("- "):
            line = line[2:].strip()
        if line.startswith(("http://", "https://")):
            links.append(line)
    return links


def section_links(text: str, header: str) -> list[str]:
    pattern = re.compile(
        update_cves.SECTION_RE_TEMPLATE.format(header=re.escape(header)),
        re.DOTALL,
    )
    match = pattern.search(text)
    return raw_section_links(match.group(2)) if match else []


def github_identity(url: str) -> GitHubIdentity | None:
    parsed = urlsplit(url)
    if (parsed.hostname or "").lower() not in {"github.com", "www.github.com"}:
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2 or parts[0].lower() in GITHUB_RESERVED_OWNERS:
        return None
    owner = parts[0]
    name = parts[1][:-4] if parts[1].lower().endswith(".git") else parts[1]
    if not owner or not name:
        return None
    full_name = f"{owner}/{name}"
    suffix = "/" + "/".join(parts[2:]) if len(parts) > 2 else ""
    return GitHubIdentity(full_name.lower(), full_name, suffix)


def canonical_github_url(url: str, canonical_base: str) -> str:
    identity = github_identity(url)
    if not identity:
        return url
    parsed = urlsplit(url)
    base = urlsplit(canonical_base.rstrip("/"))
    path = base.path.rstrip("/") + identity.suffix
    return urlunsplit(("https", "github.com", path, parsed.query, parsed.fragment))


def is_profile_repository_root(url: str) -> bool:
    identity = github_identity(url)
    if not identity or identity.suffix:
        return False
    owner, name = identity.full_name.lower().split("/", 1)
    return owner == name


def inventory_url(line: str) -> str:
    value = line.strip()
    if " - " in value:
        value = value.split(" - ", 1)[1].strip()
    return value if value.startswith(("http://", "https://")) else ""


def collect_links() -> set[str]:
    links: set[str] = set()
    for path in INVENTORY_FILES:
        if not path.exists():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if url := inventory_url(line):
                links.add(url)
    for path in ROOT.glob("[12][0-9][0-9][0-9]/CVE-*.md"):
        text = path.read_text(encoding="utf-8", errors="replace")
        for header in SECTION_EMPTY_TEXT:
            links.update(section_links(text, header))
    return links


def repository_names(links: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for url in links:
        identity = github_identity(url)
        if identity:
            result.setdefault(identity.key, identity.full_name)
    return result


def rotation_key(value: str) -> str:
    return f"{hashlib.sha256(value.encode('utf-8')).hexdigest()}:{value}"


def select_rotating(
    values: Iterable[str],
    after: str,
    limit: int,
    *,
    key: Callable[[str], str] = lambda value: value,
) -> tuple[list[str], str]:
    ordered = sorted(set(values), key=key)
    if not ordered:
        return [], ""
    if limit <= 0 or limit >= len(ordered):
        return ordered, ""
    keys = [key(value) for value in ordered]
    start = bisect.bisect_right(keys, after)
    selected = [ordered[(start + offset) % len(ordered)] for offset in range(limit)]
    return selected, key(selected[-1])


def request_result(url: str, method: str, timeout: int) -> str:
    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "identity",
        "User-Agent": USER_AGENT,
    }
    if method == "GET":
        headers["Range"] = "bytes=0-0"
    req = request.Request(url, headers=headers, method=method)
    try:
        with request.urlopen(req, timeout=timeout) as response:
            if method == "GET":
                response.read(1)
            return "alive" if int(response.status) < 400 else "unknown"
    except error.HTTPError as exc:
        code = exc.code
        exc.close()
        if code in {404, 410}:
            return "dead"
        return "unknown"
    except (error.URLError, TimeoutError, OSError):
        return "unknown"


def check_http_url(url: str, timeout: int, throttle: HostThrottle) -> str:
    def operation() -> str:
        head = request_result(url, "HEAD", timeout)
        if head == "alive":
            return head
        return request_result(url, "GET", timeout)

    return throttle.run(url, operation)


def audit_http(
    urls: list[str],
    *,
    workers: int,
    timeout: int,
    host_interval: float,
    label: str = "URLs",
) -> dict[str, str]:
    results: dict[str, str] = {}
    throttle = HostThrottle(host_interval)
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(check_http_url, url, timeout, throttle): url
            for url in urls
        }
        for count, future in enumerate(as_completed(futures), start=1):
            url = futures[future]
            try:
                results[url] = future.result()
            except Exception:
                results[url] = "unknown"
            if count == 1 or count % 250 == 0 or count == len(urls):
                print(f"{label} checked: {count} of {len(urls)}")
    return results


def rewrite_url(
    url: str,
    canonical: dict[str, str],
    missing: set[str],
    dead_urls: set[str],
) -> str | None:
    if url in dead_urls:
        return None
    identity = github_identity(url)
    if not identity:
        return url
    if identity.key in missing:
        return None
    base = canonical.get(identity.key)
    return canonical_github_url(url, base) if base else url


def rewrite_links(
    links: Iterable[str],
    canonical: dict[str, str],
    missing: set[str],
    dead_urls: set[str],
    cache: dict[str, str | None] | None = None,
    seen: set[str] | None = None,
) -> tuple[list[str], int, int, int]:
    output: list[str] = []
    seen = set() if seen is None else seen
    removed = 0
    rewritten = 0
    deduplicated = 0
    for url in links:
        if cache is not None and url in cache:
            updated = cache[url]
        else:
            updated = rewrite_url(url, canonical, missing, dead_urls)
            if cache is not None:
                cache[url] = updated
        if updated is None:
            removed += 1
            continue
        if updated != url:
            rewritten += 1
        key = update_cves.poc_link_key(updated)
        if key in seen:
            deduplicated += 1
            continue
        seen.add(key)
        output.append(updated)
    return output, removed, rewritten, deduplicated


def update_markdown(
    canonical: dict[str, str],
    missing: set[str],
    dead_urls: set[str],
    *,
    apply: bool,
    cache: dict[str, str | None] | None = None,
) -> ApplyStats:
    stats = ApplyStats()
    for path in ROOT.glob("[12][0-9][0-9][0-9]/CVE-*.md"):
        with path.open("r", encoding="utf-8", newline="") as handle:
            original = handle.read()
        updated = original
        changed = False
        seen: set[str] = set()
        for header, empty_text in SECTION_EMPTY_TEXT.items():
            links = section_links(updated, header)
            accepted = [
                url
                for url in links
                if not update_cves.github_url_is_ambiguous_root(url, path.stem)
            ]
            stats.removed += len(links) - len(accepted)
            replacement, removed, rewritten, deduplicated = rewrite_links(
                accepted,
                canonical,
                missing,
                dead_urls,
                cache,
                seen,
            )
            stats.removed += removed
            stats.rewritten += rewritten
            stats.deduplicated += deduplicated
            if replacement == links:
                continue
            updated, section_changed = update_cves.replace_section(
                updated,
                header,
                replacement,
                empty_text,
            )
            changed = changed or section_changed
        if not changed:
            continue
        stats.markdown_files += 1
        if apply:
            with path.open("w", encoding="utf-8", newline="") as handle:
                handle.write(updated)
    return stats


def update_inventory(
    path: Path,
    canonical: dict[str, str],
    missing: set[str],
    dead_urls: set[str],
    *,
    apply: bool,
    cache: dict[str, str | None] | None = None,
) -> ApplyStats:
    stats = ApplyStats()
    original = path.read_text(encoding="utf-8") if path.exists() else ""
    output: list[str] = []
    seen: set[str] = set()
    for line in original.splitlines():
        url = inventory_url(line)
        prefix = line.split(" - ", 1)[0] if " - " in line else ""
        if not url:
            updated_line = line
        else:
            if update_cves.github_url_is_ambiguous_root(url, prefix):
                stats.removed += 1
                continue
            if cache is not None and url in cache:
                updated_url = cache[url]
            else:
                updated_url = rewrite_url(url, canonical, missing, dead_urls)
                if cache is not None:
                    cache[url] = updated_url
            if updated_url is None:
                stats.removed += 1
                continue
            if updated_url != url:
                stats.rewritten += 1
            updated_line = f"{prefix} - {updated_url}" if prefix else updated_url
        dedupe_key = updated_line
        if url:
            dedupe_key = update_cves.poc_link_key(updated_url)
            if prefix:
                dedupe_key = f"{prefix} - {dedupe_key}"
        if dedupe_key in seen:
            stats.deduplicated += 1
            continue
        seen.add(dedupe_key)
        output.append(updated_line)
    updated = "\n".join(output) + ("\n" if output else "")
    if updated != original:
        stats.inventory_files = 1
        if apply:
            path.write_text(updated, encoding="utf-8")
    return stats


def add_stats(target: ApplyStats, source: ApplyStats) -> None:
    target.markdown_files += source.markdown_files
    target.inventory_files += source.inventory_files
    target.removed += source.removed
    target.rewritten += source.rewritten
    target.deduplicated += source.deduplicated


def load_state(path: Path) -> dict[str, Any]:
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return state if isinstance(state, dict) else {}


def save_state(path: Path, state: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Locally audit CVE PoC links")
    parser.add_argument("--apply", action="store_true", help="Write link and state changes")
    parser.add_argument(
        "--github-limit",
        type=int,
        default=0,
        help="GitHub repository roots checked per run; zero checks all",
    )
    parser.add_argument(
        "--http-limit",
        type=int,
        default=0,
        help="Exact URLs checked per run; zero checks all",
    )
    parser.add_argument("--workers", type=int, default=12)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--host-interval", type=float, default=0.1)
    parser.add_argument("--confirmations", type=int, default=2)
    parser.add_argument("--skip-github", action="store_true")
    parser.add_argument("--skip-http", action="store_true")
    parser.add_argument("--state-file", type=Path, default=STATE_FILE)
    args = parser.parse_args()
    if args.github_limit < 0 or args.http_limit < 0:
        parser.error("limits cannot be negative")
    if args.workers < 1 or args.timeout < 1 or args.confirmations < 1:
        parser.error("workers, timeout, and confirmations must be positive")
    if args.host_interval < 0:
        parser.error("--host-interval cannot be negative")
    return args


def main() -> int:
    args = parse_args()
    state = load_state(args.state_file)
    links = collect_links()
    names_by_key = repository_names(links)
    print(f"PoC links found: {len(links)} | GitHub repositories: {len(names_by_key)}")

    github_after = str(state.get("github_after") or "")
    missing_repo_candidates = {
        str(key): int(count)
        for key, count in (state.get("missing_repo_candidates") or {}).items()
        if key in names_by_key and isinstance(count, int) and count > 0
    }
    missing_repositories: set[str] = set()
    if not args.skip_github:
        selected_keys, github_after = select_rotating(
            names_by_key,
            github_after,
            args.github_limit,
        )
        roots_by_key = {
            key: f"https://github.com/{names_by_key[key]}"
            for key in selected_keys
        }
        results = audit_http(
            list(roots_by_key.values()),
            workers=args.workers,
            timeout=args.timeout,
            host_interval=args.host_interval,
            label="GitHub repository roots",
        )
        for key, url in roots_by_key.items():
            status = results[url]
            if status == "alive":
                missing_repo_candidates.pop(key, None)
            elif status == "dead":
                count = missing_repo_candidates.get(key, 0) + 1
                if count >= args.confirmations:
                    missing_repositories.add(key)
                    missing_repo_candidates.pop(key, None)
                else:
                    missing_repo_candidates[key] = count
        values = list(results.values())
        print(
            f"GitHub repository result: {values.count('alive')} live | "
            f"{values.count('dead')} dead | {values.count('unknown')} unknown | "
            f"{len(missing_repositories)} confirmed removals"
        )

    dead_candidates = {
        str(url): int(count)
        for url, count in (state.get("dead_candidates") or {}).items()
        if url in links and isinstance(count, int) and count > 0
    }
    dead_urls: set[str] = set()
    http_after = str(state.get("http_after") or "")
    if not args.skip_http:
        http_candidates = [
            url
            for url in links
            if not (
                (identity := github_identity(url))
                and not identity.suffix
            )
            and not (
                identity
                and identity.key in missing_repositories
            )
        ]
        selected_urls, http_after = select_rotating(
            http_candidates,
            http_after,
            args.http_limit,
            key=rotation_key,
        )
        results = audit_http(
            selected_urls,
            workers=args.workers,
            timeout=args.timeout,
            host_interval=args.host_interval,
            label="Exact URLs",
        )
        for url, status in results.items():
            if status == "alive":
                dead_candidates.pop(url, None)
            elif status == "dead":
                count = dead_candidates.get(url, 0) + 1
                if count >= args.confirmations:
                    dead_urls.add(url)
                    dead_candidates.pop(url, None)
                else:
                    dead_candidates[url] = count
        values = list(results.values())
        counts = {
            status: values.count(status)
            for status in {"alive", "dead", "unknown"}
        }
        print(
            f"Exact URL result: {counts['alive']} live | {counts['dead']} dead | "
            f"{counts['unknown']} unknown | {len(dead_urls)} confirmed removals"
        )

    profile_roots = {url for url in links if is_profile_repository_root(url)}
    dead_urls.update(profile_roots)
    if profile_roots:
        print(f"Profile repository roots to purge: {len(profile_roots)}")

    blacklist = update_cves.load_blacklist()
    blocked_repositories = {
        identity.key
        for url in links
        if (identity := github_identity(url))
        and update_cves.is_blacklisted_repo(identity.full_name, blacklist)
    }
    if blocked_repositories:
        print(f"Blacklisted repositories to purge: {len(blocked_repositories)}")
    removed_repositories = missing_repositories | blocked_repositories

    rewrite_cache: dict[str, str | None] = {}
    stats = update_markdown(
        {},
        removed_repositories,
        dead_urls,
        apply=args.apply,
        cache=rewrite_cache,
    )
    for path in INVENTORY_FILES:
        add_stats(
            stats,
            update_inventory(
                path,
                {},
                removed_repositories,
                dead_urls,
                apply=args.apply,
                cache=rewrite_cache,
            ),
        )

    if args.apply:
        save_state(
            args.state_file,
            {
                "dead_candidates": dead_candidates,
                "github_after": github_after,
                "http_after": http_after,
                "missing_repo_candidates": missing_repo_candidates,
            },
        )
        if stats.markdown_files:
            update_cves.regenerate_json()

    print(
        f"Changes: {stats.markdown_files} Markdown files | {stats.inventory_files} inventories | "
        f"{stats.removed} links removed | {stats.rewritten} rewritten | "
        f"{stats.deduplicated} duplicates removed"
    )
    if not args.apply and (stats.markdown_files or stats.inventory_files):
        print("Dry run only; pass --apply to write changes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
