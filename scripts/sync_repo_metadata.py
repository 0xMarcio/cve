#!/usr/bin/env python3
"""Refresh public repository stars independently of the slower link audit."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from pathlib import Path

from update_cves import GITHUB_GRAPHQL_URL, GitHubClient, http_json, repository_is_nonpublic
import link_health

ROOT = Path(__file__).resolve().parents[1]
METADATA = ROOT / "index" / "repo_meta.json"
STATE = ROOT / ".github" / "repo_metadata_state.json"
BATCH = 50


def load(path: Path) -> dict:
    try:
        result = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    if not isinstance(result, dict):
        raise ValueError(f"{path} must contain an object")
    return result


def save(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent, delete=False) as handle:
        json.dump(payload, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        temporary = Path(handle.name)
    try:
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def remember(repositories: list[dict]) -> None:
    """Reuse fresh REST search readings instead of leaving the search cache stale."""
    from build_site import repo_from_url
    readings = {}
    for repo in repositories:
        name = repo_from_url(repo.get("html_url") or "")
        stars = repo.get("stargazers_count")
        if name and type(stars) is int and stars >= 0 and not repository_is_nonpublic(repo):
            readings[name] = [stars, str(repo.get("pushed_at") or "")[:10]]
    if readings:
        stored = load(METADATA)
        stored.update(readings)
        save(METADATA, stored)


def survey(names: list[str], client: GitHubClient) -> tuple[dict, set[str], set[str]]:
    """Partial failures retain cached values; only explicit public metadata is used."""
    def check(batch: list[str]) -> tuple[dict, set[str], set[str]]:
        aliases = " ".join(
            f"r{i}: repository(owner: {json.dumps(name.split('/', 1)[0])}, "
            f"name: {json.dumps(name.split('/', 1)[1])}) "
            "{ nameWithOwner isPrivate visibility stargazerCount pushedAt }"
            for i, name in enumerate(batch)
        )
        try:
            payload = http_json(GITHUB_GRAPHQL_URL, headers=client.headers,
                                data={"query": "query { " + aliases + " }"})
        except Exception as problem:
            print(f"Repository metadata deferred for {len(batch)} repositories: {problem}")
            return {}, set(), set(batch)
        if not isinstance(payload, dict):
            return {}, set(), set(batch)
        errors = payload.get("errors") or []
        if any(not problem.get("path") for problem in errors):
            return {}, set(), set(batch)
        readings, unavailable, failed = {}, set(), set()
        for i, name in enumerate(batch):
            alias = f"r{i}"
            problems = [e for e in errors if e["path"][0] == alias]
            if problems:
                if all(e.get("type") == "NOT_FOUND" and len(e["path"]) == 1 for e in problems):
                    unavailable.add(name)
                else:
                    failed.add(name)
                continue
            repo = (payload.get("data") or {}).get(alias)
            if not isinstance(repo, dict):
                failed.add(name)
                continue
            if repository_is_nonpublic(repo):
                unavailable.add(name)
                continue
            if repo.get("isPrivate") is not False or repo.get("visibility") != "PUBLIC":
                failed.add(name)
                continue
            stars = repo.get("stargazerCount")
            if type(stars) is not int or stars < 0 or "pushedAt" not in repo:
                failed.add(name)
                continue
            # Preserve the requested key after a rename: existing links still use it.
            readings[name.lower()] = [stars, str(repo.get("pushedAt") or "")[:10]]
        return readings, unavailable, failed

    readings, unavailable, failed = {}, set(), set()
    batches = [names[i:i + BATCH] for i in range(0, len(names), BATCH)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        for found, absent, errors in pool.map(check, batches):
            readings.update(found)
            unavailable.update(absent)
            failed.update(errors)
    return readings, unavailable, failed


def scope(entries: list[dict], stored: dict, frontpage: list[dict], cursor: str,
          limit: int, deferred: set[str] | None = None) -> tuple[list[str], str]:
    from build_site import CURATED, repo_from_url
    fields = ["poc", *(field for _, field in CURATED)]
    linked = {name for entry in entries for field in fields for url in entry.get(field, [])
              if (name := repo_from_url(url))}
    priority = {name for row in frontpage if (name := repo_from_url(row.get("url") or ""))}
    names = sorted(linked)
    rotating = [name for name in names if name > cursor] + [name for name in names if name <= cursor]
    rotating = rotating[:limit] if limit else rotating
    selected = ((linked - stored.keys()) | priority | set(rotating)
                | set(link_health.load()["repositories"])) - (deferred or set())
    # A transient failure must not hide a front-page check for up to 24 hours.
    selected |= priority
    return sorted(selected), rotating[-1] if rotating else cursor


def main() -> int:
    from build_site import build_cve_list, build_landed, build_trending, load_blacklist
    from audit_poc_links import is_repository_url, prune_unavailable, slice_after, interleave_by_host
    from build_site import CURATED
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=2000, help="Older repositories per run; 0 refreshes all")
    parser.add_argument("--references", type=int, default=500, help="Older artifact URLs per run; 0 skips them")
    parser.add_argument("--retry-deferred", action="store_true", help="Also recheck repositories in retry cooldown")
    args = parser.parse_args()
    if args.limit < 0 or args.references < 0:
        parser.error("Limits must not be negative")
    entries, _ = build_cve_list(load_blacklist())
    stored, state = load(METADATA), load(STATE)
    frontpage = build_trending(load_blacklist()) + build_landed(entries, stored, {})
    now = datetime.now(timezone.utc)
    retries = state.get("retries", {})
    deferred = {name for name, row in retries.items() if row.get("after", "") > now.isoformat()}
    if args.retry_deferred:
        deferred = set()
    names, cursor = scope(entries, stored, frontpage, state.get("cursor", ""), args.limit, deferred)
    client = GitHubClient(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "")
    print(f"Checking public availability and metadata for {len(names)} repositories", flush=True)
    readings, unavailable, failed = survey(names, client)
    # An API NOT_FOUND can reflect token permissions. Require the same public
    # GET failure a visitor sees before withdrawing any existing public link.
    public_urls = [f"https://github.com/{name}" for name in sorted(unavailable)]
    confirmed, _ = link_health.survey_urls(public_urls, workers=2)
    missing = {name for name in unavailable if f"https://github.com/{name}" in confirmed}
    failed |= unavailable - missing
    unavailable = missing
    link_health.record(missing=unavailable, healthy=readings)
    stored.update(readings)
    for name in unavailable:
        stored.pop(name, None)
    for name in readings:
        retries.pop(name, None)
    for name in unavailable | failed:
        attempts = retries.get(name, {}).get("attempts", 0) + 1
        hours = 6 if name in unavailable else min(24, 2 ** min(attempts, 5))
        retries[name] = {"attempts": attempts, "after": (now + timedelta(hours=hours)).isoformat()}
    save(METADATA, stored)
    reference_cursor = state.get("reference_cursor", "")
    if args.references:
        urls = sorted({url for entry in entries for field in ["poc", *(f for _, f in CURATED)]
                       for url in entry.get(field, []) if not is_repository_url(url)
                       and not link_health.unavailable(url)})
        rotating = slice_after(urls, reference_cursor, args.references)
        priority = {row["url"] for row in frontpage if row.get("url")
                    and not is_repository_url(row["url"]) and not link_health.unavailable(row["url"])}
        window = interleave_by_host(sorted(set(rotating) | priority))
        dead, live = link_health.survey_urls(window, workers=16, timeout=5)
        link_health.record(dead_urls=dead, live_urls=live)
        reference_cursor = rotating[-1] if rotating else reference_cursor
        print(f"Artifact URLs: {len(window)} checked, {len(dead)} confirmed dead, "
              f"{len(window) - len(dead) - len(live)} inconclusive")
    prune_unavailable()
    # Healthy work keeps moving even when one repository persistently fails.
    save(STATE, {"cursor": cursor, "reference_cursor": reference_cursor,
                 "checked": now.isoformat(), "retries": retries})
    print(f"Repository metadata: {len(names)} checked, {len(readings)} refreshed, "
          f"{len(unavailable)} unavailable, {len(failed)} deferred")
    if failed:
        print(f"::warning::{len(failed)} repository checks were inconclusive; cached data retained and retries scheduled")
    summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if summary:
        with open(summary, 'a', encoding='utf-8') as handle:
            handle.write(f'### Repository metadata\n\n{len(readings)} refreshed, {len(unavailable)} confirmed unavailable, '
                         f'{len(failed)} deferred with cached data retained.\n')
    return int(bool(failed) and not readings and not unavailable)


if __name__ == "__main__":
    raise SystemExit(main())
