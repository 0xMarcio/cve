#!/usr/bin/env python3
"""Regenerate the Trending PoCs tables in README.md.

Goals (matching the legacy README that worked well):
- Cover the current year plus the previous three.
- Keep the familiar heading “Latest 20 of N Repositories”.
- Only show repos updated in the last WINDOW_DAYS.
- Require a CVE-shaped repo name for that year and a non-empty description.
- Sort newest first, then by stars, and cap at MAX_ROWS per year.
"""

from __future__ import annotations

import os
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, List, TypedDict

import requests

WINDOW_DAYS = 4
MAX_ROWS = 20
YEARS_BACK = 4
MIN_STARS = 0  # keep low to capture fresh repos


class Repo(TypedDict):
    name: str
    html_url: str
    description: str | None
    stargazers_count: int
    updated_at: str


def github_headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def time_ago(updated_at: str, now: datetime) -> str:
    dt = datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    delta = now - dt
    if delta.days > 0:
        return "1 day ago" if delta.days == 1 else f"{delta.days} days ago"
    hours = delta.seconds // 3600
    if hours:
        return "1 hour ago" if hours == 1 else f"{hours} hours ago"
    minutes = (delta.seconds % 3600) // 60
    if minutes:
        return "1 minute ago" if minutes == 1 else f"{minutes} minutes ago"
    return "just now"


def _search_total(year: int) -> int:
    """Return total repositories matching CVE-year (used for table heading)."""
    stars_clause = f"stars:>{MIN_STARS}" if MIN_STARS >= 0 else "stars:>0"
    query = f"CVE-{year} in:name {stars_clause} archived:false"
    url = "https://api.github.com/search/repositories"
    resp = requests.get(
        url, params={"q": query, "per_page": 1}, headers=github_headers(), timeout=30
    )
    resp.raise_for_status()
    return int(resp.json().get("total_count", 0))


def fetch_trending(year: int, cutoff: datetime) -> tuple[List[Repo], int]:
    """Fetch and filter trending repos for a year, returning rows and total_count."""
    stars_clause = f"stars:>{MIN_STARS}" if MIN_STARS >= 0 else "stars:>0"
    query = f"CVE-{year} in:name {stars_clause} archived:false pushed:>={cutoff.date().isoformat()}"
    url = "https://api.github.com/search/repositories"
    total_count = _search_total(year)
    pattern = re.compile(rf"cve-{year}-\d+", re.IGNORECASE)
    filtered: List[Repo] = []
    seen_urls: set[str] = set()

    # Walk multiple pages to gather enough fresh repos (up to MAX_ROWS).
    for page in range(1, 2):
        params = {
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": 100,
            "page": page,
        }
        resp = requests.get(url, params=params, headers=github_headers(), timeout=30)
        resp.raise_for_status()
        items: Iterable[Repo] = resp.json().get("items", [])
        if not items:
            break
        for item in items:
            name = item.get("name", "")
            updated_at = item.get("updated_at")
            description = (item.get("description") or "").strip()
            html_url = item.get("html_url")
            if not updated_at or not html_url or not description:
                continue
            if not pattern.search(name or ""):
                continue
            updated_dt = datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if updated_dt < cutoff:
                continue
            if html_url in seen_urls:
                continue
            seen_urls.add(html_url)
            filtered.append(item)
        if len(filtered) >= MAX_ROWS:
            break

    # Already sorted by updated desc; break ties by stars
    filtered.sort(
        key=lambda r: (
            -datetime.strptime(r["updated_at"], "%Y-%m-%dT%H:%M:%SZ").timestamp(),
            -int(r.get("stargazers_count", 0)),
        )
    )
    return filtered[:MAX_ROWS], total_count


def build_rows(repos: List[Repo], now: datetime) -> List[str]:
    rows: List[str] = []
    for repo in repos:
        desc = repo.get("description") or ""
        stars = int(repo.get("stargazers_count", 0))
        updated = time_ago(repo["updated_at"], now)
        rows.append(f"| {stars}⭐ | {updated} | [{repo['name']}]({repo['html_url']}) | {desc} |")
    return rows


def main() -> None:
    now = datetime.now(timezone.utc)
    current_year = now.year
    cutoff = now - timedelta(days=WINDOW_DAYS)

    output: List[str] = ['<h1 align="center">Recently updated Proof-of-Concepts</h1>']

    for year in range(current_year, current_year - YEARS_BACK, -1):
        repos, total = fetch_trending(year, cutoff)
        output.append(f"\n\n## {year}\n")
        output.append(f"### Latest {MAX_ROWS} of {total} Repositories\n")
        output.append("| Stars | Updated | Name | Description |")
        output.append("| --- | --- | --- | --- |")
        if repos:
            output.extend(build_rows(repos, now))
        else:
            output.append("| 0⭐ | — | No recent CVE PoCs | No repositories matched the filters. |")

    Path("README.md").write_text("\n".join(output), encoding="utf-8")
    print(f"Wrote tables for {YEARS_BACK} years ending {current_year}")


if __name__ == "__main__":
    main()
