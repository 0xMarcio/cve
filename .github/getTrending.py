#!/usr/bin/env python3
"""Regenerate the Trending PoCs tables in README.md.

- Consider the latest 4 years (current year and previous 3).
- Require repository name to contain a CVE for that year (e.g., CVE-2025-1234).
- Require a non-empty description (we only want actual PoCs, not empty shells).
- Restrict to repositories updated in the last 4 days.
- Sort by most recently updated, then stars, and emit up to 20 rows per year.
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


def fetch_trending(year: int, cutoff: datetime) -> List[Repo]:
    query = f"CVE-{year} in:name stars:>2 pushed:>={cutoff.date().isoformat()} archived:false"
    url = "https://api.github.com/search/repositories"
    params = {
        "q": query,
        "sort": "updated",
        "order": "desc",
        "per_page": 100,
        "page": 1,
    }
    resp = requests.get(url, params=params, headers=github_headers(), timeout=30)
    resp.raise_for_status()
    items: Iterable[Repo] = resp.json().get("items", [])
    pattern = re.compile(rf"cve-{year}-\d+", re.IGNORECASE)
    filtered: List[Repo] = []
    for item in items:
        name = item.get("name", "")
        updated_at = item.get("updated_at")
        description = (item.get("description") or "").strip()
        if not updated_at or not pattern.search(name or "") or not description:
            continue
        updated_dt = datetime.strptime(updated_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if updated_dt < cutoff:
            continue
        filtered.append(item)
    # Already sorted by updated desc; break ties by stars
    filtered.sort(key=lambda r: (-datetime.strptime(r["updated_at"], "%Y-%m-%dT%H:%M:%SZ").timestamp(), -int(r.get("stargazers_count", 0))))
    return filtered[:MAX_ROWS]


def build_rows(repos: List[Repo], now: datetime) -> List[str]:
    rows: List[str] = []
    for repo in repos:
        desc = repo.get("description") or ""
        stars = int(repo.get("stargazers_count", 0))
        updated = time_ago(repo["updated_at"], now)
        rows.append(f"| {stars}⭐ | {updated} | [{repo['name']}]({repo['html_url']}) | {desc} |")
    return rows


def main() -> None:
    current_year = datetime.now(timezone.utc).year
    cutoff = datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)
    now = datetime.now(timezone.utc)

    output: List[str] = ['<h1 align="center">Recently updated Proof-of-Concepts</h1>']

    for year in range(current_year, current_year - YEARS_BACK, -1):
        repos = fetch_trending(year, cutoff)
        output.append(f"\n\n## {year}\n")
        output.append(f"### Updated in the last {WINDOW_DAYS} days (up to {MAX_ROWS} repos)\n")
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
