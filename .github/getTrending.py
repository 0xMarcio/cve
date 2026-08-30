#!/usr/bin/env python3
"""Rebuild README.md with the most recently updated CVE proof-of-concept repositories."""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from urllib import error, parse, request

SEARCH_URL = "https://api.github.com/search/repositories"
LANGUAGES = (
    "Shell", "Go", "ASP", "WebAssembly", "R", "Lua", "Python", "C++", "C",
    "JavaScript", "Perl", "PowerShell", "Ruby", "Rust", "Java", "PHP",
)
YEARS = 5
PER_YEAR = 20
MIN_STARS = 2
USER_AGENT = "0xMarcio-cve-trending"
README = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "README.md")


def search_year(year: int) -> tuple[int, list[dict]]:
    """Return the repository count and newest PoC repositories for one CVE year."""
    query = " ".join(
        [f'"CVE-{year}" in:name', f"stars:>{MIN_STARS}"]
        + [f"language:{language}" for language in LANGUAGES]
    )
    url = SEARCH_URL + "?" + parse.urlencode(
        {"q": query, "s": "updated", "o": "desc", "per_page": PER_YEAR}
    )
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    # The token authenticates the search API only; it is never placed in the URL,
    # written to disk, or printed, so it cannot leak through logs or the commit.
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    for attempt in range(3):
        try:
            with request.urlopen(request.Request(url, headers=headers), timeout=30) as response:
                payload = json.load(response)
            return int(payload.get("total_count") or 0), payload.get("items") or []
        except error.HTTPError as exc:
            if exc.code not in {403, 429, 500, 502, 503, 504} or attempt == 2:
                raise
        except (error.URLError, TimeoutError, json.JSONDecodeError):
            if attempt == 2:
                raise
        time.sleep(5 * (attempt + 1))
    raise RuntimeError(f"GitHub search failed for CVE-{year}")


def time_ago(timestamp: str) -> str:
    moment = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - moment
    for amount, unit in ((delta.days, "day"), (delta.seconds // 3600, "hour"), (delta.seconds // 60, "minute")):
        if amount > 0:
            return f"{amount} {unit}{'s' if amount > 1 else ''} ago"
    return "just now"


def cell(value: str) -> str:
    """Keep repository text on a single markdown table cell."""
    return " ".join(str(value or "").split()).replace("|", "/")


def main() -> int:
    current_year = datetime.now(timezone.utc).year
    lines = ['<h1 align="center">Recently updated Proof-of-Concepts</h1>']

    for year in range(current_year, current_year - YEARS, -1):
        total, repositories = search_year(year)
        print(f"CVE-{year}: {total} repositories")
        if not repositories:
            continue
        lines.append(f"\n\n## {year}\n")
        lines.append(f"### Latest {len(repositories)} of {total} Repositories\n")
        lines.append("| Stars | Updated | Name | Description |")
        lines.append("| --- | --- | --- | --- |")
        for repo in repositories:
            lines.append(
                f"| {repo.get('stargazers_count', 0)}⭐ | {time_ago(repo['updated_at'])} "
                f"| [{cell(repo.get('name'))}]({repo.get('html_url')}) | {cell(repo.get('description'))} |"
            )

    with open(README, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    print(f"Wrote {README}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
