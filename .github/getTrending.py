#!/usr/bin/env python3
"""Rebuild README.md with the most recently updated CVE proof-of-concept repositories."""

from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timedelta, timezone
from urllib import error, parse, request

SEARCH_URL = "https://api.github.com/search/repositories"
GRAPHQL_URL = "https://api.github.com/graphql"
# Editing a README is not updating a proof of concept. Everything a repository
# carries as paperwork is ignored when working out when its PoC last changed.
PAPERWORK = re.compile(
    r"^(?:readme|licen[cs]e|copying|notice|authors|contributing|code_of_conduct"
    r"|security|changelog|history|\.git|\.editorconfig|\.pre-commit)",
    re.IGNORECASE,
)
PATHS_PER_REPO = 12
LANGUAGES = (
    "Shell", "Go", "ASP", "WebAssembly", "R", "Lua", "Python", "C++", "C",
    "JavaScript", "Perl", "PowerShell", "Ruby", "Rust", "Java", "PHP",
)
YEARS = 5
PER_YEAR = 20
POOL = 50          # fetched per year before re-sorting by last commit
WINDOW_DAYS = 90   # a PoC nobody has touched this quarter is not "recent"
MIN_STARS = 2
USER_AGENT = "0xMarcio-cve-trending"
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)
README = os.path.join(ROOT, "README.md")
TRENDING = os.path.join(ROOT, "trending.json")


def search_year(year: int, since: str) -> tuple[int, list[dict]]:
    """Return how many PoC repositories for one CVE year were pushed since a
    date, and the most recently pushed of them.

    The API can only sort by updated_at, which also moves when a repository
    merely gains a star. Since a push always bumps updated_at too, the newest
    commits are guaranteed to sit near the top of that order: take a pool from
    there and re-sort it by the date the table actually shows.
    """
    query = " ".join(
        [f'"CVE-{year}" in:name', f"stars:>{MIN_STARS}", f"pushed:>{since}"]
        + [f"language:{language}" for language in LANGUAGES]
    )
    url = SEARCH_URL + "?" + parse.urlencode(
        {"q": query, "s": "updated", "o": "desc", "per_page": POOL}
    )
    headers = {"Accept": "application/vnd.github+json", "User-Agent": USER_AGENT}
    # The token authenticates the API only; it is never placed in the URL,
    # written to disk, or printed, so it cannot leak through logs or the commit.
    token = github_token()
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


def github_token() -> str:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""


def graphql(query: str, token: str) -> dict:
    body = json.dumps({"query": query}).encode("utf-8")
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT,
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    for attempt in range(3):
        try:
            with request.urlopen(
                request.Request(GRAPHQL_URL, data=body, headers=headers, method="POST"),
                timeout=45,
            ) as response:
                return json.load(response).get("data") or {}
        except error.HTTPError as exc:
            if exc.code not in {403, 429, 500, 502, 503, 504} or attempt == 2:
                raise
        except (error.URLError, TimeoutError, json.JSONDecodeError):
            if attempt == 2:
                raise
        time.sleep(4 * (attempt + 1))
    return {}


def repository_alias(index: int, full_name: str, body: str) -> str:
    owner, name = full_name.split("/", 1)
    return (
        f"r{index}: repository(owner: {json.dumps(owner)}, name: {json.dumps(name)}) "
        f"{{ {body} }}"
    )


def code_paths(full_names: list[str], token: str) -> dict[str, list[str]]:
    """Root entries of each repository that are not paperwork."""
    paths: dict[str, list[str]] = {}
    for start in range(0, len(full_names), 20):
        batch = full_names[start : start + 20]
        query = "query { " + " ".join(
            repository_alias(i, n, 'object(expression: "HEAD:") { ... on Tree { entries { name } } }')
            for i, n in enumerate(batch)
        ) + " }"
        data = graphql(query, token)
        for index, full_name in enumerate(batch):
            tree = ((data.get(f"r{index}") or {}).get("object") or {}).get("entries") or []
            names = [str(e.get("name") or "") for e in tree]
            paths[full_name] = [n for n in names if n and not PAPERWORK.match(n)][:PATHS_PER_REPO]
    return paths


def code_pushed(full_names: list[str], token: str) -> dict[str, str]:
    """When each repository last committed something that is not paperwork.

    A repository whose only recent commit edits the README has not shipped a
    new proof of concept, and saying it was updated an hour ago is a lie the
    whole front page is built on.
    """
    paths = code_paths(full_names, token)
    latest: dict[str, str] = {}
    batch: list[str] = []

    def flush(names: list[str]) -> None:
        if not names:
            return
        parts = []
        for index, full_name in enumerate(names):
            history = " ".join(
                f'p{j}: history(first: 1, path: {json.dumps(path)}) {{ nodes {{ committedDate }} }}'
                for j, path in enumerate(paths[full_name])
            )
            parts.append(repository_alias(
                index, full_name,
                f"defaultBranchRef {{ target {{ ... on Commit {{ {history} }} }} }}",
            ))
        data = graphql("query { " + " ".join(parts) + " }", token)
        for index, full_name in enumerate(names):
            target = ((data.get(f"r{index}") or {}).get("defaultBranchRef") or {}).get("target") or {}
            dates = [
                (target.get(f"p{j}") or {}).get("nodes", [{}])[0].get("committedDate")
                for j in range(len(paths[full_name]))
                if (target.get(f"p{j}") or {}).get("nodes")
            ]
            dates = [d for d in dates if d]
            if dates:
                latest[full_name] = max(dates)

    for full_name in full_names:
        if not paths.get(full_name):
            continue
        batch.append(full_name)
        if len(batch) == 6:
            flush(batch)
            batch = []
    flush(batch)
    return latest


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
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=WINDOW_DAYS)).date().isoformat()
    current_year = now.year
    lines = ['<h1 align="center">Recently updated Proof-of-Concepts</h1>']
    items: list[dict] = []

    token = github_token()
    for year in range(current_year, current_year - YEARS, -1):
        total, repositories = search_year(year, since)
        shipped = code_pushed([str(r.get("full_name") or "") for r in repositories], token)
        for repo in repositories:
            repo["_shipped"] = (
                shipped.get(str(repo.get("full_name") or ""))
                or str(repo.get("pushed_at") or repo.get("updated_at") or "")
            )
        stale = len(repositories)
        repositories = [r for r in repositories if r["_shipped"][:10] >= since]
        repositories.sort(key=lambda repo: repo["_shipped"], reverse=True)
        repositories = repositories[:PER_YEAR]
        print(f"CVE-{year}: {total} pushed since {since}, "
              f"{stale - len([r for r in repositories])} dropped as paperwork-only")
        if not repositories:
            continue
        lines.append(f"\n\n## {year}\n")
        lines.append(f"### Latest {len(repositories)} of {total} Repositories\n")
        lines.append("| Stars | Updated | Name | Description |")
        lines.append("| --- | --- | --- | --- |")
        for repo in repositories:
            # The last commit that touched anything but paperwork. pushed_at counts
            # a README tweak, which had the table claiming a year-old exploit was
            # updated twenty-one hours ago.
            pushed = repo["_shipped"]
            items.append({
                "year": year,
                "stars": int(repo.get("stargazers_count") or 0),
                "name": cell(repo.get("name")),
                "url": repo.get("html_url") or "",
                "desc": cell(repo.get("description")),
                "pushed": pushed,
                "created": str(repo.get("created_at") or ""),
            })
            lines.append(
                f"| {repo.get('stargazers_count', 0)}⭐ | {time_ago(pushed)} "
                f"| [{cell(repo.get('name'))}]({repo.get('html_url')}) | {cell(repo.get('description'))} |"
            )

    with open(README, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))
    with open(TRENDING, "w", encoding="utf-8") as handle:
        json.dump(items, handle, ensure_ascii=False, indent=1)
        handle.write("\n")
    print(f"Wrote {README} and {TRENDING} ({len(items)} repositories)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
