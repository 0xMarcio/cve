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
KEV = os.path.join(ROOT, "kev.json")
STATS = os.path.join(ROOT, "docs", "stats.json")
DESC_LIMIT = 110   # a table cell, not a paragraph
FOLDED_AFTER = 2   # years past the newest two are collapsed behind a summary
CVE_ID = re.compile(r"CVE[-_](\d{4})[-_](\d{4,7})", re.IGNORECASE)
SLUG = "0xMarcio/cve"
HERO_URL = f"https://raw.githubusercontent.com/{SLUG}/main/docs/hero.svg"


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
    for amount, unit in ((delta.days, "d"), (delta.seconds // 3600, "h"), (delta.seconds // 60, "m")):
        if amount > 0:
            return f"{amount}{unit} ago"
    return "just now"


def cell(value: str) -> str:
    """Keep repository text on a single markdown table cell."""
    text = " ".join(str(value or "").split()).replace("|", "/")
    return text.replace("\u2014", "-").replace("\u2013", "-")



def known_exploited() -> set[str]:
    """CVE ids CISA lists as exploited in the wild."""
    try:
        with open(KEV, encoding="utf-8") as handle:
            return {str(key).upper() for key in json.load(handle)}
    except (OSError, ValueError):
        return set()


def cve_of(repo: dict) -> str:
    match = CVE_ID.search(f"{repo.get('name') or ''} {repo.get('description') or ''}")
    return f"CVE-{match.group(1)}-{match.group(2)}" if match else ""


def shorten(text: str) -> str:
    text = cell(text)
    if len(text) <= DESC_LIMIT:
        return text
    return text[:DESC_LIMIT].rsplit(" ", 1)[0] + "\u2026"


def figures() -> dict:
    """Index totals, written by hero.py from the same count the banner shows."""
    try:
        with open(STATS, encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return {}


def shields(text: str) -> str:
    """Escape one field of a shields badge path.

    The path is split on single hyphens, so a hyphen inside the text has to be
    doubled before it is percent-encoded or the badge loses everything after it.
    """
    return parse.quote(text.replace("-", "--").replace("_", "__"), safe="")


def pill(label: str, value: str, colour: str, link: str) -> str:
    """A shields badge whose text is baked in at build time.

    Anything describing the index is fixed here rather than resolved when the
    page is viewed: the figure is then exactly the one the banner was drawn
    from, and it cannot degrade to "resource not found" when a lookup fails.
    """
    return (f"[![{label}](https://img.shields.io/badge/"
            f"{shields(label)}-{shields(value)}-{colour}"
            f"?style=flat-square&labelColor=161b22)]({link})")


def live_pill(path: str, label: str, colour: str, link: str, stamp: str) -> str:
    """A shields badge that has to be resolved at view time.

    The stamp is ignored by shields but changes the URL every rebuild, so
    GitHub's image proxy fetches a fresh badge instead of replaying a cached one.
    """
    return (f"[![{label}](https://img.shields.io/github/{path}"
            f"?style=flat-square&label={parse.quote(label)}&color={colour}"
            f"&labelColor=161b22&_={stamp})]({link})")


def header(stamp: str, synced: str) -> list[str]:
    """Everything above the tables. The banner carries a cache-busting stamp
    because GitHub proxies README images and would otherwise serve a stale copy
    of a file that is redrawn whenever the index moves."""
    counts = figures()
    home = "https://cve.codepwn.win/"
    badges = [
        pill("last sync", synced, "2f81f7", f"https://github.com/{SLUG}/commits/main"),
        live_pill("actions/workflow/status/" + SLUG + "/hot_cves.yml", "CI", "2f81f7",
                  f"https://github.com/{SLUG}/actions/workflows/hot_cves.yml", stamp),
    ]
    if counts.get("with_pocs"):
        badges.append(pill("CVEs with PoCs", f"{counts['with_pocs']:,}", "2f81f7", home))
    if counts.get("kev"):
        badges.append(pill("known exploited", f"{counts['kev']:,}", "f85149", home))
    badges.append(live_pill("stars/" + SLUG, "stars", "e3b341",
                            f"https://github.com/{SLUG}/stargazers", stamp))
    return [
        '<div align="center">',
        "",
        f'<a href="{home}"><img src="{HERO_URL}?v={stamp}" alt="CVE Radar" width="100%"></a>',
        "",
        "&nbsp;".join(badges),
        "",
        "</div>",
        "",
    ]


FOOTER = """

## Data

Every file is plain JSON on the CDN. No key, no rate limit.

```bash
curl -s https://cve.codepwn.win/CVE_list.json | jq '.[] | select(.cve=="CVE-2026-75604")'
curl -s https://cve.codepwn.win/kev.json | jq 'keys | length'
curl -s https://cve.codepwn.win/repo_meta.json | jq '."sfewer-r7/CVE-2026-55040"'
curl -s https://cve.codepwn.win/trending_poc.json | jq '{total_cves, with_pocs}'
```

| Endpoint | Holds |
| --- | --- |
| [`CVE_list.json`](https://cve.codepwn.win/CVE_list.json) | Every indexed CVE, its description and its PoC links |
| [`kev.json`](https://cve.codepwn.win/kev.json) | CISA known exploited, keyed by CVE id |
| [`repo_meta.json`](https://cve.codepwn.win/repo_meta.json) | Stars and last push date per PoC repository |
| [`trending_poc.json`](https://cve.codepwn.win/trending_poc.json) | Trending repositories plus index totals |
| [`2026/CVE-2026-75604.md`](2026/CVE-2026-75604.md) | Markdown copy of one CVE, one directory per year |

## Build

| Job | Cadence | Picks up |
| --- | --- | --- |
| [PoC sweep](.github/workflows/hot_cves.yml) | hourly | New and updated exploit repositories |
| [CVE sync](.github/workflows/sync_cve_pocs.yml) | daily | New CVEs and references from NVD and MITRE |
| [Link audit](.github/workflows/audit_poc_links.yml) | weekly | Repositories that went dead, dropped from the index |

A repository counts as updated only when a commit touches something other than
paperwork, so a README tweak cannot pass a year-old exploit off as recent.

## Contributing

Missing PoC, wrong link, dead repository: open an issue with the CVE id and the
repository URL.
"""


def main() -> int:
    now = datetime.now(timezone.utc)
    since = (now - timedelta(days=WINDOW_DAYS)).date().isoformat()
    current_year = now.year
    kev = known_exploited()
    items: list[dict] = []
    sections: list[list[str]] = []
    flagged = 0

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
              f"{stale - len(repositories)} dropped as paperwork-only")
        if not repositories:
            continue
        block = [
            f"## {year} &middot; newest {len(repositories)} of {total}",
            "",
            "| Stars | Updated | Repository | Description |",
            "| --- | --- | --- | --- |",
        ]
        for repo in repositories:
            # The last commit that touched anything but paperwork. pushed_at counts
            # a README tweak, which had the table claiming a year-old exploit was
            # updated twenty-one hours ago.
            pushed = repo["_shipped"]
            cve = cve_of(repo)
            exploited = cve in kev
            flagged += exploited
            items.append({
                "year": year,
                "stars": int(repo.get("stargazers_count") or 0),
                "name": cell(repo.get("name")),
                "url": repo.get("html_url") or "",
                "desc": cell(repo.get("description")),
                "pushed": pushed,
                "created": str(repo.get("created_at") or ""),
                "cve": cve,
                "kev": exploited,
            })
            block.append(
                f"| {repo.get('stargazers_count', 0)}\u2b50 | {time_ago(pushed)} "
                f"| {'\U0001f525 ' if exploited else ''}[{cell(repo.get('name'))}]({repo.get('html_url')}) "
                f"| {shorten(repo.get('description'))} |"
            )
        sections.append(block)

    stamp = now.strftime("%Y%m%d%H%M")
    # No hyphens: they are the field separator in a shields badge path.
    synced = now.strftime("%d %b %Y %H:%M UTC")
    lines = header(stamp, synced)
    lines.append(f"Exploit repositories with a commit in the last {WINDOW_DAYS} days, "
                 f"newest first. \U0001f525 marks a CVE on the CISA known exploited list.")
    lines.append("")
    for index, block in enumerate(sections):
        if index == FOLDED_AFTER and len(sections) > FOLDED_AFTER:
            years = ", ".join(section[0][3:7] for section in sections[FOLDED_AFTER:])
            lines.append(f"<details>\n<summary>{years}</summary>\n")
        lines.extend(block)
        lines.append("")
    if len(sections) > FOLDED_AFTER:
        lines.append("</details>")

    with open(README, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines).rstrip() + FOOTER)
    with open(TRENDING, "w", encoding="utf-8") as handle:
        json.dump(items, handle, ensure_ascii=False, indent=1)
        handle.write("\n")
    print(f"Wrote {README} and {TRENDING} ({len(items)} repositories, {flagged} known-exploited)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
