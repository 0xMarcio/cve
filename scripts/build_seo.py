#!/usr/bin/env python3
"""Write docs/robots.txt and docs/sitemap.xml.

Both files were 404 before this, so nothing told a crawler where the site ends
or how often it changes. Everything here is derived from scripts/brand.py, so a
domain move is one edit rather than a hunt through the tree.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from brand import SITE

DOCS = os.path.join(ROOT, "docs")
ROBOTS = os.path.join(DOCS, "robots.txt")
SITEMAP = os.path.join(DOCS, "sitemap.xml")

# Googlebot renders the page before it indexes it, so anything the first paint
# needs has to stay crawlable. These three are small and carry the only server
# rendered content on the page, the trending table and the header counts.
RENDER_CRITICAL = ("trending_poc.json", "kev.json", "stats.json")

# These only feed the search box, which a crawler never types into. Together they
# are over 13 MB on the wire, which is crawl budget spent on nothing. Blocking
# them here does not touch curl: robots.txt binds crawlers, not clients.
BULK_PAYLOADS = (
    "CVE_list.json",
    "cve_metadata.json",
    "epss.json",
    "repo_meta.json",
    "nuclei.json",
)


def robots() -> str:
    lines = ["User-agent: *", "Allow: /"]
    lines += [f"Disallow: /{name}" for name in BULK_PAYLOADS]
    lines += ["", f"Sitemap: {SITE}/sitemap.xml", ""]
    return "\n".join(lines)


def urlset(urls: list[tuple[str, str]]) -> str:
    body = "".join(
        f"  <url>\n    <loc>{loc}</loc>\n    <lastmod>{lastmod}</lastmod>\n  </url>\n"
        for loc, lastmod in urls
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{body}</urlset>\n"
    )


def sitemap_index(names: list[str], today: str) -> str:
    body = "".join(
        f"  <sitemap>\n    <loc>{SITE}/{name}</loc>\n"
        f"    <lastmod>{today}</lastmod>\n  </sitemap>\n"
        for name in names
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{body}</sitemapindex>\n"
    )


def main() -> int:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    os.makedirs(DOCS, exist_ok=True)

    with open(ROBOTS, "w", encoding="utf-8") as handle:
        handle.write(robots())

    # One sitemap per CVE year. The 50,000 URL cap makes some split necessary and
    # the year is the split the data already has, which also means a crawler only
    # refetches the shard that moved.
    try:
        with open(os.path.join(DOCS, "CVE_list.json"), encoding="utf-8") as handle:
            cves = json.load(handle)
    except FileNotFoundError:
        cves = []

    years: dict[str, list[tuple[str, str]]] = {}
    for entry in cves:
        cid = entry["cve"]
        year = cid.split("-")[1]
        lastmod = entry.get("modified") or entry.get("published") or today
        years.setdefault(year, []).append((f"{SITE}/{cid}", lastmod))

    names = []
    for year in sorted(years):
        name = f"sitemap-{year}.xml"
        with open(os.path.join(DOCS, name), "w", encoding="utf-8") as handle:
            handle.write(urlset(years[year]))
        names.append(name)

    with open(os.path.join(DOCS, "sitemap-home.xml"), "w", encoding="utf-8") as handle:
        handle.write(urlset([(f"{SITE}/", today)]))
    names.insert(0, "sitemap-home.xml")

    with open(SITEMAP, "w", encoding="utf-8") as handle:
        handle.write(sitemap_index(names, today))

    total = sum(len(v) for v in years.values()) + 1
    print(f"Wrote {ROBOTS}, {SITEMAP} and {len(names)} shards ({total:,} URLs) for {SITE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
