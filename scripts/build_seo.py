#!/usr/bin/env python3
"""Write docs/robots.txt and docs/sitemap.xml.

Both files were 404 before this, so nothing told a crawler where the site ends
or how often it changes. Everything here is derived from scripts/brand.py, so a
domain move is one edit rather than a hunt through the tree.
"""

from __future__ import annotations

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


def sitemap(urls: list[tuple[str, str]]) -> str:
    body = "".join(
        f"  <url>\n    <loc>{loc}</loc>\n    <lastmod>{lastmod}</lastmod>\n  </url>\n"
        for loc, lastmod in urls
    )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        f"{body}"
        "</urlset>\n"
    )


def main() -> int:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    urls = [(f"{SITE}/", today)]

    os.makedirs(DOCS, exist_ok=True)
    with open(ROBOTS, "w", encoding="utf-8") as handle:
        handle.write(robots())
    with open(SITEMAP, "w", encoding="utf-8") as handle:
        handle.write(sitemap(urls))

    print(f"Wrote {ROBOTS} and {SITEMAP} ({len(urls)} URL) for {SITE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
