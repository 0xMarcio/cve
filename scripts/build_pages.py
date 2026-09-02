#!/usr/bin/env python3
"""Render one static page per CVE, at the site root.

The index held 82,000 CVEs behind a single URL. Every one of them is a query
somebody types ("CVE-2026-72898 poc"), and the pages that answered those queries
belonged to other people. These are flat files at /CVE-2026-72898, no prefix and
no extension: GitHub Pages resolves an extensionless request to the .html beside
it, verified against the live site rather than assumed.

Nothing here is committed. The payloads this reads are already gitignored and
built in CI, so the pages go straight into the Pages artifact and git never sees
them. Rendering all of them costs about fifteen seconds.
"""

from __future__ import annotations

import html
import json
import os
import sys
from collections import defaultdict

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir)
sys.path.insert(0, os.path.join(ROOT, "scripts"))

from brand import BRAND, SITE

DOCS = os.path.join(ROOT, "docs")
RELATED = 6
GITHUB = "https://github.com/"

SOURCES = (
    ("nuclei", "Nuclei templates", "projectdiscovery/nuclei-templates"),
    ("msf", "Metasploit modules", "rapid7/metasploit-framework"),
    ("edb", "ExploitDB entries", "exploit-db.com"),
    ("vulhub", "Vulhub environments", "vulhub/vulhub"),
    ("collections", "Exploit collections", ""),
)


def load(name: str) -> dict | list:
    with open(os.path.join(DOCS, name), encoding="utf-8") as handle:
        return json.load(handle)


def esc(value) -> str:
    return html.escape(str(value or ""), quote=True)


def short(text: str, limit: int) -> str:
    text = " ".join((text or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rsplit(" ", 1)[0] + "…"


def best_cvss(rows: list) -> tuple | None:
    """The highest-scoring assessment, which is the one a reader wants first."""
    scored = [r for r in rows or [] if isinstance(r[1], (int, float))]
    return max(scored, key=lambda r: r[1]) if scored else None


def owner_of(url: str) -> str | None:
    if not url.startswith(GITHUB):
        return None
    parts = url[len(GITHUB):].split("/")
    return parts[0].lower() if parts and parts[0] else None


def build_related(cves: list) -> dict:
    """A crawlable graph. A sitemap gets pages discovered; links get them crawled
    sooner and pass context. Sharing a PoC author is a real relation, so it beats
    padding the page with neighbouring CVE numbers, which is used only as filler."""
    by_owner = defaultdict(list)
    for entry in cves:
        for url in entry.get("poc") or []:
            owner = owner_of(url)
            if owner:
                by_owner[owner].append(entry["cve"])
    # An author with hundreds of PoCs relates nothing in particular.
    by_owner = {o: v for o, v in by_owner.items() if 1 < len(v) <= 40}

    by_year = defaultdict(list)
    for entry in cves:
        by_year[entry["cve"].split("-")[1]].append(entry["cve"])
    position = {}
    for year, ids in by_year.items():
        ids.sort()
        for i, cid in enumerate(ids):
            position[cid] = (year, i)

    related = {}
    for entry in cves:
        cid = entry["cve"]
        seen = {cid}
        picks = []
        for url in entry.get("poc") or []:
            owner = owner_of(url)
            for other in by_owner.get(owner, ()):
                if other not in seen:
                    seen.add(other)
                    picks.append(other)
                if len(picks) >= RELATED:
                    break
            if len(picks) >= RELATED:
                break
        if len(picks) < RELATED:
            year, i = position[cid]
            siblings = by_year[year]
            for j in range(1, RELATED + 1):
                for k in (i - j, i + j):
                    if 0 <= k < len(siblings) and siblings[k] not in seen:
                        seen.add(siblings[k])
                        picks.append(siblings[k])
                    if len(picks) >= RELATED:
                        break
                if len(picks) >= RELATED:
                    break
        related[cid] = picks[:RELATED]
    return related


def link_rows(urls: list, repo_meta: dict) -> str:
    rows = []
    for url in urls:
        label = url[len(GITHUB):] if url.startswith(GITHUB) else url
        meta = repo_meta.get(label.lower()) if url.startswith(GITHUB) else None
        note = f"<span>{meta[0]}★ · {esc(meta[1])}</span>" if meta else ""
        rows.append(
            f'<li><a href="{esc(url)}" rel="nofollow noopener" target="_blank">'
            f"{esc(short(label, 90))}</a>{note}</li>"
        )
    return "".join(rows)


def page(entry: dict, data: dict) -> str:
    cid = entry["cve"]
    desc = " ".join((entry.get("desc") or "").split())
    pocs = entry.get("poc") or []
    cvss = best_cvss((data["meta"].get(cid) or {}).get("cvss"))
    ep = data["epss"].get(cid)
    flagged = data["kev"].get(cid)
    tpl = data["nuclei"].get(cid)

    count = f"{len(pocs):,} public PoC exploit" + ("" if len(pocs) == 1 else "s")
    title = f"{cid}: {count} | {BRAND}"
    meta_desc = short(f"{cid}. {count}. {desc}", 155)
    url = f"{SITE}/{cid}"

    chips = []
    if flagged:
        ransom = " RANSOMWARE" if flagged[1] else ""
        chips.append(f'<span class="chip chip-kev">KEV{ransom}</span>')
    if cvss:
        chips.append(
            f'<span class="chip chip-sev is-{esc(str(cvss[2]).lower())}">'
            f"{esc(cvss[2])} {esc(cvss[1])}</span>"
        )
    if ep:
        hot = " is-hot" if ep[0] >= 0.1 else ""
        chips.append(f'<span class="chip chip-epss{hot}">EPSS {ep[0] * 100:.1f}%</span>')

    facts = []
    for row in ((data["meta"].get(cid) or {}).get("cvss") or []):
        if isinstance(row[1], (int, float)):
            facts.append(
                f"<dt>CVSS v{esc(row[0])}</dt><dd>{esc(row[1])} {esc(row[2])}"
                f'<code>{esc(row[3])}</code></dd>'
            )
    if ep:
        facts.append(
            f"<dt>EPSS</dt><dd>{ep[0] * 100:.2f}% chance of exploitation in the next "
            f"30 days, {ep[1] * 100:.0f}th percentile</dd>"
        )
    if flagged:
        used = ", used in ransomware campaigns" if flagged[1] else ""
        facts.append(f"<dt>CISA KEV</dt><dd>added {esc(flagged[0])}{used}</dd>")
    if tpl:
        cwe = f" · {esc(tpl.get('cwe'))}" if tpl.get("cwe") else ""
        facts.append(f"<dt>Nuclei</dt><dd>{esc(tpl.get('severity'))}{cwe}</dd>")
    if entry.get("published"):
        facts.append(f"<dt>Published</dt><dd>{esc(entry['published'])}</dd>")
    if entry.get("modified"):
        facts.append(f"<dt>Updated</dt><dd>{esc(entry['modified'])}</dd>")

    blocks = []
    if pocs:
        blocks.append(
            f"<h2>Proof-of-concept exploits ({len(pocs):,})</h2>"
            f'<ul class="cve-links">{link_rows(pocs, data["repo_meta"])}</ul>'
        )
    for key, heading, _ in SOURCES:
        urls = entry.get(key) or []
        if urls:
            blocks.append(
                f"<h2>{heading} ({len(urls)})</h2>"
                f'<ul class="cve-links">{link_rows(urls, data["repo_meta"])}</ul>'
            )

    siblings = "".join(
        f'<li><a href="/{other}">{other}</a></li>' for other in data["related"].get(cid, ())
    )

    ld = json.dumps(
        {
            "@context": "https://schema.org",
            "@type": "TechArticle",
            "headline": f"{cid} proof-of-concept exploits",
            "url": url,
            "description": meta_desc,
            "datePublished": entry.get("published"),
            "dateModified": entry.get("modified") or entry.get("published"),
            "isPartOf": {"@type": "WebSite", "name": BRAND, "url": f"{SITE}/"},
        },
        separators=(",", ":"),
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>{esc(title)}</title>
<meta name="description" content="{esc(meta_desc)}"/>
<meta name="robots" content="index, follow, max-image-preview:large"/>
<link rel="canonical" href="{url}"/>
<meta property="og:type" content="article"/>
<meta property="og:site_name" content="{BRAND}"/>
<meta property="og:title" content="{esc(title)}"/>
<meta property="og:description" content="{esc(meta_desc)}"/>
<meta property="og:url" content="{url}"/>
<meta property="og:image" content="{SITE}/social-card.png"/>
<meta name="twitter:card" content="summary_large_image"/>
<meta name="twitter:title" content="{esc(title)}"/>
<meta name="twitter:description" content="{esc(meta_desc)}"/>
<meta name="twitter:image" content="{SITE}/social-card.png"/>
<link rel="icon" href="/favicon.ico"/>
<link rel="stylesheet" href="/style.css"/>
<script type="application/ld+json">{ld}</script>
</head>
<body>
<header class="container cve-bar"><a class="cve-home" href="/">{BRAND}</a>
<form class="cve-search" role="search" action="/" method="get">
<input type="text" name="q" placeholder="Search CVE, vendor, product or keyword" aria-label="Search"/>
</form></header>
<main class="container cve-page">
<h1>{cid}</h1>
<div class="chips">{''.join(chips)}</div>
<p class="cve-desc">{esc(desc)}</p>
<dl class="cve-facts">{''.join(facts)}</dl>
{''.join(blocks)}
<h2>References</h2>
<ul class="cve-links">
<li><a href="https://www.cve.org/CVERecord?id={cid}" rel="nofollow noopener" target="_blank">CVE Record</a></li>
<li><a href="https://nvd.nist.gov/vuln/detail/{cid}" rel="nofollow noopener" target="_blank">NVD entry</a></li>
</ul>
{f'<h2>Related</h2><ul class="cve-related">{siblings}</ul>' if siblings else ''}
</main>
<footer class="site-footer"><div class="container">
<span>sources: nvd &middot; cve program &middot; github &middot; cisa kev &middot; first epss</span>
<span><a href="/">All {len(data['cves']):,} indexed CVEs</a></span>
</div></footer>
</body>
</html>
"""


def main() -> int:
    cves = load("CVE_list.json")
    data = {
        "cves": cves,
        "meta": load("cve_metadata.json"),
        "epss": load("epss.json"),
        "kev": load("kev.json"),
        "nuclei": load("nuclei.json"),
        "repo_meta": load("repo_meta.json"),
    }
    data["related"] = build_related(cves)

    written = 0
    for entry in cves:
        path = os.path.join(DOCS, f"{entry['cve']}.html")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(page(entry, data))
        written += 1

    print(f"Wrote {written:,} CVE pages into {DOCS}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
