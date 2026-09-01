#!/usr/bin/env python3
"""Render the CVE Radar hero banner and social card as self-contained SVG.

Both cards are plain SVG with no external font, image or stylesheet reference:
GitHub proxies README images through camo, which fetches the file on its own and
would drop anything it has to resolve afterwards.
"""

from __future__ import annotations

import importlib.util
import json
import os
from urllib import request

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir))
BUILD_SITE = os.path.join(ROOT, "scripts", "build_site.py")
LIVE_STATS = "https://cve.codepwn.win/trending_poc.json"
LIVE_KEV = "https://cve.codepwn.win/kev.json"
HERO = os.path.join(ROOT, "docs", "hero.svg")
SOCIAL = os.path.join(ROOT, "docs", "social-card.svg")
STATS = os.path.join(ROOT, "docs", "stats.json")

CANVAS = "#0d1117"
SUBTLE = "#161b22"
BORDER = "#30363d"
FG = "#e6edf3"
MUTED = "#8b949e"
NEUTRAL = "#6e7681"
ACCENT = "#2f81f7"
DANGER = "#f85149"
MONO = "ui-monospace,SFMono-Regular,Menlo,Consolas,monospace"


def corpus_counts() -> dict | None:
    """Count the index the same way the site build does.

    The banner and the site header have to agree, so this reuses build_site's
    own parser instead of a second guess at what counts as a PoC. Roughly
    fifteen seconds over the whole corpus.
    """
    try:
        spec = importlib.util.spec_from_file_location("build_site", BUILD_SITE)
        build_site = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build_site)
        entries, total = build_site.build_cve_list(build_site.load_blacklist())
    except Exception as problem:
        print(f"corpus count failed: {problem}")
        return None
    if not total:
        return None
    return {
        "total_cves": total,
        "with_pocs": len(entries),
        "kev": len(build_site.build_kev(entries)),
    }


def live_stats() -> dict | None:
    """What the deployed site is currently serving.

    Only reached when the corpus itself will not parse, which on a normal
    checkout means something is broken rather than something is missing.
    """
    try:
        with request.urlopen(LIVE_STATS, timeout=20) as response:
            data = json.load(response)
        total = int(data.get("total_cves") or 0)
        pocs = int(data.get("with_pocs") or 0)
    except Exception as problem:
        print(f"live stats failed: {problem}")
        return None
    if not total or not pocs:
        return None
    try:
        # the site's copy, already narrowed to CVEs the index carries, so this
        # path reports the same figure the corpus count would
        with request.urlopen(LIVE_KEV, timeout=20) as response:
            kev = len(json.load(response))
    except Exception:
        kev = 0
    return {"total_cves": total, "with_pocs": pocs, "kev": kev}


def group(value: int) -> str:
    return f"{value:,}"


def sweep(cx: float, cy: float, radius: float, opacity: float) -> str:
    """Radar rings with a hand rotating over them once every eight seconds."""
    rings = "".join(
        f'<circle cx="{cx}" cy="{cy}" r="{radius * scale:.1f}" fill="none" '
        f'stroke="{ACCENT}" stroke-width="1" opacity="{opacity * fade:.3f}"/>'
        for scale, fade in ((0.35, 0.9), (0.62, 0.65), (0.85, 0.45), (1.0, 0.3))
    )
    return f"""<g>
    {rings}
    <line x1="{cx}" y1="{cy}" x2="{cx}" y2="{cy - radius:.1f}" stroke="{ACCENT}"
          stroke-width="1.5" stroke-linecap="round" opacity="{opacity * 1.6:.3f}">
      <animateTransform attributeName="transform" type="rotate"
                        from="0 {cx} {cy}" to="360 {cx} {cy}"
                        dur="8s" repeatCount="indefinite"/>
    </line>
  </g>"""


def stat_block(x: float, y: float, value: str, label: str, colour: str, size: int) -> str:
    return f"""<text x="{x}" y="{y}" font-family="{MONO}" font-size="{size}" font-weight="700"
        fill="{colour}" letter-spacing="-0.5">{value}</text>
  <text x="{x}" y="{y + size * 0.62:.0f}" font-family="{MONO}" font-size="{size * 0.34:.0f}"
        fill="{NEUTRAL}" letter-spacing="1.6">{label}</text>"""


def hero(counts: dict) -> str:
    blocks = "".join(
        stat_block(x, 96, value, label, colour, 34)
        for x, value, label, colour in (
            (620, group(counts["total_cves"]), "CVES INDEXED", FG),
            (840, group(counts["with_pocs"]), "WITH POCS", ACCENT),
            (1010, group(counts["kev"]), "KNOWN EXPLOITED", DANGER),
        )
    )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="180" viewBox="0 0 1200 180"
     role="img" aria-label="CVE Radar, {group(counts['with_pocs'])} CVEs with public proof-of-concept exploits">
  <clipPath id="card"><rect x="1" y="1" width="1198" height="178" rx="12"/></clipPath>
  <rect x="0.5" y="0.5" width="1199" height="179" rx="12" fill="{CANVAS}" stroke="{BORDER}"/>
  <g clip-path="url(#card)" opacity="0.6">{sweep(1090, 90, 160, 0.3)}</g>

  <text x="56" y="70" font-family="{MONO}" font-size="44" font-weight="700"
        fill="{FG}" letter-spacing="2">CVE RADAR</text>
  <text x="56" y="104" font-family="{MONO}" font-size="15" fill="{MUTED}">
    Public proof-of-concept exploits for every CVE.</text>
  <text x="56" y="132" font-family="{MONO}" font-size="15" fill="{ACCENT}">cve.codepwn.win</text>

  {blocks}
</svg>
"""


def social(counts: dict) -> str:
    """1280x640 card for the repository social preview and the site og:image."""
    blocks = "".join(
        stat_block(x, 430, value, label, colour, 46)
        for x, value, label, colour in (
            (96, group(counts["total_cves"]), "CVES INDEXED", FG),
            (500, group(counts["with_pocs"]), "WITH POCS", ACCENT),
            (880, group(counts["kev"]), "KNOWN EXPLOITED", DANGER),
        )
    )
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="640" viewBox="0 0 1280 640"
     role="img" aria-label="CVE Radar">
  <clipPath id="card"><rect x="56" y="56" width="1168" height="528" rx="16"/></clipPath>
  <rect width="1280" height="640" fill="{CANVAS}"/>
  <g clip-path="url(#card)" opacity="0.6">{sweep(1000, 300, 220, 0.26)}</g>
  <rect x="56" y="56" width="1168" height="528" rx="16" fill="none" stroke="{BORDER}"/>

  <text x="96" y="215" font-family="{MONO}" font-size="76" font-weight="700"
        fill="{FG}" letter-spacing="3">CVE RADAR</text>
  <text x="96" y="272" font-family="{MONO}" font-size="24" fill="{MUTED}">
    Public proof-of-concept exploits for every CVE.</text>

  <rect x="96" y="344" width="1088" height="1" fill="{BORDER}"/>
  {blocks}

  <text x="96" y="532" font-family="{MONO}" font-size="22" fill="{ACCENT}"
        letter-spacing="1">cve.codepwn.win</text>
</svg>
"""


def render(counts: dict) -> None:
    """Draw both cards and leave the figures behind for the README build."""
    for path, markup in ((HERO, hero(counts)), (SOCIAL, social(counts))):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(markup)
    # No timestamp: this file should only change when the figures do, so the
    # README build can read the same numbers the banner is drawn from.
    with open(STATS, "w", encoding="utf-8") as handle:
        json.dump(counts, handle, indent=1, sort_keys=True)
        handle.write("\n")


def main() -> int:
    counts = corpus_counts() or live_stats()
    if not counts:
        # Drawing zeros would be worse than leaving the previous banner in place.
        print("no usable counts, leaving the existing banner alone")
        return 1
    render(counts)
    print(f"Wrote {HERO}, {SOCIAL} and {STATS}: {group(counts['total_cves'])} CVEs, "
          f"{group(counts['with_pocs'])} with PoCs, {group(counts['kev'])} known exploited")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
