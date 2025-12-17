from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path
import re
from typing import Dict, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

from utils import (
    API_DIR,
    DOCS_DIR,
    TEMPLATES_DIR,
    ensure_dirs,
    load_json,
    load_poc_index,
    parse_trending_from_readme,
    save_json,
)

from build_joined import build_joined, write_api_outputs
from build_diffs import build_diff, prune_snapshots

KEV_DATA = DOCS_DIR.parent / "data" / "kev.json"
EPSS_DATA = DOCS_DIR.parent / "data" / "epss.json"
README_PATH = DOCS_DIR.parent / "README.md"


def build_env() -> Environment:
    loader = FileSystemLoader(str(TEMPLATES_DIR))
    env = Environment(loader=loader, autoescape=select_autoescape(["html", "xml"]))
    env.trim_blocks = True
    env.lstrip_blocks = True
    return env


def render(env: Environment, template_name: str, context: Dict, output_path: Path) -> None:
    html = env.get_template(template_name).render(**context)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")


def load_joined() -> Dict:
    kev = load_json(KEV_DATA, default={})
    epss = load_json(EPSS_DATA, default={})
    poc_index = load_poc_index()
    payload = build_joined(kev, epss, poc_index)
    write_api_outputs(payload)
    return payload


def write_snapshot(joined: Dict) -> Path:
    snapshot_path = API_DIR / "snapshots" / f"{joined['generated']}.json"
    ensure_dirs(snapshot_path.parent)
    save_json(snapshot_path, joined)
    return snapshot_path


def build_pages(env: Environment, data: Dict, diff: Dict | None = None, html_mode: str = "summary") -> None:
    joined = data["joined"]
    details = data["details"]
    vendors = data["vendors"]
    def is_recent_label(label: str) -> bool:
        label = (label or "").lower()
        if "minute" in label or "hour" in label:
            return True
        m = re.search(r"(\d+)\\s*day", label)
        if not m:
            return False
        return int(m.group(1)) <= 4

    current_year = datetime.now(timezone.utc).year

    def extract_year(name: str) -> int | None:
        m = re.search(r"cve-(\\d{4})-", name.lower())
        return int(m.group(1)) if m else None

    trending_raw = parse_trending_from_readme(README_PATH)
    trending = [
        row
        for row in trending_raw
        if is_recent_label(row.get("updated", ""))
        and (extract_year(row.get("name", "")) or current_year) >= current_year - 1
    ]
    trending.sort(key=lambda r: int(r.get("stars") or 0), reverse=True)
    recent_kev = (diff or {}).get("new_kev_entries") or []
    metrics = {
        "kev_total": len(data["kev_enriched"]),
        "high_epss_count": len(joined["high_epss"]),
        "recent_kev_count": len(recent_kev),
    }

    if html_mode in {"summary", "all"}:
        common_ctx = {"generated": joined["generated"], "metrics": metrics, "recent_kev": recent_kev}
        render(
            env,
            "index.html",
            {**common_ctx, "data": joined, "trending": trending, "diff": diff or {}},
            DOCS_DIR / "index.html",
        )
        render(env, "kev.html", {**common_ctx, "kev": data["kev_enriched"]}, DOCS_DIR / "kev" / "index.html")
        render(env, "epss.html", {**common_ctx, "epss": joined["high_epss"]}, DOCS_DIR / "epss" / "index.html")
        render(env, "diffs.html", {**common_ctx, "diff": diff or {}}, DOCS_DIR / "diffs" / "index.html")

    if html_mode == "all":
        common_ctx = {"generated": joined["generated"]}
        for cve, detail in details.items():
            render(env, "cve.html", {**common_ctx, "cve": detail}, DOCS_DIR / "cve" / f"{cve}.html")

        for slug, vendor in vendors.items():
            cve_details = [details[cve] for cve in vendor["cves"] if cve in details]
            render(env, "vendor.html", {**common_ctx, "vendor": vendor, "cves": cve_details}, DOCS_DIR / "vendors" / f"{slug}.html")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build static site and JSON")
    parser.add_argument(
        "--html-mode",
        choices=["none", "summary", "all"],
        default="none",
        help="Render no HTML, summary pages only, or all pages including per-CVE.",
    )
    args = parser.parse_args()

    ensure_dirs(DOCS_DIR, DOCS_DIR / "kev", DOCS_DIR / "epss", DOCS_DIR / "diffs")

    data = load_joined()
    # snapshot + diff before rendering so dashboard can show it
    snapshot_path = write_snapshot(data["joined"])
    snapshots = sorted((API_DIR / "snapshots").glob("*.json"))
    diff, target = build_diff(
        snapshots,
        kev_full=data["kev_enriched"],
        threshold=0.05,
        max_movers=50,
        recent_days=30,
    )
    prune_snapshots(snapshots, lookback_days=14)

    if args.html_mode != "none":
        env = build_env()
        build_pages(env, data, diff, html_mode=args.html_mode)

    # build daily diff after snapshot is written
    print("Site generated under docs/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
