from __future__ import annotations

import argparse
from pathlib import Path
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


def build_pages(env: Environment, data: Dict, diff: Dict | None = None) -> None:
    joined = data["joined"]
    details = data["details"]
    vendors = data["vendors"]
    trending = parse_trending_from_readme(README_PATH)

    common_ctx = {"generated": joined["generated"]}
    render(
        env,
        "index.html",
        {**common_ctx, "data": joined, "trending": trending, "diff": diff or {}},
        DOCS_DIR / "index.html",
    )
    render(env, "kev.html", {**common_ctx, "kev": data["kev_enriched"]}, DOCS_DIR / "kev" / "index.html")
    render(env, "epss.html", {**common_ctx, "epss": joined["high_epss"]}, DOCS_DIR / "epss" / "index.html")
    render(env, "diffs.html", {**common_ctx, "diff": diff or {}}, DOCS_DIR / "diffs" / "index.html")

    for cve, detail in details.items():
        render(env, "cve.html", {**common_ctx, "cve": detail}, DOCS_DIR / "cve" / f"{cve}.html")

    for slug, vendor in vendors.items():
        cve_details = [details[cve] for cve in vendor["cves"] if cve in details]
        render(env, "vendor.html", {**common_ctx, "vendor": vendor, "cves": cve_details}, DOCS_DIR / "vendors" / f"{slug}.html")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build static site and JSON")
    args = parser.parse_args()

    ensure_dirs(DOCS_DIR, DOCS_DIR / "cve", DOCS_DIR / "vendors", DOCS_DIR / "kev", DOCS_DIR / "epss", DOCS_DIR / "diffs")

    env = build_env()
    data = load_joined()
    # snapshot + diff before rendering so dashboard can show it
    snapshot_path = write_snapshot(data["joined"])
    snapshots = sorted((API_DIR / "snapshots").glob("*.json"))
    diff, target = build_diff(snapshots, threshold=0.5, max_movers=50)
    prune_snapshots(snapshots, lookback_days=14)

    build_pages(env, data, diff)

    # build daily diff after snapshot is written
    print("Site generated under docs/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
