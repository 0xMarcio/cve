from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Dict, List

import requests

from pipeline_outputs import (
    build_diff,
    prune_old_diffs,
    prune_old_snapshots,
    summarise_for_snapshot,
    write_cve_outputs,
    write_diff,
    write_index,
    write_snapshot,
    write_top,
)
from poc_pipeline import PoCPipeline, build_scope, persist_evidence
from utils import API_DIR, DOCS_DIR, load_json


def load_existing_results(api_dir: Path) -> List[Dict]:
    results: List[Dict] = []
    if not api_dir.exists():
        return results
    for path in api_dir.glob("CVE-*.json"):
        data = load_json(path, default={}) or {}
        if "pocs" in data:
            results.append({"cve_id": data.get("cve_id") or path.stem, "pocs": data.get("pocs", []), "last_updated": data.get("last_updated")})
    return results


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build CVE PoC pipeline outputs, snapshots, and static site")
    parser.add_argument("--days", type=int, default=7, help="Days window for GitHub discovery windows")
    parser.add_argument("--mode", choices=["daily", "weekly"], default="daily", help="Run mode to tune scope")
    parser.add_argument("--limit", type=int, default=50, help="Maximum CVEs to scan per run")
    parser.add_argument("--cve", action="append", help="Explicit CVE IDs to scan (can be passed multiple times)")
    parser.add_argument("--skip-discovery", action="store_true", help="Skip GitHub discovery and reuse existing API outputs")
    parser.add_argument("--check-links", action="store_true", help="Optionally HEAD check repo URLs for dead links")
    args = parser.parse_args(argv)

    pipeline = PoCPipeline()
    scope: List[str] = []
    discovery_days = args.days
    if args.cve:
        scope = [cve.upper() for cve in args.cve]
    elif not args.skip_discovery:
        prefer_recent = True
        scan_days = args.days
        limit = args.limit
        if args.mode == "weekly":
            scan_days = max(scan_days, 30)
            discovery_days = scan_days
            prefer_recent = False
            limit = None
        scope = build_scope(scan_days, github_list=Path("github.txt"), existing_api=API_DIR / "cve", prefer_recent_years=prefer_recent, max_cves=limit)

    results: List[Dict] = []
    if args.skip_discovery:
        results = load_existing_results(API_DIR / "cve")
    else:
        for idx, cve_id in enumerate(scope):
            try:
                results.append(pipeline.discover_for_cve(cve_id, days=discovery_days))
            except Exception as exc:  # noqa: BLE001
                print(f"[warn] Failed to process {cve_id}: {exc}", file=sys.stderr)
        persist_evidence(results)

    if not results:
        print("No results to write; aborting.")
        return 1

    write_cve_outputs(results)
    index_payload = write_index(results)
    top_payload = write_top(results)

    def maybe_check_links() -> List[Dict]:
        if not args.check_links:
            return []
        urls = []
        for result in results:
            for poc in result.get("pocs", []):
                if poc.get("confidence_tier") in {"high", "medium"} and poc.get("repo_url"):
                    urls.append(poc["repo_url"])
        urls = urls[:25]
        dead: List[Dict] = []
        for url in urls:
            try:
                resp = requests.head(url, timeout=5, allow_redirects=True)
                if resp.status_code >= 400:
                    dead.append({"url": url, "status": resp.status_code})
            except requests.RequestException as exc:  # noqa: BLE001
                dead.append({"url": url, "error": str(exc)})
        return dead

    snapshot_payload = summarise_for_snapshot(results, top=top_payload)
    prev_snapshot = load_json(API_DIR / "snapshots" / "latest.json", default={}) or {}
    snapshot_path = write_snapshot(snapshot_payload)
    diff_payload = build_diff(prev_snapshot, snapshot_payload, dead_links=maybe_check_links())
    write_diff(diff_payload)
    prune_old_snapshots()
    prune_old_diffs()

    print(f"Wrote pipeline outputs under {DOCS_DIR}")
    print(f"Wrote latest snapshot to {snapshot_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
