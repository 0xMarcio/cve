from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

from utils import API_DIR, SNAPSHOT_DIR, ensure_dirs, load_json, save_json

DEFAULT_LOOKBACK_DAYS = 14
DEFAULT_HIGH_EPSS_THRESHOLD = 0.5
DEFAULT_MAX_MOVERS = 50


def parse_date(date_str: str) -> date:
    return datetime.strptime(date_str, "%Y-%m-%d").date()


def load_snapshot(path: Path) -> Dict:
    return load_json(path, default={}) or {}


def diff_lists(prev: List[Dict], curr: List[Dict], key: str = "cve") -> Dict[str, List[Dict]]:
    prev_ids = {item[key]: item for item in prev}
    curr_ids = {item[key]: item for item in curr}
    new_items = [curr_ids[cve] for cve in sorted(curr_ids.keys() - prev_ids.keys())]
    removed_items = [prev_ids[cve] for cve in sorted(prev_ids.keys() - curr_ids.keys())]
    return {"new": new_items, "removed": removed_items}


def compute_epss_movers(prev_epss: Dict[str, Dict], curr_epss: Dict[str, Dict], max_items: int) -> List[Dict]:
    deltas = []
    for cve, curr in curr_epss.items():
        prev = prev_epss.get(cve)
        if not prev:
            continue
        delta = (curr.get("epss") or 0) - (prev.get("epss") or 0)
        if abs(delta) < 0.0001:
            continue
        deltas.append({"cve": cve, "delta": round(delta, 5), "epss": curr.get("epss"), "prev_epss": prev.get("epss")})
    deltas.sort(key=lambda row: (-row["delta"], row["cve"]))
    return deltas[:max_items]


def build_diff(snapshots: List[Path], *, threshold: float, max_movers: int) -> Tuple[Dict, Path | None]:
    if not snapshots:
        return {}, None
    latest_path = snapshots[-1]
    latest = load_snapshot(latest_path)
    latest_date = latest.get("generated") or latest_path.stem

    if len(snapshots) >= 2:
        prev = load_snapshot(snapshots[-2])
        kev_diff = diff_lists(prev.get("kev_top", []), latest.get("kev_top", []))
        high_epss_diff = diff_lists(prev.get("high_epss", []), latest.get("high_epss", []))
    else:
        prev = {}
        kev_diff = {"new": latest.get("kev_top", []), "removed": []}
        high_epss_diff = {"new": latest.get("high_epss", []), "removed": []}

    prev_epss_lookup = {row["cve"]: row for row in (prev.get("high_epss", []) if prev else [])}
    curr_epss_lookup = {row["cve"]: row for row in latest.get("high_epss", [])}
    epss_movers = compute_epss_movers(prev_epss_lookup, curr_epss_lookup, max_movers)

    diff_outputs = {
        "generated": latest_date,
        "new_kev_entries": kev_diff["new"],
        "removed_kev_entries": kev_diff["removed"],
        "new_high_epss": [row for row in high_epss_diff["new"] if (row.get("epss") or 0) >= threshold],
        "removed_high_epss": high_epss_diff["removed"],
        "epss_movers": epss_movers,
    }

    target = API_DIR / "diff" / f"{latest_date}.json"
    ensure_dirs(target.parent)
    save_json(target, diff_outputs)
    # also write a stable latest pointer
    save_json(target.parent / "latest.json", diff_outputs)

    return diff_outputs, target


def prune_snapshots(snapshots: List[Path], *, lookback_days: int) -> None:
    cutoff = datetime.utcnow().date() - timedelta(days=lookback_days)
    for snap in snapshots:
        snap_date = parse_date(snap.stem)
        if snap_date < cutoff:
            snap.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build daily diff JSON from snapshots")
    parser.add_argument("--threshold", type=float, default=DEFAULT_HIGH_EPSS_THRESHOLD, help="High EPSs minimum threshold")
    parser.add_argument("--lookback", type=int, default=DEFAULT_LOOKBACK_DAYS, help="How many days of snapshots to keep")
    parser.add_argument("--max-movers", type=int, default=DEFAULT_MAX_MOVERS, help="Max EPSs movers to keep")
    args = parser.parse_args()

    ensure_dirs(SNAPSHOT_DIR)
    snapshots = sorted(SNAPSHOT_DIR.glob("*.json"))
    diff, target = build_diff(snapshots, threshold=args.threshold, max_movers=args.max_movers)
    if target:
        print(f"Wrote diff to {target}")
    else:
        print("No snapshots available to diff")

    prune_snapshots(snapshots, lookback_days=args.lookback)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
