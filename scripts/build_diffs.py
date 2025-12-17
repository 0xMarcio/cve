from __future__ import annotations

import argparse
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple

from utils import API_DIR, SNAPSHOT_DIR, ensure_dirs, load_json, save_json

DEFAULT_LOOKBACK_DAYS = 14
DEFAULT_HIGH_EPSS_THRESHOLD = 0.05
DEFAULT_MAX_MOVERS = 50
DEFAULT_RECENT_KEV_DAYS = 30


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


def filter_recent_kev(kev_items: List[Dict], *, recent_days: int) -> List[Dict]:
    cutoff = datetime.utcnow().date() - timedelta(days=recent_days)
    fresh: List[Tuple[date, Dict]] = []
    for row in kev_items:
        date_str = row.get("date_added") or row.get("dateAdded")
        if not date_str:
            continue
        try:
            added = parse_date(date_str)
        except ValueError:
            continue
        if added >= cutoff:
            fresh.append((added, row))
    fresh.sort(key=lambda item: (item[0], item[1].get("percentile") or 0), reverse=True)
    return [row for _, row in fresh]


def build_diff(
    snapshots: List[Path],
    kev_full: List[Dict] | None = None,
    *,
    threshold: float,
    max_movers: int,
    recent_days: int,
) -> Tuple[Dict, Path | None]:
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

    kev_recent = filter_recent_kev(kev_full or latest.get("kev_top", []), recent_days=recent_days)

    diff_outputs = {
        "generated": latest_date,
        "new_kev_entries": kev_recent,
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
    parser.add_argument("--recent-days", type=int, default=DEFAULT_RECENT_KEV_DAYS, help="Days of KEV entries to surface as new")
    args = parser.parse_args()

    ensure_dirs(SNAPSHOT_DIR)
    snapshots = sorted(SNAPSHOT_DIR.glob("*.json"))
    diff, target = build_diff(snapshots, kev_full=None, threshold=args.threshold, max_movers=args.max_movers, recent_days=args.recent_days)
    if target:
        print(f"Wrote diff to {target}")
    else:
        print("No snapshots available to diff")

    prune_snapshots(snapshots, lookback_days=args.lookback)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
