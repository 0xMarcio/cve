from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from utils import API_DIR, DIFFS_DIR, SNAPSHOT_DIR, TOP_DIR, ensure_dirs, load_json, save_json, today_str


def write_cve_outputs(results: List[Dict], *, base_dir: Path | None = None) -> None:
    target_dir = base_dir or API_DIR / "cve"
    ensure_dirs(target_dir)
    for result in results:
        last_updated = result.get("last_updated") or today_str()
        output = {
            "cve_id": result["cve_id"],
            "last_updated": last_updated,
            "pocs": [
                {
                    "repo_full_name": poc.get("repo_full_name"),
                    "repo_url": poc.get("repo_url"),
                    "is_fork": poc.get("is_fork"),
                    "parent_repo_url": poc.get("parent_repo_url"),
                    "stars": poc.get("stars"),
                    "forks": poc.get("forks"),
                    "archived": poc.get("archived"),
                    "pushed_at": poc.get("pushed_at") or poc.get("updated_at"),
                    "topics": poc.get("topics", []),
                    "primary_language": poc.get("primary_language"),
                    "matches": poc.get("matches", []),
                    "confidence_score": poc.get("confidence_score"),
                    "confidence_tier": poc.get("confidence_tier"),
                }
                for poc in result.get("pocs", [])
            ],
        }
        save_json(target_dir / f"{result['cve_id']}.json", output)


def build_index(results: List[Dict]) -> Dict:
    items: List[Dict] = []
    for result in results:
        poc_entries = result.get("pocs", [])
        high = [p for p in poc_entries if p.get("confidence_tier") == "high"]
        medium = [p for p in poc_entries if p.get("confidence_tier") == "medium"]
        langs = Counter()
        max_score = 0.0
        for poc in poc_entries:
            lang = poc.get("primary_language")
            if lang:
                langs[lang] += 1
            max_score = max(max_score, poc.get("confidence_score") or 0)
        items.append(
            {
                "cve_id": result["cve_id"],
                "poc_count": len(poc_entries),
                "high_confidence": len(high),
                "medium_confidence": len(medium),
                "top_languages": [lang for lang, _ in langs.most_common(3)],
                "max_score": max_score,
                "last_updated": result.get("last_updated"),
            }
        )
    return {"generated": today_str(), "items": sorted(items, key=lambda r: r["cve_id"], reverse=True)}


def write_index(results: List[Dict]) -> Dict:
    ensure_dirs(API_DIR)
    payload = build_index(results)
    save_json(API_DIR / "index.json", payload)
    return payload


def write_top(results: List[Dict], *, limit: int = 100) -> Dict:
    ensure_dirs(TOP_DIR)
    entries: List[Dict] = []
    for result in results:
        for poc in result.get("pocs", []):
            if poc.get("confidence_tier") not in {"high", "medium"}:
                continue
            entries.append(
                {
                    "cve_id": result["cve_id"],
                    "repo_full_name": poc.get("repo_full_name"),
                    "repo_url": poc.get("repo_url"),
                    "score": poc.get("confidence_score"),
                    "tier": poc.get("confidence_tier"),
                    "stars": poc.get("stars"),
                    "primary_language": poc.get("primary_language"),
                }
            )
    entries.sort(key=lambda e: (-(e.get("score") or 0), -(e.get("stars") or 0)))
    payload = {"generated": today_str(), "items": entries[:limit]}
    save_json(TOP_DIR / "today.json", payload)
    return payload


def summarise_for_snapshot(results: List[Dict], *, top: Dict | None = None) -> Dict:
    summary: Dict[str, Dict[str, Dict]] = {}
    for result in results:
        repo_map: Dict[str, Dict] = {}
        for poc in result.get("pocs", []):
            repo_map[poc.get("repo_full_name")] = {
                "score": poc.get("confidence_score"),
                "tier": poc.get("confidence_tier"),
            }
        summary[result["cve_id"]] = repo_map
    payload = {"generated": today_str(), "entries": summary}
    if top:
        payload["top"] = top
    return payload


def write_snapshot(summary: Dict) -> Path:
    ensure_dirs(SNAPSHOT_DIR)
    target = SNAPSHOT_DIR / f"{summary['generated']}.json"
    save_json(target, summary)
    save_json(SNAPSHOT_DIR / "latest.json", summary)
    return target


def prune_old_snapshots(days: int = 14) -> None:
    if not SNAPSHOT_DIR.exists():
        return
    cutoff = datetime.utcnow().date() - timedelta(days=days)
    for snap in SNAPSHOT_DIR.glob("*.json"):
        try:
            snap_date = datetime.strptime(snap.stem, "%Y-%m-%d").date()
        except ValueError:
            continue
        if snap_date < cutoff:
            snap.unlink(missing_ok=True)


def prune_old_diffs(days: int = 14) -> None:
    if not DIFFS_DIR.exists():
        return
    cutoff = datetime.now().date() - timedelta(days=days)
    for diff in DIFFS_DIR.glob("*.json"):
        try:
            diff_date = datetime.strptime(diff.stem, "%Y-%m-%d").date()
        except ValueError:
            continue
        if diff_date < cutoff:
            diff.unlink(missing_ok=True)


def _load_snapshot(path: Path) -> Dict:
    return load_json(path, default={}) or {}


def build_diff(prev: Dict, curr: Dict, *, dead_links: List[Dict] | None = None) -> Dict:
    prev_entries = prev.get("entries", {})
    curr_entries = curr.get("entries", {})

    new_high: List[Dict] = []
    promoted: List[Dict] = []
    demoted: List[Dict] = []

    for cve_id, repos in curr_entries.items():
        for repo_name, info in repos.items():
            tier = info.get("tier")
            if tier != "high":
                continue
            prev_info = (prev_entries.get(cve_id) or {}).get(repo_name)
            if not prev_info:
                new_high.append({"cve_id": cve_id, "repo_full_name": repo_name, "score": info.get("score")})
            elif prev_info.get("tier") != "high":
                promoted.append(
                    {
                        "cve_id": cve_id,
                        "repo_full_name": repo_name,
                        "score": info.get("score"),
                        "previous_tier": prev_info.get("tier"),
                    }
                )

    for cve_id, repos in prev_entries.items():
        for repo_name, info in repos.items():
            if info.get("tier") != "high":
                continue
            curr_info = (curr_entries.get(cve_id) or {}).get(repo_name)
            if not curr_info or curr_info.get("tier") != "high":
                demoted.append(
                    {
                        "cve_id": cve_id,
                        "repo_full_name": repo_name,
                        "previous_score": info.get("score"),
                        "previous_tier": info.get("tier"),
                        "current_tier": curr_info.get("tier") if curr_info else None,
                    }
                )

    return {
        "generated": curr.get("generated"),
        "new_high_conf_pocs": new_high,
        "promoted_to_high": promoted,
        "demoted_or_removed": demoted,
        "dead_links": dead_links or [],
    }


def write_diff(diff: Dict) -> Path:
    ensure_dirs(DIFFS_DIR)
    target = DIFFS_DIR / f"{diff['generated']}.json"
    save_json(target, diff)
    save_json(DIFFS_DIR / "latest.json", diff)
    return target


def latest_snapshots() -> Tuple[Dict, Dict]:
    if not SNAPSHOT_DIR.exists():
        return {}, {}
    snaps = sorted(SNAPSHOT_DIR.glob("*.json"))
    if not snaps:
        return {}, {}
    curr = _load_snapshot(snaps[-1])
    prev = _load_snapshot(snaps[-2]) if len(snaps) > 1 else {}
    return prev, curr
