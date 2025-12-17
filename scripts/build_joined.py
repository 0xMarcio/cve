from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

from utils import (
    API_DIR,
    DATA_DIR,
    DOCS_DIR,
    SNAPSHOT_DIR,
    load_json,
    save_json,
    today_str,
    ensure_dirs,
    load_poc_index,
    slugify,
    stable_unique,
)

KEV_PATH = DATA_DIR / "kev.json"
EPSS_PATH = DATA_DIR / "epss.json"

DEFAULT_TOP_KEV = 75
DEFAULT_HIGH_EPSS_LIMIT = 50
DEFAULT_HIGH_EPSS_THRESHOLD = 0.05
RECENT_YEAR_WINDOW = 1


def load_inputs(kev_path: Path, epss_path: Path) -> Tuple[Dict, Dict]:
    kev_data = load_json(kev_path, default={}) or {}
    epss_data = load_json(epss_path, default={}) or {}
    return kev_data, epss_data


def enrich_kev(kev_items: List[Dict], epss_lookup: Dict[str, Dict], poc_index: Dict[str, Dict]) -> List[Dict]:
    enriched = []
    current_year = today_str()
    current_year_int = int(current_year.split("-")[0])
    def is_recent(cve_id: str) -> bool:
        try:
            year = int(cve_id.split("-")[1])
        except Exception:
            return False
        return year >= current_year_int - RECENT_YEAR_WINDOW

    for entry in kev_items:
        cve = entry.get("cve") or entry.get("cveID") or ""
        if not cve:
            continue
        cve = cve.upper()
        if not is_recent(cve):
            continue
        epss_info = epss_lookup.get(cve, {})
        poc_info = poc_index.get(cve)
        if not poc_info or not poc_info.get("poc"):
            continue
        poc_count = len(poc_info["poc"])
        enriched.append(
            {
                "cve": cve,
                "vendor": entry.get("vendor") or entry.get("vendorProject", ""),
                "product": entry.get("product", ""),
                "date_added": entry.get("date_added") or entry.get("dateAdded"),
                "due_date": entry.get("due_date") or entry.get("dueDate"),
                "short_description": entry.get("short_description") or entry.get("shortDescription", ""),
                "required_action": entry.get("required_action") or entry.get("requiredAction", ""),
                "notes": entry.get("notes", ""),
                "epss": epss_info.get("epss"),
                "percentile": epss_info.get("percentile"),
                "poc_count": poc_count,
            }
        )
    enriched.sort(key=lambda row: (-float(row.get("percentile") or 0), row["cve"]))
    return enriched


def build_epss_lookup(epss_items: List[Dict]) -> Dict[str, Dict]:
    return {row.get("cve", "").upper(): row for row in epss_items if row.get("cve")}


def build_high_epss_not_in_kev(
    epss_items: List[Dict],
    kev_set: Set[str],
    poc_index: Dict[str, Dict],
    *,
    threshold: float,
    limit: int,
) -> List[Dict]:
    current_year_int = int(today_str().split("-")[0])
    def is_recent(cve_id: str) -> bool:
        try:
            year = int(cve_id.split("-")[1])
        except Exception:
            return False
        return year >= current_year_int - RECENT_YEAR_WINDOW

    ranked = sorted(
        (
            row
            for row in epss_items
            if row.get("cve")
            and row.get("cve", "").upper() not in kev_set
            and (row.get("epss") is not None)
            and is_recent(row.get("cve", ""))
        ),
        key=lambda row: (-float(row.get("epss") or 0), row.get("cve", "")),
    )

    def build_rows(source: List[Dict]) -> List[Dict]:
        output: List[Dict] = []
        for row in source:
            cve = row.get("cve", "").upper()
            if not cve:
                continue
            epss_score = row.get("epss") or 0.0
            if epss_score < threshold:
                continue
            poc_info = poc_index.get(cve)
            if not poc_info or not poc_info.get("poc"):
                continue
            poc_count = len(poc_info["poc"])
            output.append(
                {
                    "cve": cve,
                    "epss": row.get("epss"),
                    "percentile": row.get("percentile"),
                    "summary": truncate_description(poc_info.get("desc", "")),
                    "poc_count": poc_count,
                }
            )
            if len(output) >= limit:
                break
        return output

    rows = build_rows(ranked)
    if not rows and threshold > 0:
        # If the threshold is too strict for a given day, fall back to the top ranked set.
        rows = build_rows([dict(row, epss=row.get("epss", 0) or 0) for row in ranked[:limit]])
    return rows


def build_cve_details(
    kev_enriched: Iterable[Dict],
    high_epss: Iterable[Dict],
    poc_index: Dict[str, Dict],
) -> Dict[str, Dict]:
    details: Dict[str, Dict] = {}

    def ensure_detail(cve: str) -> Dict:
        if cve not in details:
            data = poc_index.get(cve, {})
            details[cve] = {
                "cve": cve,
                "description": data.get("desc", ""),
                "poc_links": data.get("poc", []),
                "poc_count": len(data.get("poc", [])),
                "kev": None,
                "epss": None,
                "percentile": None,
                "vendor": None,
                "product": None,
            }
        return details[cve]

    for entry in kev_enriched:
        cve = entry["cve"]
        detail = ensure_detail(cve)
        detail.update(
            {
                "kev": {
                    "date_added": entry.get("date_added"),
                    "due_date": entry.get("due_date"),
                    "short_description": entry.get("short_description"),
                    "required_action": entry.get("required_action"),
                    "notes": entry.get("notes"),
                },
                "epss": entry.get("epss"),
                "percentile": entry.get("percentile"),
                "vendor": entry.get("vendor"),
                "product": entry.get("product"),
            }
        )

    for entry in high_epss:
        cve = entry["cve"]
        detail = ensure_detail(cve)
        if detail.get("epss") is None:
            detail["epss"] = entry.get("epss")
            detail["percentile"] = entry.get("percentile")

    return details


def build_vendor_map(details: Dict[str, Dict]) -> Dict[str, Dict]:
    vendors: Dict[str, Dict] = {}
    for detail in details.values():
        vendor_name = detail.get("vendor")
        if not vendor_name:
            continue
        slug = slugify(vendor_name)
        entry = vendors.setdefault(slug, {"vendor": vendor_name, "cves": []})
        entry["cves"].append(detail["cve"])

    for value in vendors.values():
        value["cves"].sort()
    return dict(sorted(vendors.items(), key=lambda kv: kv[0]))


def truncate_description(text: str, limit: int = 220) -> str:
    if not text:
        return ""
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 3].rstrip() + "..."


def build_joined(
    kev_data: Dict,
    epss_data: Dict,
    poc_index: Dict[str, Dict],
    *,
    top_kev: int = DEFAULT_TOP_KEV,
    high_epss_threshold: float = DEFAULT_HIGH_EPSS_THRESHOLD,
    high_epss_limit: int = DEFAULT_HIGH_EPSS_LIMIT,
    extra_cves: Iterable[str] | None = None,
) -> Dict:
    kev_items = kev_data.get("items") or []
    epss_items = epss_data.get("items") or []

    epss_lookup = build_epss_lookup(epss_items)
    kev_enriched = enrich_kev(kev_items, epss_lookup, poc_index)
    kev_top = kev_enriched[:top_kev]

    kev_set = {row["cve"] for row in kev_enriched}
    high_epss = build_high_epss_not_in_kev(epss_items, kev_set, poc_index, threshold=high_epss_threshold, limit=high_epss_limit)

    details = build_cve_details(kev_top, high_epss, poc_index)

    if extra_cves:
        extra_set = {cve.upper() for cve in extra_cves}
        epss_lookup = build_epss_lookup(epss_items)
        kev_lookup = {row["cve"]: row for row in kev_enriched}
        for cve in sorted(extra_set):
            if cve in details:
                continue
            epss_row = epss_lookup.get(cve, {})
            kev_row = kev_lookup.get(cve)
            details[cve] = {
                "cve": cve,
                "description": poc_index.get(cve, {}).get("desc", ""),
                "poc_links": poc_index.get(cve, {}).get("poc", []),
                "poc_count": len(poc_index.get(cve, {}).get("poc", [])),
                "kev": None,
                "epss": epss_row.get("epss"),
                "percentile": epss_row.get("percentile"),
                "vendor": None,
                "product": None,
            }
            if kev_row:
                details[cve]["kev"] = {
                    "date_added": kev_row.get("date_added"),
                    "due_date": kev_row.get("due_date"),
                    "short_description": kev_row.get("short_description"),
                    "required_action": kev_row.get("required_action"),
                    "notes": kev_row.get("notes"),
                }
                details[cve]["vendor"] = kev_row.get("vendor")
                details[cve]["product"] = kev_row.get("product")

    vendors = build_vendor_map(details)

    # add display summary
    for collection in (kev_top, high_epss):
        for row in collection:
            desc = poc_index.get(row["cve"], {}).get("desc") or ""
            row["summary"] = truncate_description(desc)

    joined = {
        "generated": today_str(),
        "kev_top": kev_top,
        "high_epss": high_epss,
    }

    return {
        "joined": joined,
        "kev_enriched": kev_enriched,
        "epss_items": epss_items,
        "details": details,
        "vendors": vendors,
    }


def write_api_outputs(payload: Dict, *, api_dir: Path = API_DIR) -> None:
    ensure_dirs(api_dir, api_dir / "cve", SNAPSHOT_DIR)
    joined = payload["joined"]
    save_json(api_dir / "kev.json", {"generated": joined["generated"], "items": payload["kev_enriched"]})
    save_json(
        api_dir / "epss_top.json",
        {
            "generated": joined["generated"],
            "items": payload["joined"]["high_epss"],
        },
    )
    save_json(api_dir / "joined_top.json", joined)

    for cve, detail in payload["details"].items():
        save_json(api_dir / "cve" / f"{cve}.json", detail)


def main() -> int:
    parser = argparse.ArgumentParser(description="Join KEV and EPSS with PoC data")
    parser.add_argument("--kev", type=Path, default=KEV_PATH, help="Path to KEV JSON")
    parser.add_argument("--epss", type=Path, default=EPSS_PATH, help="Path to EPSS JSON")
    parser.add_argument("--top-kev", type=int, default=DEFAULT_TOP_KEV, help="How many KEV rows to surface on top list")
    parser.add_argument(
        "--high-epss-threshold",
        type=float,
        default=DEFAULT_HIGH_EPSS_THRESHOLD,
        help="Minimum EPSS to include when selecting high EPSs CVEs",
    )
    parser.add_argument(
        "--high-epss-limit",
        type=int,
        default=DEFAULT_HIGH_EPSS_LIMIT,
        help="Maximum number of high EPSs CVEs to keep",
    )
    args = parser.parse_args()

    poc_index = load_poc_index()
    kev_data, epss_data = load_inputs(args.kev, args.epss)
    payload = build_joined(
        kev_data,
        epss_data,
        poc_index,
        top_kev=args.top_kev,
        high_epss_threshold=args.high_epss_threshold,
        high_epss_limit=args.high_epss_limit,
    )
    write_api_outputs(payload)
    print("Generated joined JSON endpoints under docs/api/v1/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
