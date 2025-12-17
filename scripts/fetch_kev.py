from __future__ import annotations

import argparse
from pathlib import Path

from utils import DATA_DIR, fetch_json, save_json, today_str

DEFAULT_SOURCE = "https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json"


def fetch_kev(source: str = DEFAULT_SOURCE) -> dict:
    data = fetch_json(source)
    items = data.get("vulnerabilities") or data.get("data") or data

    normalised = []
    for entry in items:
        cve_id = (entry.get("cveID") or "").upper()
        if not cve_id:
            continue
        normalised.append(
            {
                "cve": cve_id,
                "vendor": entry.get("vendorProject", "").strip(),
                "product": entry.get("product", "").strip(),
                "date_added": entry.get("dateAdded"),
                "due_date": entry.get("dueDate"),
                "short_description": entry.get("shortDescription", "").strip(),
                "required_action": entry.get("requiredAction", "").strip(),
                "notes": entry.get("notes", "").strip(),
            }
        )

    normalised.sort(key=lambda row: row["cve"])
    return {
        "source": source,
        "fetched": today_str(),
        "count": len(normalised),
        "items": normalised,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch CISA KEV catalogue")
    parser.add_argument("--source", default=DEFAULT_SOURCE, help="KEV JSON source URL")
    parser.add_argument(
        "--output",
        type=Path,
        default=DATA_DIR / "kev.json",
        help="Where to store the downloaded KEV JSON",
    )
    args = parser.parse_args()

    payload = fetch_kev(args.source)
    save_json(args.output, payload)
    print(f"Saved {payload['count']} KEV entries to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
