from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List

import requests

from utils import DATA_DIR, maybe_float, save_json, today_str

API_URL = "https://api.first.org/data/v1/epss"
DEFAULT_LIMIT = 2000
DEFAULT_BATCH = 1000


def fetch_batch(offset: int, limit: int) -> Dict:
    params = {
        "offset": offset,
        "limit": limit,
        "sort": "epss",
        "order": "desc",
    }
    response = requests.get(API_URL, params=params, timeout=30)
    response.raise_for_status()
    return response.json()


def normalise_rows(raw_rows: List[Dict]) -> List[Dict]:
    normalised = []
    for row in raw_rows:
        cve = str(row.get("cve", "")).upper()
        if not cve:
            continue
        epss = maybe_float(row.get("epss"))
        pct = maybe_float(row.get("percentile"))
        normalised.append(
            {
                "cve": cve,
                "epss": epss,
                "percentile": pct,
                "date": row.get("date"),
            }
        )
    return normalised


def fetch_epss(limit: int = DEFAULT_LIMIT, batch_size: int = DEFAULT_BATCH) -> Dict:
    rows: List[Dict] = []
    offset = 0
    while offset < limit:
        size = min(batch_size, limit - offset)
        payload = fetch_batch(offset, size)
        data_rows = payload.get("data") or []
        rows.extend(normalise_rows(data_rows))
        if len(data_rows) < size:
            break
        offset += size

    rows.sort(key=lambda row: (-row.get("epss", 0.0), row["cve"]))
    return {
        "source": API_URL,
        "fetched": today_str(),
        "count": len(rows),
        "limit": limit,
        "items": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch EPSS top list")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Number of EPSS rows to fetch")
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH,
        help="Batch size for paginated EPSS API calls",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DATA_DIR / "epss.json",
        help="Where to store the downloaded EPSS JSON",
    )
    args = parser.parse_args()

    payload = fetch_epss(args.limit, args.batch_size)
    save_json(args.output, payload)
    print(f"Saved {payload['count']} EPSS rows to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
