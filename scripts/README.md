# Build pipeline

```
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python scripts/fetch_kev.py
python scripts/fetch_epss.py
python scripts/build_site.py
python scripts/build_all.py
```

Outputs land in `docs/` and JSON under `docs/api/v1/`. Snapshots live in `docs/api/v1/snapshots/` (last 14 days) and diffs under `docs/api/v1/diffs/`.
