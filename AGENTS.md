# Repository Guidelines

## Project Structure & Module Organization
Year-specific directories (`2000/`–`2025/`) store curated CVE entries as markdown files named `CVE-YYYY-NNNN.md`. Each file follows the shared heading layout used across the repository. Supporting assets live in `docs/`: the generated `CVE_list.json`, static site files (`index.html`, `logic.js`, `style.css`), and the `generate_cve_list.py` helper. Automation now lives in `scripts/update_cves.py`, which syncs markdown and JSON from the latest GitHub PoCs. Reference inventories (`github*.txt`, `references*.txt`, `blacklist.txt`) and utilities such as `removedups.py` sit at the repository root.

## Build, Test, and Development Commands
Run `python3 scripts/update_cves.py` from the repository root to pull fresh CVE descriptions from the CVE Program API, merge new PoC links from `github.txt`, and regenerate `docs/CVE_list.json`. Metadata responses are cached in `data/cve_cache.json` for one week by default; use `--refresh-cache` or tweak `--cache-ttl` when you need a fresh pull. Pass `--cve CVE-2024-1234` when testing a single record, and `--skip-json` to avoid touching the compiled artifact during dry runs. For manual edits, `cd docs && python3 generate_cve_list.py` still regenerates the JSON directly. Use `python3 removedups.py references.txt > references.txt.new` to deduplicate lists before replacing the original file. `rg "CVE-2024-1234" 2024` is the fastest way to confirm whether an entry already exists. Keep commands in the repository root to ensure relative paths resolve.

## Coding Style & Naming Conventions
Name new entries `CVE-YYYY-####.md` and mirror the existing sections: title, badges, `### Description`, then `### POC` with `#### Reference` and `#### Github`. Prefer concise paragraphs and Markdown lists that start with `- `. Python helpers use standard library only, four-space indentation, snake_case identifiers, and inline comments only when they clarify parsing logic.

## Testing Guidelines
No automated suite exists; rely on lightweight validation. After regenerating JSON, run `python3 -m json.tool docs/CVE_list.json > /dev/null` to confirm structure. Manually spot-check added markdown in a browser or Markdown preview to ensure badges render and links resolve. When touching scripts, execute them with sample files and review the diff to confirm no unintended rewrites.

## Commit & Pull Request Guidelines
Existing history shows automation using `Trending CVEs update YYYY-MM-DD HH:MM :robot:` summaries. A scheduled workflow now commits daily updates via `sync_cve_pocs.yml`; keep manual commits focused on human-reviewed adjustments. When contributing manually, use a clear imperative line such as `Add CVE-2024-1234 PoC entry` and group related file changes per commit. Pull requests should describe the data source, mention regenerated artifacts, and note any manual verification steps; include screenshots only when UI assets change.

## Security & Data Integrity
Verify every CVE reference against a reputable advisory before inclusion and avoid linking to weaponized exploits. Remove sensitive tokens or credentials from pasted content. Keep automation scripts dependency-free so they can run in restricted environments, and prefer relative paths to support archive exports and GitHub Actions runners.
