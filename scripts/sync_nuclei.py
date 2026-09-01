#!/usr/bin/env python3
"""Fold ProjectDiscovery's nuclei templates into the index.

A template is a runnable check for one CVE, which makes it a proof of concept
in its own right, and it carries the severity, CVSS, EPSS and CWE the markdown
entries never had. Both are picked up here: the template link joins the PoC
list for its CVE, and the ratings land in nuclei.json for the site to read.
"""

from __future__ import annotations

import argparse
import io
import json
import re
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "nuclei.json"
TARBALL = "https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/refs/heads/main"
BLOB = "https://github.com/projectdiscovery/nuclei-templates/blob/main/"
SECTION = "#### Nuclei"
EMPTY = "No nuclei template."
TEMPLATE_NAME = re.compile(r"^CVE-\d{4}-\d{4,7}\.yaml$")
USER_AGENT = "0xMarcio-cve-nuclei"

# The fields wanted are plain scalars on their own line inside info:, so they
# are read directly rather than pulling a YAML parser into a stdlib-only job.
FIELDS = {
    "name": re.compile(r"^  name:\s*(.+?)\s*$", re.M),
    "severity": re.compile(r"^\s{2,4}severity:\s*([a-z]+)\s*$", re.M),
    "cvss": re.compile(r"^\s+cvss-score:\s*([0-9.]+)\s*$", re.M),
    "cvss_vector": re.compile(r"^\s+cvss-metrics:\s*(\S+)\s*$", re.M),
    "epss": re.compile(r"^\s+epss-score:\s*([0-9.]+)\s*$", re.M),
    "epss_pct": re.compile(r"^\s+epss-percentile:\s*([0-9.]+)\s*$", re.M),
    "cwe": re.compile(r"^\s+cwe-id:\s*(CWE-\d+)\s*$", re.M | re.I),
}


def download() -> bytes:
    request = urllib.request.Request(TARBALL, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=180) as response:
        return response.read()


def parse(text: str) -> dict:
    """Ratings for one template, dropping anything the template does not state."""
    head = text[:4000]
    found: dict[str, object] = {}
    for key, pattern in FIELDS.items():
        match = pattern.search(head)
        if not match:
            continue
        value = match.group(1).strip().strip('"\'')
        if key in ("cvss", "epss", "epss_pct"):
            try:
                found[key] = round(float(value), 5)
            except ValueError:
                pass
        elif value:
            found[key] = value
    return found


def collect(archive: bytes) -> dict[str, dict]:
    """Every CVE template in the tarball, keyed by CVE id.

    Templates live under several top level directories (http, code, network and
    so on); what marks one is a cves/ path segment and a CVE-shaped filename.
    """
    templates: dict[str, dict] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            parts = Path(member.name).parts
            if "cves" not in parts or not TEMPLATE_NAME.match(parts[-1]):
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            text = handle.read().decode("utf-8", "replace")
            cve = parts[-1][:-5].upper()
            # Strip the archive's own top level directory from the blob path.
            relative = "/".join(parts[1:])
            entry = parse(text)
            entry["url"] = BLOB + relative
            # A CVE with more than one template keeps the richer of the two.
            if len(entry) >= len(templates.get(cve, {})):
                templates[cve] = entry
    return templates


def section_bounds(text: str, header: str) -> tuple[int, int] | None:
    start = text.find("\n" + header)
    if start < 0:
        return None
    body = start + 1 + len(header)
    nxt = text.find("\n#", body)
    return body, len(text) if nxt < 0 else nxt


def apply_to_markdown(cve: str, url: str, dry_run: bool) -> str:
    """Add the template link to one CVE entry. Returns what happened."""
    path = ROOT / cve.split("-")[1] / f"{cve}.md"
    if not path.exists():
        return "absent"
    original = path.read_text(encoding="utf-8")
    if url in original:
        return "unchanged"
    block = f"\n{SECTION}\n- {url}\n"
    bounds = section_bounds(original, SECTION)
    if bounds:
        start, end = bounds
        updated = original[:start] + f"\n- {url}\n" + original[end:]
    else:
        # The section sits at the end of the POC block, after the GitHub links.
        updated = original.rstrip("\n") + "\n" + block
    if not dry_run:
        path.write_text(updated, encoding="utf-8")
    return "added"


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync nuclei templates into the index")
    parser.add_argument("--dry-run", action="store_true", help="report without writing")
    args = parser.parse_args()

    templates = collect(download())
    print(f"{len(templates):,} CVE templates in nuclei-templates")

    tally = {"added": 0, "unchanged": 0, "absent": 0}
    for cve, entry in sorted(templates.items()):
        tally[apply_to_markdown(cve, entry["url"], args.dry_run)] += 1

    payload = {cve: entry for cve, entry in sorted(templates.items())}
    if not args.dry_run:
        with OUTPUT.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=0, sort_keys=True)
            handle.write("\n")

    rated = sum(1 for e in payload.values() if "cvss" in e)
    scored = sum(1 for e in payload.values() if "epss" in e)
    print(f"markdown: {tally['added']:,} links added, {tally['unchanged']:,} already there, "
          f"{tally['absent']:,} for CVEs not in the index")
    print(f"{OUTPUT.name}: {len(payload):,} CVEs, {rated:,} with CVSS, {scored:,} with EPSS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
