#!/usr/bin/env python3
"""Fold nuclei templates into the index.

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
def source(repo: str, branch: str = "main", *, scoped: bool = False) -> tuple:
    """A template repository: where to fetch it and how to link into it.

    ProjectDiscovery keeps templates for everything, so only its cves/ tree
    counts. The community repositories below are nothing but CVE templates,
    where that scoping would throw the whole repository away.
    """
    return (
        repo,
        f"https://codeload.github.com/{repo}/tar.gz/refs/heads/{branch}",
        f"https://github.com/{repo}/blob/{branch}/",
        scoped,
    )


# Order is precedence. ProjectDiscovery's template is the one to link when it
# exists; the rest are read only for the CVEs it does not cover. Wordfence
# alone carries thousands of WordPress plugin CVEs nobody else templates.
SOURCES = (
    source("projectdiscovery/nuclei-templates", scoped=True),
    source("topscoder/nuclei-wordfence-cve"),
    source("linuxadi/40k-nuclei-templates"),
    source("CharanRayudu/Custom-Nuclei-Templates"),
    source("geeknik/the-nuclei-templates"),
    source("Akokonunes/Private-Nuclei-Templates"),
)
SECTION = "#### Nuclei"
EMPTY = "No nuclei template."
# ProjectDiscovery names a template for its CVE and nothing else. Wordfence
# appends the plugin slug and an advisory uuid, so the id is a prefix there.
TEMPLATE_NAME = re.compile(r"^(CVE-\d{4}-\d{4,7})(?:[-_.][^/]*)?\.ya?ml$", re.IGNORECASE)
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


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=900) as response:
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


def collect(archive: bytes, blob: str, scoped: bool) -> dict[str, dict]:
    """Every CVE template in the tarball, keyed by CVE id."""
    templates: dict[str, dict] = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar:
            if not member.isfile():
                continue
            parts = Path(member.name).parts
            named = TEMPLATE_NAME.match(parts[-1])
            if not named:
                continue
            if scoped and "cves" not in parts:
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            text = handle.read().decode("utf-8", "replace")
            cve = named.group(1).upper()
            # Strip the archive's own top level directory from the blob path.
            relative = "/".join(parts[1:])
            entry = parse(text)
            entry["url"] = blob + relative
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

    templates: dict[str, dict] = {}
    for repo, tarball, blob, scoped in SOURCES:
        try:
            found = collect(download(tarball), blob, scoped)
        except Exception as problem:
            print(f"{repo}: unavailable ({problem}); skipped")
            continue
        fresh = {cve: entry for cve, entry in found.items() if cve not in templates}
        templates.update(fresh)
        print(f"{repo}: {len(found):,} CVE templates, {len(fresh):,} not already covered")
    print(f"{len(templates):,} CVEs templated in total")

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
