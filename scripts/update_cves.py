#!/usr/bin/env python3
"""Discover CVE proof-of-concept links and update the repository."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator
from urllib import error, request
from urllib.parse import quote, urlparse

ROOT = Path(__file__).resolve().parents[1]
DOCS_DIR = ROOT / "docs"
JSON_SCRIPT = DOCS_DIR / "generate_cve_list.py"
GITHUB_LIST = ROOT / "github.txt"
REFERENCE_LIST = ROOT / "references.txt"
BLACKLIST_FILE = ROOT / "blacklist.txt"
STATE_FILE = ROOT / ".github" / "cve_sync_state.json"

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"
CVE_API_URL = "https://cveawg.mitre.org/api/cve/{cve_id}"
CVELIST_DELTA_LOG_URL = (
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json"
)

CVE_RE = re.compile(r"\bCVE[-_ ](?P<year>\d{4})[-_ ](?P<number>\d{4,})\b", re.IGNORECASE)
POC_RE = re.compile(
    r"\b(?:poc|exploit(?:ation)?|proof[ _-]*of[ _-]*concept|"
    r"repro(?:ducer|duction|duce)?|payload)\b",
    re.IGNORECASE,
)
UNSAFE_RE = re.compile(
    r"\b(?:fully[ _-]*weaponized|weaponiz(?:e|es|ed|ing|ation)|"
    r"mass(?:ive)?[ _-]*(?:attack|exploit(?:ation)?|scanners?|scanning)|"
    r"bulk[ _-]*(?:attack|exploit(?:ation)?|scanners?|scanning))\b",
    re.IGNORECASE,
)
NON_POC_RE = re.compile(
    r"(?:\b(?:advisory|aggregat(?:ion|or)|analysis|ansible|audits?|block(?:er|ing)?|blog|"
    r"bookmark|challenge|check(?:er|ing)|collection|corpus|course|ctf|dataset|defen(?:ce|se|sive)|"
    r"detect(?:ion|or)?|dfir|exam|feed|finder|github[ _-]*stars|hardening|investigation|"
    r"honeypot|intelligence|ioc|lab|list|lookup|mitigat(?:e|ing|ion|or)|model(?:er|ing)|"
    r"monitor(?:ing)?|notes?|papers?|patch(?:es)?|pentest|portfolio|prediction|"
    r"prevent(?:ion|ive)?|profile|protect(?:ion|ive)|remediat(?:e|ion)|reports?|"
    r"resources?|rules?|scanners?|shield|signature|suggester|toolkit|walkthrough|wazuh|"
    r"write[ _-]*ups?)\b|searchpoc|watchdog)",
    re.IGNORECASE,
)
SECTION_RE_TEMPLATE = r"({header}\s*\n)(.*?)(?=\n#### |\n### |\Z)"
USER_AGENT = "0xMarcio-cve-poc-sync"

GITHUB_SEARCH_QUERY = """
query($query: String!, $cursor: String) {
  search(type: REPOSITORY, query: $query, first: 100, after: $cursor) {
    repositoryCount
    pageInfo { hasNextPage endCursor }
    nodes {
      ... on Repository {
        nameWithOwner
        url
        description
        isArchived
        isFork
        pushedAt
        repositoryTopics(first: 20) { nodes { topic { name } } }
      }
    }
  }
  rateLimit { cost remaining resetAt }
}
"""


@dataclass
class CVEDetails:
    description: str
    products: list[str]
    versions: list[str]
    vulnerabilities: list[str]


@dataclass
class SyncStats:
    created: list[str] = field(default_factory=list)
    updated: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.created or self.updated)


def stable_unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def is_valid_cve(cve_id: str) -> bool:
    match = re.fullmatch(r"CVE-(\d{4})-(\d{4,})", cve_id, re.IGNORECASE)
    if not match:
        return False
    return 1999 <= int(match.group(1)) <= 2100


def extract_cves(text: str | None, year: int | None = None) -> set[str]:
    result: set[str] = set()
    for match in CVE_RE.finditer(text or ""):
        match_year = int(match.group("year"))
        if year is not None and match_year != year:
            continue
        cve_id = f"CVE-{match_year}-{match.group('number')}"
        if is_valid_cve(cve_id):
            result.add(cve_id)
    return result


def load_blacklist(path: Path = BLACKLIST_FILE) -> list[str]:
    if not path.exists():
        return []
    return [
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def is_blacklisted_repo(full_name: str, blacklist: list[str]) -> bool:
    repo = full_name.rsplit("/", 1)[-1].lower()
    full_name = full_name.lower()
    for entry in blacklist:
        target = full_name if "/" in entry else repo
        if entry.endswith("*") and target.startswith(entry[:-1]):
            return True
        if target == entry:
            return True
    return False


def normalise_identity(text: str) -> str:
    return re.sub(r"[_-]+", " ", text)


def has_unsafe_claim(text: str) -> bool:
    text = normalise_identity(text)
    for match in UNSAFE_RE.finditer(text):
        before = text[max(0, match.start() - 80) : match.start()]
        after = text[match.end() : match.end() + 80]
        if re.search(
            r"\b(?:avoid|cannot|no|non|not|without)\b.{0,50}$",
            before,
            re.IGNORECASE | re.DOTALL,
        ):
            continue
        if re.search(r"\b(?:can|could|may)\s+be\s*$", before, re.IGNORECASE):
            continue
        if re.match(r".{0,30}\b(?:is|are)\s+withheld\b", after, re.IGNORECASE):
            continue
        return True
    return False


def github_repo_from_url(url: str) -> str:
    parsed = urlparse(url)
    if (parsed.hostname or "").lower() != "github.com":
        return ""
    parts = [part for part in parsed.path.split("/") if part]
    return "/".join(parts[:2]) if len(parts) >= 2 else ""


def readme_text(repo: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("readmeMd", "readmeUpper", "readmeRst", "readmeBare"):
        value = repo.get(key)
        if isinstance(value, dict) and isinstance(value.get("text"), str):
            parts.append(value["text"])
    return "\n".join(stable_unique(parts))


def topic_names(repo: dict[str, Any]) -> list[str]:
    topics = repo.get("repositoryTopics") or {}
    names: list[str] = []
    for node in topics.get("nodes") or []:
        name = ((node or {}).get("topic") or {}).get("name")
        if name:
            names.append(str(name))
    return names


def readme_has_poc_context(readme: str, cve_id: str, full_name: str = "") -> bool:
    year, number = cve_id.split("-")[1:]
    pattern = re.compile(rf"\bCVE[-_ ]{re.escape(year)}[-_ ]{re.escape(number)}\b", re.IGNORECASE)
    for match in pattern.finditer(readme):
        line_start = readme.rfind("\n", 0, match.start()) + 1
        line_end = readme.find("\n", match.end())
        line = readme[line_start : line_end if line_end >= 0 else len(readme)]
        linked_repos = {
            github_repo_from_url(url).lower()
            for url in re.findall(r"https://github\.com/[^\s)>]+", line, re.IGNORECASE)
        }
        linked_repos.discard("")
        if linked_repos and full_name.lower() not in linked_repos:
            continue
        start = max(0, match.start() - 350)
        end = min(len(readme), match.end() + 350)
        if POC_RE.search(readme[start:end]):
            return True
    return False


def qualifying_repo_cves(
    repo: dict[str, Any],
    year: int,
    blacklist: list[str],
) -> set[str]:
    full_name = str(repo.get("nameWithOwner") or "")
    if not full_name or repo.get("isFork") or repo.get("isArchived"):
        return set()
    owner, repo_name = full_name.lower().split("/", 1)
    if owner == repo_name or repo_name.endswith(".github.io"):
        return set()
    if is_blacklisted_repo(full_name, blacklist):
        return set()

    description = str(repo.get("description") or "")
    topics = " ".join(topic_names(repo))
    readme = readme_text(repo)
    if has_unsafe_claim(f"{full_name} {description} {topics} {readme}"):
        return set()
    name_cves = extract_cves(full_name, year)
    description_cves = extract_cves(description, year)
    topic_cves = extract_cves(topics, year)
    readme_cves = extract_cves(readme, year)
    identity_text = normalise_identity(f"{full_name} {description}")
    identity_has_poc = bool(POC_RE.search(identity_text))
    metadata_has_poc = identity_has_poc or bool(POC_RE.search(topics))
    identity_is_non_poc = bool(NON_POC_RE.search(identity_text))
    if len(extract_cves(readme)) > 25:
        readme_cves = set()

    accepted: set[str] = set()
    for cve_id in name_cves:
        name_has_poc = bool(POC_RE.search(normalise_identity(full_name)))
        if not identity_is_non_poc or name_has_poc:
            accepted.add(cve_id)
    for cve_id in description_cves | topic_cves:
        if not identity_is_non_poc and (
            metadata_has_poc or readme_has_poc_context(readme, cve_id, full_name)
        ):
            accepted.add(cve_id)
    for cve_id in readme_cves:
        if (
            identity_has_poc
            and not identity_is_non_poc
            and readme_has_poc_context(readme, cve_id, full_name)
        ):
            accepted.add(cve_id)
    return accepted


def http_json(
    url: str,
    *,
    headers: dict[str, str] | None = None,
    data: dict[str, Any] | None = None,
    timeout: int = 45,
    allow_not_found: bool = False,
) -> Any:
    request_headers = {"Accept": "application/json", "User-Agent": USER_AGENT}
    request_headers.update(headers or {})
    body = None
    method = "GET"
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
        method = "POST"

    for attempt in range(3):
        req = request.Request(url, data=body, headers=request_headers, method=method)
        try:
            with request.urlopen(req, timeout=timeout) as response:
                return json.load(response)
        except error.HTTPError as exc:
            if allow_not_found and exc.code == 404:
                return None
            if exc.code not in {429, 500, 502, 503, 504} or attempt == 2:
                raise
        except (error.URLError, TimeoutError, json.JSONDecodeError):
            if attempt == 2:
                raise
        time.sleep(2 ** attempt)
    raise RuntimeError(f"Unable to fetch {url}")


class GitHubClient:
    def __init__(self, token: str) -> None:
        if not token:
            raise ValueError("GITHUB_TOKEN is required for GitHub PoC discovery")
        self.headers = {"Authorization": f"Bearer {token}"}

    def search_page(self, query_text: str, cursor: str | None = None) -> dict[str, Any]:
        payload = http_json(
            GITHUB_GRAPHQL_URL,
            headers=self.headers,
            data={"query": GITHUB_SEARCH_QUERY, "variables": {"query": query_text, "cursor": cursor}},
        )
        data = payload.get("data") or {}
        search = data.get("search")
        if not search:
            messages = "; ".join(str(item.get("message")) for item in payload.get("errors") or [])
            raise RuntimeError(f"GitHub search failed: {messages or 'missing response data'}")
        rate = data.get("rateLimit") or {}
        if int(rate.get("remaining") or 0) < 5:
            raise RuntimeError(f"GitHub GraphQL quota is nearly exhausted; resets at {rate.get('resetAt')}")
        return search

    def fetch_readmes(self, full_names: list[str]) -> tuple[set[str], dict[str, str]]:
        fields = """
          readmeMd: object(expression: \"HEAD:README.md\") { ... on Blob { text } }
          readmeUpper: object(expression: \"HEAD:README.MD\") { ... on Blob { text } }
          readmeRst: object(expression: \"HEAD:README.rst\") { ... on Blob { text } }
          readmeBare: object(expression: \"HEAD:README\") { ... on Blob { text } }
        """
        aliases: list[str] = []
        names: list[str] = []
        for full_name in full_names:
            if "/" not in full_name:
                continue
            owner, name = full_name.split("/", 1)
            index = len(names)
            aliases.append(
                f"repo{index}: repository(owner: {json.dumps(owner)}, name: {json.dumps(name)}) "
                f"{{ {fields} }}"
            )
            names.append(full_name)
        if not aliases:
            return set(), {}
        query_text = "query { " + " ".join(aliases) + " rateLimit { remaining resetAt } }"
        payload = http_json(
            GITHUB_GRAPHQL_URL,
            headers=self.headers,
            data={"query": query_text},
        )
        data = payload.get("data") or {}
        rate = data.get("rateLimit") or {}
        if int(rate.get("remaining") or 0) < 5:
            raise RuntimeError(f"GitHub GraphQL quota is nearly exhausted; resets at {rate.get('resetAt')}")
        result: dict[str, str] = {}
        existing: set[str] = set()
        for index, full_name in enumerate(names):
            repo = data.get(f"repo{index}")
            if repo is None:
                continue
            existing.add(full_name)
            text = readme_text(repo)
            if text:
                result[full_name] = text
        return existing, result


def split_date_range(start: date, end: date) -> tuple[tuple[date, date], tuple[date, date]]:
    midpoint = start + timedelta(days=(end - start).days // 2)
    return (start, midpoint), (midpoint + timedelta(days=1), end)


def build_search_query(search_terms: str, qualifier: str, start: date, end: date) -> str:
    return (
        f"{search_terms} fork:false archived:false "
        f"{qualifier}:{start.isoformat()}..{end.isoformat()}"
    )


def search_range(
    client: GitHubClient,
    search_terms: str,
    qualifier: str,
    start: date,
    end: date,
) -> Iterator[dict[str, Any]]:
    query_text = build_search_query(search_terms, qualifier, start, end)
    first_page = client.search_page(query_text)
    count = int(first_page.get("repositoryCount") or 0)

    if count > 1000:
        if start == end:
            raise RuntimeError(f"GitHub search returned more than 1000 repositories for {query_text}")
        left, right = split_date_range(start, end)
        yield from search_range(client, search_terms, qualifier, *left)
        yield from search_range(client, search_terms, qualifier, *right)
        return

    print(f"GitHub {qualifier} {start}..{end}: {count} repositories")
    page = first_page
    while True:
        for repo in page.get("nodes") or []:
            if repo:
                yield repo
        page_info = page.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        page = client.search_page(query_text, str(page_info.get("endCursor")))


def search_without_range(client: GitHubClient, search_terms: str) -> Iterator[dict[str, Any]]:
    query_text = f"{search_terms} fork:false archived:false"
    cursor: str | None = None
    while True:
        page = client.search_page(query_text, cursor)
        if int(page.get("repositoryCount") or 0) > 1000:
            raise RuntimeError(f"GitHub search returned more than 1000 repositories for {query_text}")
        for repo in page.get("nodes") or []:
            if repo:
                yield repo
        page_info = page.get("pageInfo") or {}
        if not page_info.get("hasNextPage"):
            break
        cursor = str(page_info.get("endCursor"))


def discover_github_pocs(
    token: str,
    *,
    years: Iterable[int],
    lookback_days: int,
    backfill: bool,
    cve_filter: set[str],
) -> dict[str, list[str]]:
    client = GitHubClient(token)
    blacklist = load_blacklist()
    discovered: dict[str, list[str]] = defaultdict(list)
    repositories: dict[str, dict[str, Any]] = {}
    target_years = list(years)
    if cve_filter:
        target_years = sorted({int(cve_id.split("-")[1]) for cve_id in cve_filter})

    def remember(repo: dict[str, Any]) -> None:
        full_name = str(repo.get("nameWithOwner") or "")
        if full_name and not is_blacklisted_repo(full_name, blacklist):
            repositories[full_name] = repo

    def collect(repo: dict[str, Any], year: int) -> None:
        url = str(repo.get("url") or "").rstrip("/")
        if not url.startswith("https://github.com/"):
            return
        for cve_id in qualifying_repo_cves(repo, year, blacklist):
            if cve_filter and cve_id not in cve_filter:
                continue
            if url not in discovered[cve_id]:
                discovered[cve_id].append(url)

    def search_terms(identifier: str) -> list[str]:
        return [
            f'"{identifier}" in:name,description',
            f'"{identifier}" poc in:readme',
            f'"{identifier}" exploit in:readme',
            f'"{identifier}" "proof of concept" in:readme',
            f'"{identifier}" reproducer in:readme',
        ]

    if cve_filter:
        for cve_id in sorted(cve_filter):
            for terms in search_terms(cve_id):
                for repo in search_without_range(client, terms):
                    remember(repo)
    else:
        end = datetime.now(timezone.utc).date()
        for year in target_years:
            if backfill:
                qualifier = "created"
                start = date(2008, 1, 1)
            else:
                qualifier = "pushed"
                start = end - timedelta(days=max(1, lookback_days))
            for terms in search_terms(f"CVE-{year}"):
                for repo in search_range(client, terms, qualifier, start, end):
                    remember(repo)

    names = sorted(repositories)
    batches = [names[offset : offset + 10] for offset in range(0, len(names), 10)]
    completed = 0
    existing_names: set[str] = set()
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(client.fetch_readmes, batch): batch for batch in batches}
        for future in as_completed(futures):
            batch = futures[future]
            try:
                existing, readmes = future.result()
            except Exception as exc:
                print(f"Skipped README batch starting with {batch[0]}: {exc}", file=sys.stderr)
                existing = set(batch)
                readmes = {}
            existing_names.update(existing)
            for full_name, text in readmes.items():
                repositories[full_name]["readmeMd"] = {"text": text}
            completed += len(batch)
            if completed % 500 < len(batch):
                print(f"Fetched README data for {completed} of {len(names)} repositories")

    removed = set(repositories) - existing_names
    for full_name in removed:
        del repositories[full_name]
    if removed:
        print(f"Discarded {len(removed)} repositories removed during discovery")

    for repo in repositories.values():
        for year in target_years:
            collect(repo, year)
    return discovered


def cna_container(record: dict[str, Any]) -> dict[str, Any]:
    return (record.get("containers") or {}).get("cna") or {}


def record_is_published(record: dict[str, Any]) -> bool:
    return str((record.get("cveMetadata") or {}).get("state") or "").upper() == "PUBLISHED"


def record_cve_id(record: dict[str, Any]) -> str:
    return str((record.get("cveMetadata") or {}).get("cveId") or "").upper()


def english_description(container: dict[str, Any]) -> str:
    descriptions = container.get("descriptions") or []
    for item in descriptions:
        if str(item.get("lang") or "").lower().startswith("en") and item.get("value"):
            return str(item["value"]).strip()
    for item in descriptions:
        if item.get("value"):
            return str(item["value"]).strip()
    return ""


def details_from_record(record: dict[str, Any]) -> CVEDetails | None:
    if not record_is_published(record):
        return None
    cna = cna_container(record)
    description = english_description(cna)
    if not description:
        return None

    products: list[str] = []
    versions: list[str] = []
    for affected in cna.get("affected") or []:
        product = str(affected.get("product") or "").strip()
        if product:
            products.append(product)
        for version in affected.get("versions") or []:
            status = str(version.get("status") or "affected").lower()
            value = str(version.get("version") or "").strip()
            if status == "affected" and value:
                versions.append(value)

    vulnerabilities: list[str] = []
    for problem in cna.get("problemTypes") or []:
        for item in problem.get("descriptions") or []:
            value = item.get("description") or item.get("cweId")
            if value:
                vulnerabilities.append(str(value).strip())

    return CVEDetails(
        description=description,
        products=stable_unique(products),
        versions=stable_unique(versions),
        vulnerabilities=stable_unique(vulnerabilities),
    )


def reference_is_poc(reference: dict[str, Any], blacklist: list[str]) -> bool:
    url = str(reference.get("url") or "").strip()
    if not url.startswith(("http://", "https://")):
        return False
    repo = github_repo_from_url(url)
    if repo and is_blacklisted_repo(repo, blacklist):
        return False
    tags = [str(tag).lower() for tag in reference.get("tags") or []]
    evidence = " ".join([url, str(reference.get("name") or ""), *tags])
    if any("exploit" in tag for tag in tags):
        return True
    return bool(POC_RE.search(evidence))


def poc_references(
    record: dict[str, Any],
    blacklist: list[str] | None = None,
) -> list[str]:
    cve_id = record_cve_id(record)
    if not cve_id or not record_is_published(record):
        return []
    blacklist = load_blacklist() if blacklist is None else blacklist
    candidates = [cna_container(record)]
    references: list[str] = []
    for container in candidates:
        for item in container.get("references") or []:
            url = str(item.get("url") or "").strip()
            if reference_is_poc(item, blacklist):
                references.append(url)
    return stable_unique(references)


def read_record(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return None


def load_backfill_records(
    cve_dir: Path,
    year: int,
    cve_filter: set[str],
) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]], dict[str, Path]]:
    records: dict[str, dict[str, Any]] = {}
    references: dict[str, list[str]] = {}
    paths: dict[str, Path] = {}
    blacklist = load_blacklist()

    for path in sorted(cve_dir.rglob("CVE-*.json")):
        cve_id = path.stem.upper()
        if not is_valid_cve(cve_id) or int(cve_id.split("-")[1]) != year:
            continue
        if cve_filter and cve_id not in cve_filter:
            continue
        paths[cve_id] = path
        record = read_record(path)
        if not record or not record_is_published(record):
            continue
        selected = poc_references(record, blacklist)
        if selected:
            records[cve_id] = record
            references[cve_id] = selected
    return records, references, paths


def load_state(path: Path = STATE_FILE) -> str | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    value = data.get("cvelist_fetch_time")
    return str(value) if value else None


def delta_changes(last_fetch_time: str | None) -> tuple[dict[str, str], str]:
    log = http_json(CVELIST_DELTA_LOG_URL)
    if not isinstance(log, list) or not log:
        raise RuntimeError("CVE List V5 delta log is empty")
    newest = str(log[0].get("fetchTime") or "")
    selected: list[dict[str, Any]] = []
    for batch in log:
        fetch_time = str(batch.get("fetchTime") or "")
        if last_fetch_time and fetch_time <= last_fetch_time:
            break
        selected.append(batch)
        if not last_fetch_time:
            break

    changes: dict[str, str] = {}
    for batch in reversed(selected):
        for group in ("new", "updated"):
            for item in batch.get(group) or []:
                cve_id = str(item.get("cveId") or "").upper()
                url = str(item.get("githubLink") or "")
                if is_valid_cve(cve_id) and url:
                    changes[cve_id] = url
    print(f"CVE List V5: {len(selected)} delta batches, {len(changes)} changed CVEs")
    return changes, newest


def fetch_records(urls: dict[str, str], *, allow_not_found: bool) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    failures: list[str] = []

    def fetch(cve_id: str, url: str) -> tuple[str, dict[str, Any] | None]:
        result = http_json(url, allow_not_found=allow_not_found)
        return cve_id, result if isinstance(result, dict) else None

    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {executor.submit(fetch, cve_id, url): cve_id for cve_id, url in urls.items()}
        for future in as_completed(futures):
            cve_id = futures[future]
            try:
                fetched_cve, record = future.result()
            except Exception as exc:
                failures.append(f"{cve_id}: {exc}")
                continue
            if record:
                records[fetched_cve] = record

    if failures and not allow_not_found:
        raise RuntimeError("Failed to fetch CVE records: " + "; ".join(failures[:10]))
    if failures:
        print(f"Skipped {len(failures)} CVE API failures", file=sys.stderr)
    return records


def load_incremental_records(
    cve_filter: set[str],
) -> tuple[dict[str, dict[str, Any]], dict[str, list[str]], str]:
    changes, newest = delta_changes(load_state())
    if cve_filter:
        changes = {cve_id: url for cve_id, url in changes.items() if cve_id in cve_filter}
    records = fetch_records(changes, allow_not_found=False) if changes else {}
    blacklist = load_blacklist()
    references = {
        cve_id: selected
        for cve_id, record in records.items()
        if (selected := poc_references(record, blacklist))
    }
    return records, references, newest


def fetch_missing_records(
    cve_ids: Iterable[str],
    records: dict[str, dict[str, Any]],
) -> None:
    urls = {
        cve_id: CVE_API_URL.format(cve_id=cve_id)
        for cve_id in cve_ids
        if cve_id not in records
    }
    if urls:
        records.update(fetch_records(urls, allow_not_found=True))


def badge(label: str, message: str, color: str) -> str:
    return (
        "![](https://img.shields.io/static/v1?"
        f"label={quote(label, safe='')}&message={quote(message, safe='')}&color={color})"
    )


def build_markdown(
    cve_id: str,
    details: CVEDetails,
    github_links: list[str],
    references: list[str],
) -> str:
    description = "\n".join(
        line.expandtabs(4).rstrip() for line in details.description.strip().splitlines()
    )
    lines = [f"### [{cve_id}](https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id})"]
    products = details.products or ["n/a"]
    versions = details.versions or [""]
    vulnerabilities = details.vulnerabilities or ["n/a"]
    lines.extend(badge("Product", value, "blue") for value in products)
    lines.extend(badge("Version", value, "brightgreen") for value in versions)
    vuln_color = "brightgreen" if details.vulnerabilities else "blue"
    lines.extend(badge("Vulnerability", value, vuln_color) for value in vulnerabilities)
    lines.extend(["", "### Description", "", description, "", "### POC", "", "#### Reference"])
    lines.extend((f"- {url}" for url in references) if references else ["No PoCs from references."])
    lines.extend(["", "#### Github"])
    lines.extend((f"- {url}" for url in github_links) if github_links else ["No PoCs found on GitHub currently."])
    lines.append("")
    return "\n".join(lines)


def parse_section_links(block: str) -> list[str]:
    links: list[str] = []
    for raw_line in block.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("No PoCs"):
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        if line.startswith(("http://", "https://")):
            links.append(line)
    return stable_unique(links)


def merge_section(text: str, header: str, links: Iterable[str], empty_text: str) -> tuple[str, bool]:
    incoming = stable_unique(links)
    if not incoming:
        return text, False
    pattern = re.compile(SECTION_RE_TEMPLATE.format(header=re.escape(header)), re.DOTALL)
    match = pattern.search(text)
    if not match:
        return text, False
    existing = parse_section_links(match.group(2))
    combined = stable_unique([*existing, *incoming])
    if combined == existing:
        return text, False
    replacement = "\n".join(f"- {url}" for url in combined) if combined else empty_text
    body = match.group(2)
    trailing = body[len(body.rstrip()) :] or "\n"
    updated = text[: match.start(2)] + replacement + trailing + text[match.end(2) :]
    return updated, True


def update_existing_markdown(
    path: Path,
    github_links: list[str],
    references: list[str],
    *,
    dry_run: bool,
) -> bool:
    original = path.read_text(encoding="utf-8")
    updated, reference_changed = merge_section(
        original,
        "#### Reference",
        references,
        "No PoCs from references.",
    )
    updated, github_changed = merge_section(
        updated,
        "#### Github",
        github_links,
        "No PoCs found on GitHub currently.",
    )
    if not (reference_changed or github_changed):
        return False
    if not updated.endswith("\n"):
        updated += "\n"
    if not dry_run:
        path.write_text(updated, encoding="utf-8")
    return True


def sync_markdown(
    records: dict[str, dict[str, Any]],
    github: dict[str, list[str]],
    references: dict[str, list[str]],
    *,
    dry_run: bool,
) -> tuple[SyncStats, dict[str, list[str]], dict[str, list[str]]]:
    stats = SyncStats()
    accepted_github: dict[str, list[str]] = {}
    accepted_references: dict[str, list[str]] = {}
    cve_ids = sorted(set(github) | set(references))

    for cve_id in cve_ids:
        year = cve_id.split("-")[1]
        path = ROOT / year / f"{cve_id}.md"
        github_links = stable_unique(github.get(cve_id, []))
        reference_links = stable_unique(references.get(cve_id, []))
        record = records.get(cve_id)

        if record and not record_is_published(record):
            stats.skipped.append(f"{cve_id}: CVE is not published")
            continue

        if path.exists():
            if update_existing_markdown(
                path,
                github_links,
                reference_links,
                dry_run=dry_run,
            ):
                stats.updated.append(cve_id)
        else:
            details = details_from_record(record or {})
            if not details:
                stats.skipped.append(f"{cve_id}: published CVE metadata is unavailable")
                continue
            if not dry_run:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    build_markdown(cve_id, details, github_links, reference_links),
                    encoding="utf-8",
                )
            stats.created.append(cve_id)

        accepted_github[cve_id] = github_links
        accepted_references[cve_id] = reference_links

    return stats, accepted_github, accepted_references


def append_inventory(path: Path, mappings: dict[str, list[str]], *, dry_run: bool) -> int:
    existing = set(path.read_text(encoding="utf-8").splitlines()) if path.exists() else set()
    additions = sorted(
        f"{cve_id} - {url}"
        for cve_id, urls in mappings.items()
        for url in urls
        if url and f"{cve_id} - {url}" not in existing
    )
    if not additions or dry_run:
        return len(additions)
    prefix = ""
    if path.exists() and path.stat().st_size and not path.read_bytes().endswith(b"\n"):
        prefix = "\n"
    with path.open("a", encoding="utf-8") as handle:
        handle.write(prefix + "\n".join(additions) + "\n")
    return len(additions)


def write_state(fetch_time: str, *, dry_run: bool) -> None:
    if not fetch_time or dry_run:
        return
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(
        json.dumps({"cvelist_fetch_time": fetch_time}, indent=2) + "\n",
        encoding="utf-8",
    )


def newest_delta_time() -> str:
    log = http_json(CVELIST_DELTA_LOG_URL)
    if not isinstance(log, list) or not log:
        raise RuntimeError("CVE List V5 delta log is empty")
    return str(log[0].get("fetchTime") or "")


def regenerate_json() -> None:
    subprocess.run([sys.executable, JSON_SCRIPT.name], cwd=DOCS_DIR, check=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Discover and ingest CVE PoC links")
    parser.add_argument("--backfill-dir", type=Path, help="Local CVE List V5 year directory")
    parser.add_argument("--year", type=int, help="Year to backfill")
    parser.add_argument("--lookback-days", type=int, default=3, help="GitHub pushed-date overlap")
    parser.add_argument("--years", type=int, default=6, help="Number of recent years to scan")
    parser.add_argument("--cve", action="append", default=[], help="Process one CVE ID")
    parser.add_argument("--skip-github", action="store_true", help="Skip GitHub repository discovery")
    parser.add_argument("--skip-cvelist", action="store_true", help="Skip CVE List V5 references")
    parser.add_argument("--skip-json", action="store_true", help="Skip docs/CVE_list.json generation")
    parser.add_argument("--dry-run", action="store_true", help="Report changes without writing files")
    args = parser.parse_args()
    if bool(args.backfill_dir) != bool(args.year):
        parser.error("--backfill-dir and --year must be used together")
    if args.lookback_days < 1 or args.years < 1:
        parser.error("--lookback-days and --years must be positive")
    return args


def main() -> int:
    args = parse_args()
    cve_filter = {cve.upper() for cve in args.cve if is_valid_cve(cve.upper())}
    if args.cve and len(cve_filter) != len(args.cve):
        raise SystemExit("Every --cve value must be a valid CVE ID")

    backfill = bool(args.backfill_dir)
    records: dict[str, dict[str, Any]] = {}
    references: dict[str, list[str]] = {}
    record_paths: dict[str, Path] = {}
    checkpoint = ""

    if not args.skip_cvelist:
        if backfill:
            records, references, record_paths = load_backfill_records(
                args.backfill_dir,
                args.year,
                cve_filter,
            )
            checkpoint = newest_delta_time()
            print(f"CVE List V5 backfill: {len(references)} CVEs with PoC references")
        else:
            records, references, checkpoint = load_incremental_records(cve_filter)

    github: dict[str, list[str]] = {}
    if not args.skip_github:
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
        current_year = datetime.now(timezone.utc).year
        years = [args.year] if backfill else list(range(current_year, current_year - args.years, -1))
        github = discover_github_pocs(
            token,
            years=years,
            lookback_days=args.lookback_days,
            backfill=backfill,
            cve_filter=cve_filter,
        )
        print(f"GitHub discovery: {sum(len(urls) for urls in github.values())} links for {len(github)} CVEs")

    if backfill:
        for cve_id in set(github) - set(records):
            path = record_paths.get(cve_id)
            if path and (record := read_record(path)):
                records[cve_id] = record
    fetch_missing_records(set(github) | set(references), records)

    stats, accepted_github, accepted_references = sync_markdown(
        records,
        github,
        references,
        dry_run=args.dry_run,
    )
    github_additions = append_inventory(GITHUB_LIST, accepted_github, dry_run=args.dry_run)
    reference_additions = append_inventory(REFERENCE_LIST, accepted_references, dry_run=args.dry_run)

    if stats.changed and not args.skip_json and not args.dry_run:
        regenerate_json()
    write_state(checkpoint, dry_run=args.dry_run)

    print(
        f"Created: {len(stats.created)} | Updated: {len(stats.updated)} | "
        f"Skipped: {len(stats.skipped)}"
    )
    print(
        f"Inventory additions: {github_additions} GitHub | "
        f"{reference_additions} references"
    )
    if stats.skipped:
        for entry in stats.skipped[:20]:
            print(f"Skipped {entry}")
        if len(stats.skipped) > 20:
            print(f"Skipped {len(stats.skipped) - 20} additional CVEs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
