from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from github_client import GitHubClient, SearchResult, build_client
from poc_scoring import match_score, score_repo
from utils import API_DIR, EVIDENCE_DIR, chunked, cve_year, ensure_dirs, isoformat, load_blacklist, load_json, save_json, today_str


LANG_PARTITIONS = ("python", "go", "c", "shell", "powershell", "java", "ruby", "js")
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


@dataclass
class MatchEvidence:
    path: str
    match_type: str
    query: str
    score: float | None = None


@dataclass
class RepoCandidate:
    cve_id: str
    repo_full_name: str
    repo_url: str
    matches: List[MatchEvidence] = field(default_factory=list)
    metadata: Dict[str, object] = field(default_factory=dict)

    def add_match(self, path: str, match_type: str, query: str) -> None:
        key = (path, match_type)
        existing = {(m.path, m.match_type) for m in self.matches}
        if key in existing:
            return
        self.matches.append(MatchEvidence(path=path, match_type=match_type, query=query))


def build_created_ranges(days: int, *, window: int = 7) -> List[Tuple[str, str]]:
    end = date.today()
    start = end - timedelta(days=max(days, 1))
    ranges: List[Tuple[str, str]] = []
    cursor = start
    while cursor <= end:
        window_end = min(cursor + timedelta(days=window - 1), end)
        ranges.append((cursor.isoformat(), window_end.isoformat()))
        cursor = window_end + timedelta(days=1)
    return ranges or [(start.isoformat(), end.isoformat())]


def build_query_pack(cve_id: str, created_range: Tuple[str, str] | None = None) -> List[Dict[str, str]]:
    base_repo = f'{cve_id} in:name,description,readme fork:false'
    enriched_repo = f'{cve_id} (poc OR exploit) in:name,description,readme fork:false'
    topic_query = f"topic:{cve_id.lower()} fork:false"
    created_suffix = ""
    if created_range:
        created_suffix = f" created:{created_range[0]}..{created_range[1]}"

    queries = [
        {"kind": "repositories", "query": base_repo + created_suffix, "match_type": "name"},
        {"kind": "repositories", "query": enriched_repo + created_suffix, "match_type": "description"},
        {"kind": "repositories", "query": topic_query + created_suffix, "match_type": "topic"},
    ]

    for lang in LANG_PARTITIONS:
        base_code = f'{cve_id} in:file language:{lang}{created_suffix}'
        queries.append({"kind": "code", "query": base_code, "match_type": "code"})

    # generic code search without language partition for the most recent window
    queries.append({"kind": "code", "query": f"{cve_id} in:file{created_suffix}", "match_type": "code"})
    return queries


def parse_repo_from_item(item: Dict) -> Tuple[str | None, str | None]:
    repo_full_name = item.get("full_name") or item.get("repository", {}).get("full_name")
    repo_url = item.get("html_url") or item.get("repository", {}).get("html_url")
    if not repo_full_name and "repository" in item:
        repo_full_name = item["repository"].get("owner", {}).get("login", "")
        if repo_full_name:
            repo_full_name = f"{repo_full_name}/{item['repository'].get('name', '')}"
    return repo_full_name, repo_url


def extract_matches(item: Dict, default_type: str, query: str) -> List[MatchEvidence]:
    matches: List[MatchEvidence] = []
    for text_match in item.get("text_matches", []) or []:
        prop = text_match.get("property") or text_match.get("object_type") or ""
        fragment = text_match.get("fragment") or text_match.get("path") or prop or ""
        match_type = prop if prop else default_type
        matches.append(MatchEvidence(path=str(fragment), match_type=str(match_type), query=query))
    if not matches:
        path = item.get("path") or default_type
        matches.append(MatchEvidence(path=str(path), match_type=default_type, query=query))
    return matches


def normalise_metadata(meta: Dict, fallback_full_name: str, fallback_url: str) -> Dict:
    topics = []
    if meta.get("repositoryTopics"):
        for node in meta["repositoryTopics"].get("nodes", []):
            topic = (node.get("topic") or {}).get("name")
            if topic:
                topics.append(topic)
    primary_language = None
    if meta.get("primaryLanguage"):
        primary_language = meta["primaryLanguage"].get("name")
    parent = meta.get("parent") or {}
    return {
        "repo_full_name": meta.get("nameWithOwner") or fallback_full_name,
        "repo_url": meta.get("url") or fallback_url,
        "description": meta.get("description") or "",
        "is_fork": bool(meta.get("isFork")),
        "parent_repo_url": parent.get("url"),
        "stars": meta.get("stargazerCount") or 0,
        "forks": meta.get("forkCount") or 0,
        "archived": bool(meta.get("isArchived")),
        "pushed_at": meta.get("pushedAt"),
        "updated_at": meta.get("updatedAt"),
        "topics": topics,
        "primary_language": primary_language,
    }


class PoCPipeline:
    def __init__(
        self,
        client: GitHubClient | None = None,
        *,
        blacklist_path: Path | None = None,
        search_ttl: int = 3 * 3600,
    ) -> None:
        self.client = client or build_client()
        self.blacklist = load_blacklist(blacklist_path)
        self.search_ttl = search_ttl

    def _run_query(self, query: Dict, page: int) -> SearchResult:
        if query["kind"] == "repositories":
            return self.client.search_repositories(query["query"], page=page, per_page=50, ttl=self.search_ttl)
        if query["kind"] == "code":
            return self.client.search_code(query["query"], page=page, per_page=50, ttl=self.search_ttl)
        return self.client.search_topics(query["query"], page=page, per_page=50, ttl=self.search_ttl)

    def discover_for_cve(self, cve_id: str, *, days: int, max_pages_repo: int = 2, max_pages_code: int = 2) -> Dict:
        ranges = build_created_ranges(days)
        candidates: Dict[str, RepoCandidate] = {}
        query_log: List[Dict] = []

        for created_range in ranges:
            query_pack = build_query_pack(cve_id, created_range)
            for query in query_pack:
                query_log.append({"query": query["query"], "kind": query["kind"], "window": created_range})
                page_limit = max_pages_code if query["kind"] == "code" else max_pages_repo
                for page in range(1, page_limit + 1):
                    result = self._run_query(query, page)
                    items = result.payload.get("items", [])
                    for item in items:
                        repo_full_name, repo_url = parse_repo_from_item(item)
                        if not repo_full_name or not repo_url:
                            continue
                        candidate = candidates.setdefault(
                            repo_full_name,
                            RepoCandidate(cve_id=cve_id, repo_full_name=repo_full_name, repo_url=repo_url),
                        )
                        for match in extract_matches(item, query["match_type"], query["query"]):
                            candidate.add_match(match.path, match.match_type, match.query)
                    if len(items) < 50:
                        break

        metadata = self.client.fetch_repo_metadata(candidates.keys())
        for repo_full_name, candidate in candidates.items():
            meta = metadata.get(repo_full_name, {})
            candidate.metadata = normalise_metadata(meta, repo_full_name, candidate.repo_url)

        repos: List[Dict] = []
        for candidate in candidates.values():
            matches_dicts = []
            for m in candidate.matches:
                m.score = match_score({"path": m.path, "match_type": m.match_type})
                matches_dicts.append({"path": m.path, "match_type": m.match_type, "query": m.query, "score": m.score})
            score, tier = score_repo(candidate.metadata, matches_dicts, self.blacklist)
            repo_entry = {
                **candidate.metadata,
                "matches": matches_dicts,
                "confidence_score": score,
                "confidence_tier": tier,
                "cve_id": cve_id,
            }
            repos.append(repo_entry)

        repos.sort(key=lambda r: (-r["confidence_score"], -r.get("stars", 0)))

        evidence = {
            "queries": query_log,
            "candidates": [
                {
                    "repo_full_name": r["repo_full_name"],
                    "matches": r["matches"],
                    "match_count": len(r["matches"]),
                    "score": r["confidence_score"],
                    "tier": r["confidence_tier"],
                }
                for r in repos
            ],
        }
        return {"cve_id": cve_id, "last_updated": isoformat(), "pocs": repos, "evidence": evidence}

    def discover_many(self, cve_ids: Iterable[str], *, days: int, limit: Optional[int] = None) -> List[Dict]:
        results: List[Dict] = []
        for idx, cve_id in enumerate(cve_ids):
            if limit and idx >= limit:
                break
            results.append(self.discover_for_cve(cve_id, days=days))
        return results


def persist_evidence(results: List[Dict]) -> None:
    ensure_dirs(EVIDENCE_DIR)
    for result in results:
        cve_id = result["cve_id"]
        evidence_path = EVIDENCE_DIR / f"{cve_id}.json"
        save_json(evidence_path, result.get("evidence", {}))


def discover_from_github_list(path: Path) -> List[str]:
    if not path.exists():
        return []
    ids: List[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        matches = CVE_RE.findall(line)
        for match in matches:
            if match.upper() not in ids:
                ids.append(match.upper())
    return ids


def load_existing_cves(api_dir: Path = API_DIR / "cve") -> List[str]:
    if not api_dir.exists():
        return []
    return sorted({p.stem.upper() for p in api_dir.glob("CVE-*.json") if CVE_RE.match(p.stem)})


def build_scope(
    days: int,
    *,
    github_list: Path,
    existing_api: Path,
    prefer_recent_years: bool = True,
    max_cves: int | None = None,
    low_conf_threshold: int = 1,
) -> List[str]:
    seeds = discover_from_github_list(github_list)
    existing = load_existing_cves(existing_api)
    candidates = seeds or existing

    if prefer_recent_years:
        current_year = date.today().year
        candidates = [cve for cve in candidates if cve_year(cve) and cve_year(cve) >= current_year - 2] or candidates

    index_path = API_DIR / "index.json"
    low_conf: List[str] = []
    if index_path.exists():
        index_payload = load_json(index_path, default={}) or {}
        for item in index_payload.get("items", []):
            score = (item.get("high_confidence", 0) or 0) + (item.get("medium_confidence", 0) or 0)
            if score <= low_conf_threshold:
                low_conf.append(item.get("cve_id"))

    scoped = candidates + [cve for cve in low_conf if cve and cve not in candidates]
    if max_cves:
        scoped = scoped[:max_cves]
    return scoped
