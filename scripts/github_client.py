from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import requests

from utils import CACHE_DIR, chunked, hash_key, isoformat


TEXT_MATCH_HEADER = "application/vnd.github.text-match+json"


class RateLimiter:
    def __init__(self, calls_per_minute: int) -> None:
        self.min_interval = 60.0 / max(calls_per_minute, 1)
        self.last_call: Dict[str, float] = {}

    def wait(self, bucket: str) -> None:
        last = self.last_call.get(bucket, 0.0)
        elapsed = time.time() - last
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self.last_call[bucket] = time.time()


class FileCache:
    def __init__(self, base: Path) -> None:
        self.base = base
        self.base.mkdir(parents=True, exist_ok=True)

    def _path_for(self, key: str) -> Path:
        digest = hash_key(key)
        return self.base / digest[:2] / f"{digest}.json"

    def load(self, key: str, *, ttl: int) -> Optional[Dict]:
        path = self._path_for(key)
        if not path.exists():
            return None
        try:
            with path.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, json.JSONDecodeError):
            return None
        expires_at = data.get("expires_at")
        if expires_at:
            try:
                expires_ts = time.mktime(time.strptime(expires_at, "%Y-%m-%dT%H:%M:%S"))
                if time.time() > expires_ts:
                    return None
            except Exception:
                return None
        return data.get("payload")

    def save(self, key: str, payload: Dict, *, ttl: int) -> None:
        path = self._path_for(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "fetched_at": isoformat(),
            "expires_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + ttl)),
            "payload": payload,
        }
        with path.open("w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2)


@dataclass
class SearchResult:
    kind: str
    query: str
    page: int
    payload: Dict


class GitHubClient:
    def __init__(
        self,
        token: Optional[str],
        *,
        cache_dir: Path | None = None,
        code_search_rpm: int = 10,
        general_rpm: int = 30,
    ) -> None:
        self.session = requests.Session()
        self.session.headers.update({"Accept": TEXT_MATCH_HEADER})
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        self.base_url = "https://api.github.com"
        self.graphql_url = f"{self.base_url}/graphql"
        cache_root = cache_dir or CACHE_DIR / "github"
        self.cache = FileCache(cache_root)
        self.rate_limiters = {
            "code": RateLimiter(code_search_rpm),
            "search": RateLimiter(general_rpm),
            "graphql": RateLimiter(general_rpm),
        }

    def _request(self, method: str, url: str, *, bucket: str, **kwargs) -> requests.Response:
        self.rate_limiters[bucket].wait(bucket)
        attempts = 0
        while True:
            attempts += 1
            try:
                response = self.session.request(method, url, timeout=30, **kwargs)
            except requests.RequestException:
                if attempts >= 3:
                    raise
                time.sleep(2 * attempts)
                continue

            if response.status_code == 403 and "X-RateLimit-Remaining" in response.headers:
                remaining = int(response.headers.get("X-RateLimit-Remaining") or "0")
                reset = response.headers.get("X-RateLimit-Reset")
                if remaining <= 0 and reset:
                    try:
                        reset_ts = int(reset)
                        wait_for = max(0, reset_ts - int(time.time()) + 1)
                        time.sleep(wait_for)
                        continue
                    except ValueError:
                        pass
            if response.status_code >= 500 and attempts < 3:
                time.sleep(1 + attempts)
                continue
            response.raise_for_status()
            return response

    def _cached_search(self, kind: str, query: str, page: int, per_page: int, ttl: int) -> Dict:
        cache_key = f"{kind}:{query}:p{page}:n{per_page}"
        cached = self.cache.load(cache_key, ttl=ttl)
        if cached is not None:
            return cached

        url = f"{self.base_url}/search/{kind}"
        params = {"q": query, "page": page, "per_page": per_page}
        resp = self._request("GET", url, params=params, bucket="code" if kind == "code" else "search")
        payload = resp.json()
        self.cache.save(cache_key, payload, ttl=ttl)
        return payload

    def search_repositories(self, query: str, *, page: int = 1, per_page: int = 100, ttl: int = 3600) -> SearchResult:
        return SearchResult("repositories", query, page, self._cached_search("repositories", query, page, per_page, ttl))

    def search_code(self, query: str, *, page: int = 1, per_page: int = 100, ttl: int = 3600) -> SearchResult:
        return SearchResult("code", query, page, self._cached_search("code", query, page, per_page, ttl))

    def search_topics(self, query: str, *, page: int = 1, per_page: int = 100, ttl: int = 3600) -> SearchResult:
        return SearchResult("repositories", query, page, self._cached_search("repositories", query, page, per_page, ttl))

    def fetch_repo_metadata(self, full_names: Iterable[str], *, ttl: int = 6 * 3600) -> Dict[str, Dict]:
        results: Dict[str, Dict] = {}
        to_fetch: List[str] = []
        for name in full_names:
            cache_key = f"repo-meta:{name}"
            cached = self.cache.load(cache_key, ttl=ttl)
            if cached is not None:
                results[name] = cached
            else:
                to_fetch.append(name)

        if not to_fetch:
            return results

        fields = """
        nameWithOwner
        url
        stargazerCount
        description
        forkCount
        isFork
        isArchived
        pushedAt
        updatedAt
        primaryLanguage { name }
        parent { nameWithOwner url }
        repositoryTopics(first: 20) { nodes { topic { name } } }
        """

        for batch in chunked(to_fetch, 12):
            parts = []
            for idx, full_name in enumerate(batch):
                if "/" not in full_name:
                    continue
                owner, name = full_name.split("/", 1)
                owner = owner.replace('"', "")
                name = name.replace('"', "")
                parts.append(f'repo_{idx}: repository(owner: "{owner}", name: "{name}") {{ {fields} }}')
            if not parts:
                continue
            query = "query { " + " ".join(parts) + " }"
            resp = self._request("POST", self.graphql_url, json={"query": query}, bucket="graphql")
            data = resp.json()
            repos = data.get("data", {})
            for idx, full_name in enumerate(batch):
                key = f"repo_{idx}"
                meta = repos.get(key) or {}
                cache_key = f"repo-meta:{full_name}"
                self.cache.save(cache_key, meta, ttl=ttl)
                results[full_name] = meta

        return results


def build_client(token_env: str = "GITHUB_TOKEN") -> GitHubClient:
    token = os.environ.get(token_env)
    return GitHubClient(token, cache_dir=CACHE_DIR / "github")
