from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Tuple

from utils import clamp, parse_date

DOC_EXTS = {"md", "txt", "rst", "adoc", "markdown", "mkd", "mdown"}
POSITIVE_KEYWORDS = ("poc", "exploit", "rce", "lpe", "auth bypass", "bypass")
NEGATIVE_KEYWORDS = ("report", "writeup", "advisory", "changelog")


def is_doc_path(path: str) -> bool:
    lower = path.lower()
    if lower.endswith("/"):
        return True
    if "." not in lower:
        return False
    ext = lower.rsplit(".", 1)[-1]
    return ext in DOC_EXTS


def match_score(match: Dict) -> float:
    path = str(match.get("path", ""))
    match_type = str(match.get("match_type", "")).lower()
    base = 50 if not is_doc_path(path) else 30
    if match_type in ("code",):
        base += 10
    if "readme" in match_type:
        base += 5
    if "topic" in match_type:
        base -= 5
    return clamp(base, 0, 100)


def tier_for_score(score: float) -> str:
    if score >= 75:
        return "high"
    if score >= 45:
        return "medium"
    return "low"


def keyword_hits(text: str, keywords: Iterable[str]) -> int:
    if not text:
        return 0
    lower = text.lower()
    return sum(1 for kw in keywords if kw in lower)


def recency_bonus(pushed_at: str | None) -> float:
    if not pushed_at:
        return 0.0
    dt = parse_date(pushed_at)
    if not dt:
        return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt
    if delta <= timedelta(days=30):
        return 18.0
    if delta <= timedelta(days=90):
        return 10.0
    if delta <= timedelta(days=180):
        return 5.0
    return 0.0


def score_repo(repo: Dict, matches: List[Dict], blacklist: List[str]) -> Tuple[float, str]:
    stars = repo.get("stargazerCount") or repo.get("stars") or 0
    forks = repo.get("forkCount") or repo.get("forks") or 0
    is_fork = bool(repo.get("isFork"))
    archived = bool(repo.get("isArchived"))
    topics = [t.lower() for t in repo.get("topics", []) if t]
    name = str(repo.get("nameWithOwner") or repo.get("repo_full_name") or "").lower()
    description = str(repo.get("description") or "").lower()

    non_doc_matches = [m for m in matches if not is_doc_path(str(m.get("path", "")))]
    doc_matches = [m for m in matches if is_doc_path(str(m.get("path", "")))]

    score = 12.0
    if non_doc_matches:
        score += 25 + min(len(non_doc_matches) * 2, 10)
    if doc_matches and not non_doc_matches:
        score -= 20

    score += recency_bonus(repo.get("pushed_at") or repo.get("pushedAt") or repo.get("updated_at"))

    score += min(stars / 50.0, 25.0)
    score += min(forks / 200.0, 5.0)

    score += keyword_hits(description, POSITIVE_KEYWORDS) * 4.0
    score += keyword_hits(" ".join(topics), POSITIVE_KEYWORDS) * 4.0

    negative_bias = keyword_hits(description, NEGATIVE_KEYWORDS)
    if negative_bias and not non_doc_matches:
        score -= 15

    if is_fork:
        score -= 12
    if archived:
        score -= 30

    lowered_blacklist = [entry.lower() for entry in blacklist]
    for forbidden in lowered_blacklist:
        if not forbidden:
            continue
        if forbidden.endswith("*"):
            prefix = forbidden[:-1]
            if prefix and name.startswith(prefix):
                score -= 40
                break
        elif forbidden in name:
            score -= 40
            break

    for match in matches:
        score += match_score(match) / 25.0

    return clamp(score, 0, 100), tier_for_score(score)
