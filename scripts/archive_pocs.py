#!/usr/bin/env python3
"""Resumable Wayback lookup/capture of published PoC pages and source artifacts."""
from __future__ import annotations

import argparse
import hashlib
import gzip
import ipaddress
import json
import os
import re
import tempfile
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from http.client import HTTPException
from pathlib import Path
from urllib import error, parse, request

import link_health

ROOT = Path(__file__).resolve().parents[1]
DIRECTORY = ROOT / 'index' / 'archives'
API = 'https://web.archive.org/save'
AVAILABILITY = 'https://archive.org/wayback/available'
AGENT = 'pocindex/1.0 (+https://pocindex.io)'


def now() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def public_url(url: str) -> bool:
    try:
        p = parse.urlsplit(url)
        if (p.scheme not in {'http', 'https'} or not p.hostname or p.username or p.password
                or p.port not in {None, 80, 443} or any(c.isspace() for c in url)):
            return False
        host = p.hostname.lower()
        if '.' not in host or host.endswith(('.localhost', '.local', '.internal')):
            return False
        try:
            return ipaddress.ip_address(host).is_global
        except ValueError:
            return True
    except (ValueError, TypeError):
        return False


def identity(url: str) -> str:
    return link_health.url_key(url)


def snapshot_url(url: str, stamp: str) -> str:
    if not re.fullmatch(r'\d{14}', stamp) or not public_url(url):
        raise ValueError('Invalid Wayback capture identity')
    datetime.strptime(stamp, '%Y%m%d%H%M%S')
    return f'https://web.archive.org/web/{stamp}/{parse.urldefrag(url).url}'


def valid_snapshot(row: dict) -> bool:
    snap = row.get('snapshot') or {}
    try:
        p = parse.urlsplit(snap.get('url', ''))
        match = re.fullmatch(r'/web/(\d{14})/(https?://.+)', p.path + ('?' + p.query if p.query else ''))
        return bool(p.scheme == 'https' and p.netloc == 'web.archive.org' and match
                    and snap.get('timestamp') == match[1]
                    and snapshot_url(match[2], match[1]) == snap['url']
                    and (not row.get('original') or equivalent(match[2], row['original']))
                    and snap.get('verified_at'))
    except (ValueError, TypeError):
        return False


def load_records(directory: Path = DIRECTORY) -> dict:
    rows = {}
    for path in sorted(directory.glob('[0-9a-f][0-9a-f].json')):
        payload = json.loads(path.read_text())
        if payload.get('version') != 1 or not isinstance(payload.get('entries'), dict):
            raise ValueError(f'Invalid archive shard: {path}')
        for key, row in payload['entries'].items():
            if not isinstance(row, dict) or identity(row.get('original', '')) != key or not public_url(key):
                raise ValueError(f'Invalid archive record: {path}')
            if row.get('snapshot') and not valid_snapshot(row):
                raise ValueError(f'Invalid archive snapshot: {path}')
            rows[key] = row
    return rows


def save_records(rows: dict, changed: set[str], directory: Path = DIRECTORY) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    shards = {hashlib.sha256(key.encode()).hexdigest()[:2] for key in changed}
    for shard in sorted(shards):
        entries = {k: v for k, v in sorted(rows.items()) if hashlib.sha256(k.encode()).hexdigest()[:2] == shard}
        with tempfile.NamedTemporaryFile('w', dir=directory, delete=False) as handle:
            json.dump({'version': 1, 'entries': entries}, handle, sort_keys=True, separators=(',', ':'))
            handle.write('\n')
            temporary = Path(handle.name)
        temporary.replace(directory / (shard + '.json'))


def published_snapshots(records: dict | None = None, allowed: set | None = None) -> dict:
    rows = load_records() if records is None else records
    result = {}
    for key, row in rows.items():
        if not valid_snapshot(row) or allowed is not None and key not in allowed and row.get('parent') not in allowed:
            continue
        snap = {k: row['snapshot'][k] for k in ('url', 'timestamp')}
        result.setdefault(row['original'], {}).update(snap)
        if row.get('parent'):
            parent = rows.get(row['parent'], {}).get('original') or row.get('parent_original') or row['parent']
            result.setdefault(parent, {}).setdefault('files', []).append({'original': row['original'], **snap})
    return result


def archived_fallbacks(records: dict | None = None, blacklist=(), exclusions=()) -> dict:
    """Recover the preserved artifact, never republish its unavailable original."""
    result = defaultdict(list)
    records = load_records() if records is None else records
    rows = [row for row in records.values() if valid_snapshot(row)
            and (not row.get('parent') or not valid_snapshot(records.get(row['parent'], {})))]
    if not rows:
        return result
    eligible = {(row['cve'], identity(row['url'])): row for row in eligible_ledger()}
    for row in rows:
        source = row.get('parent') or row['original']
        if link_health.repository(source) not in blacklist:
            for cve in row.get('cves', []):
                pair = eligible.get((cve, identity(source)))
                if (re.fullmatch(r'CVE-\d{4}-\d{4,}', cve)
                        and (cve, link_health.repository(source)) not in exclusions
                        and pair and (link_health.unavailable(source) or pair.get('gone_reason') == 'unavailable')):
                    field = pair.get('field', 'poc')
                    result[cve].append((field, row['snapshot']['url']))
    return result


class ArchiveError(Exception):
    def __init__(self, reason: str, *, cooldown: int = 0, fatal: bool = False):
        super().__init__(reason)
        self.cooldown = cooldown
        self.fatal = fatal


def service_error(reason: str) -> ArchiveError | None:
    if reason in {'error:max-daily-bandwidth', 'error:max-daily-bandwidth-from-ip'}:
        return ArchiveError(reason, cooldown=86400)
    if reason == 'error:user-session-limit':
        return ArchiveError(reason, cooldown=300)
    if reason == 'error:blocked-client-ip':
        return ArchiveError(reason, cooldown=3600)
    if reason in {'error:celery', 'error:job-failed', 'error:internal-server-error',
                  'error:no-browsers-available', 'error:proxy-error', 'error:capture-location-error', 'error:cannot-fetch'}:
        return ArchiveError(reason, cooldown=600)
    return None


class NoRedirect(request.HTTPRedirectHandler):
    # IA credentials are never forwarded to a redirected origin.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def response_bytes(response, limit: int) -> bytes:
    encoding = response.headers.get('Content-Encoding', '').lower()
    if encoding in {'', 'identity'}:
        body = response.read(limit + 1)
    elif encoding == 'gzip':
        with gzip.GzipFile(fileobj=response) as stream:
            body = stream.read(limit + 1)
    else:
        raise ArchiveError('unsupported-response-encoding')
    if len(body) > limit:
        raise ArchiveError('response-too-large')
    return body


class ReplayRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        destination = parse.urlsplit(newurl)
        if destination.scheme != 'https' or destination.netloc != 'web.archive.org':
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def after(seconds: float) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds)).strftime('%Y-%m-%dT%H:%M:%SZ')


def retry_delay(value: str, default: int = 300) -> int:
    try:
        seconds = int(value) if value.isdigit() else (parsedate_to_datetime(value) - datetime.now(timezone.utc)).total_seconds()
        return max(default, int(seconds))
    except (ValueError, TypeError, OverflowError):
        return default


class Client:
    def __init__(self, access: str = '', secret: str = '', interval: float = 15):
        self.auth = f'LOW {access}:{secret}' if access and secret else ''
        self.interval = max(10 if self.auth else 21, interval)
        self.last_submit = 0.0
        self.last_request = 0.0

    def json(self, url: str, data: dict | None = None, *, auth: bool = False) -> dict:
        self.operation = ('capture' if data is not None else 'availability' if url.startswith(AVAILABILITY)
                          else 'account' if '/status/user?' in url else 'capture-status')
        # Space lookups and status requests too, not just capture submissions.
        time.sleep(max(0, 1 - (time.monotonic() - self.last_request)))
        self.last_request = time.monotonic()
        headers = {'Accept': 'application/json', 'User-Agent': AGENT, 'Accept-Encoding': 'identity'}
        if auth and self.auth:
            if parse.urlsplit(url).netloc != 'web.archive.org':
                raise ValueError('Credentials may only be sent to Wayback')
            headers['Authorization'] = self.auth
        payload = None if data is None else parse.urlencode(data).encode()
        req = request.Request(url, data=payload, headers=headers)
        try:
            with request.build_opener(NoRedirect).open(req, timeout=30) as response:
                value = json.loads(response_bytes(response, 1_000_000))
            if not isinstance(value, dict):
                raise ArchiveError('invalid-response', cooldown=600)
            return value
        except error.HTTPError as exc:
            code = exc.code
            retry = exc.headers.get('Retry-After', '')
            exc.close()
            delay = retry_delay(retry) if code == 429 else 600 if code >= 500 else 0
            raise ArchiveError(f'http-{code}', cooldown=delay, fatal=code in {401, 403}) from None
        except (OSError, error.URLError, ValueError, HTTPException, EOFError) as exc:
            raise ArchiveError(type(exc).__name__, cooldown=600) from None

    def lookup(self, url: str) -> dict | None:
        result = self.json(AVAILABILITY + '?' + parse.urlencode({'url': parse.urldefrag(url).url}))
        if not isinstance(result.get('archived_snapshots'), dict):
            raise ArchiveError('invalid-availability-response', cooldown=600)
        row = result['archived_snapshots'].get('closest') or {}
        if not row:
            return None
        if row.get('available') is not True or str(row.get('status')) != '200':
            return None
        replay = str(row.get('url', '')).replace('http://web.archive.org/', 'https://web.archive.org/', 1)
        candidate = {'url': replay, 'timestamp': row.get('timestamp'), 'verified_at': now()}
        if not valid_snapshot({'snapshot': candidate}):
            raise ArchiveError('invalid-snapshot-response', cooldown=600)
        captured = replay.split('/web/' + candidate['timestamp'] + '/', 1)[1]
        if not equivalent(captured, url):
            return None
        return candidate

    def submit(self, url: str, *, retry: bool = False) -> dict:
        time.sleep(max(0, self.interval - (time.monotonic() - self.last_submit)))
        self.last_submit = time.monotonic()
        return self.json(API, {'url': parse.urldefrag(url).url, 'capture_all': '0', 'capture_outlinks': '0',
                               'skip_first_archive': '1', 'if_not_archived_within': '1s' if retry else '30d'}, auth=True)

    def status(self, job: str) -> dict:
        if not re.fullmatch(r'[a-zA-Z0-9-]+', job):
            raise ArchiveError('invalid-job-id')
        return self.json(API + '/status/' + job, auth=True)

    def capacity(self) -> int:
        row = self.json(API + '/status/user?' + parse.urlencode({'_t': time.time_ns()}), auth=True)
        for field in ('daily_captures', 'daily_status'):
            used, limit = row.get(field), row.get(field + '_limit')
            if isinstance(used, int) and isinstance(limit, int) and used >= limit:
                raise ArchiveError('daily-quota-exhausted', cooldown=86400)
        available = row.get('available')
        if not isinstance(available, int) or available < 0:
            raise ArchiveError('invalid-capacity-response', cooldown=300)
        if available == 0:
            raise ArchiveError('no-capture-slots', cooldown=300)
        return min(2, available)


def verify_snapshot(snap: dict, original: str, expected_blobs=(), repo_id=None) -> bool:
    """Replay must load content, not a login page or an archive error wrapper."""
    replay = snap['url'].replace('/' + snap['timestamp'] + '/', '/' + snap['timestamp'] + 'id_/', 1)
    try:
        with request.build_opener(ReplayRedirect).open(request.Request(replay, headers={'User-Agent': AGENT}), timeout=30) as response:
            final = parse.urlsplit(response.url)
            if (response.status != 200 or final.hostname != 'web.archive.org'
                    or not final.path.startswith('/web/' + snap['timestamp'] + 'id_/')):
                return False
            body = response_bytes(response, 2_000_000)
            mime = response.headers.get('Content-Type', '').lower()
        if not body:
            return False
        raw = parse.urlsplit(original).hostname == 'raw.githubusercontent.com'
        verified_raw = False
        if raw and expected_blobs and len(body) >= 256:
            digest = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
            if digest not in expected_blobs:
                return False
            verified_raw = True
        if not verified_raw and body.strip() in {b'404: Not Found', b'Not Found', b'Access Denied'}:
            return False
        if not verified_raw and ('html' in mime or body.lstrip().lower().startswith(b'<!doctype html')):
            text = body.decode('utf-8', errors='replace')
            if repo_id and parse.urlsplit(original).hostname in {'github.com', 'www.github.com'}:
                found = re.search(r'<meta\s+name="octolytics-dimension-repository_id"\s+content="(\d+)"', text)
                if not found or found[1] != str(repo_id):
                    return False
            title = re.search(r'<title[^>]*>(.*?)</title>', text, re.I | re.S)
            if title and re.search(r'^\s*(404\b|(?:page )?not found\b|page unavailable\b|access denied\b|sign in\b|log in\b|just a moment\b|Wayback Machine\s*$)', title[1], re.I):
                return False
            if parse.urlsplit(original).hostname in {'hackerone.com', 'www.hackerone.com'}:
                # A 200 HackerOne application shell is not a saved public report.
                if not re.search(r'"vulnerability_information"\s*:\s*"[^"\s]|report-content[^>]*>\s*\S', text):
                    return False
        if parse.urlsplit(original).path.endswith('.json') and 'hackerone.com' == parse.urlsplit(original).hostname:
            report = json.loads(body)
            if not isinstance(report, dict) or not report.get('disclosed_at') or not report.get('vulnerability_information'):
                return False
        snap['verified_at'] = now()
        return True
    except error.HTTPError as exc:
        status = exc.code
        retry = exc.headers.get('Retry-After', '')
        exc.close()
        if status in {404, 429} or status >= 500:
            raise ArchiveError(f'replay-http-{status}', cooldown=retry_delay(retry) if status == 429 else 0) from None
        return False
    except (OSError, error.URLError, HTTPException, EOFError) as exc:
        raise ArchiveError('replay-' + type(exc).__name__) from None
    except ValueError:
        return False


def eligible_ledger(min_year: int = 2026) -> list[dict]:
    import releases
    from build_site import load_blacklist, load_source_exclusions, load_reference_exclusions, link_key, METADATA_INPUT
    blacklist, exclusions, references = load_blacklist(), load_source_exclusions(), load_reference_exclusions()
    rejected = set()
    for path in METADATA_INPUT.glob('*.json'):
        if path.stem.isdigit() and int(path.stem) >= min_year:
            rejected.update(cve for cve, meta in json.loads(path.read_text()).items() if meta.get('rejected'))
    result = []
    for row in releases.load_ledger().values():
        url = row['url']
        cve = re.fullmatch(r'CVE-(\d{4})-\d{4,}', row.get('cve', ''))
        if (not cve or int(cve[1]) < min_year or not public_url(url) or row['cve'] in rejected
                or parse.urlsplit(url).hostname == 'web.archive.org'
                or link_health.repository(url) in blacklist
                or (row['cve'], link_health.repository(url)) in exclusions
                or (row['cve'], link_key(url)) in references
                or row.get('gone') and row.get('gone_reason') != 'unavailable'):
            continue
        result.append(row)
    return result


def inventory(min_year: int = 2026) -> dict:
    import releases
    result = {}
    for row in eligible_ledger(min_year):
        url = row['url']
        key = identity(url)
        target = result.setdefault(key, {'original': url, 'cves': [], 'priority': ''})
        if row['cve'] not in target['cves']:
            target['cves'].append(row['cve'])
        target['priority'] = max(target['priority'], row.get('seen') or row.get('released') or '')
        # First observation is an upper bound, not proof the material did not
        # exist earlier. Accept older captures unless publication evidence rules
        # them out (verified history, repository creation or source date).
        released, _ = releases.date_release(row)
        earliest = releases.timestamp(released)
        if earliest:
            bound = earliest.strftime('%Y-%m-%dT%H:%M:%SZ')
            target['not_before'] = min(target.get('not_before', bound), bound)
        if row.get('repo'):
            target['repo_id'] = str(row['repo'])
        if re.fullmatch(r'/reports/\d+/?', parse.urlsplit(url).path) and parse.urlsplit(url).hostname in {'hackerone.com', 'www.hackerone.com'}:
            report_json = url.rstrip('/') + '.json'
            item = result.setdefault(identity(report_json), {'original': report_json, 'cves': [],
                                      'priority': target['priority'], 'parent': key, 'parent_original': url})
            if row['cve'] not in item['cves']:
                item['cves'].append(row['cve'])
        # Pin actual code bytes when source inspection already identified a revision.
        sha = row.get('sha') if row.get('commit_verified') else None
        repo = link_health.repository(url)
        files = set()
        if repo and re.fullmatch(r'[0-9a-f]{40}', sha or ''):
            files.update((sha, path) for path in row.get('history_paths', []))
        pinned = re.fullmatch(r'/[^/]+/[^/]+/(?:blob|raw)/([0-9a-f]{40})/(.+)', parse.urlsplit(url).path)
        if repo and pinned:
            files.add((pinned[1], parse.unquote(pinned[2])))
        for revision, path in sorted(files):
            raw = f'https://raw.githubusercontent.com/{repo}/{revision}/{parse.quote(path, safe="/")}'
            item = result.setdefault(identity(raw), {'original': raw, 'cves': [],
                                                     'priority': target['priority'], 'parent': key,
                                                     'parent_original': url})
            if row.get('head') == revision and path in row.get('history_paths', []) and row.get('blobs'):
                item['expected_blobs'] = row['blobs']
            if row['cve'] not in item['cves']:
                item['cves'].append(row['cve'])
    return result


def equivalent(left: str, right: str) -> bool:
    def parts(url):
        parsed = parse.urlsplit(identity(url))
        return parsed.netloc.lower().removeprefix('www.'), parsed.path.rstrip('/'), parsed.query
    return public_url(left) and public_url(right) and parts(left) == parts(right)


def active_job(row: dict) -> bool:
    return bool(row.get('job_id') and row.get('submitted_at', '') > after(-3600))


def verify_candidate(row: dict) -> None:
    snap = row['candidate']
    captured = snap['url'].split('/web/' + snap['timestamp'] + '/', 1)[1]
    moment = datetime.strptime(snap['timestamp'], '%Y%m%d%H%M%S').replace(tzinfo=timezone.utc)
    lower = datetime.fromisoformat(row['not_before'].replace('Z', '+00:00')) if row.get('not_before') else None
    upper = datetime.fromisoformat(row['unavailable_since'].replace('Z', '+00:00')) if row.get('unavailable_since') else None
    row['next_check_at'] = after(60)
    row['verify_attempts'] = row.get('verify_attempts', 0) + 1
    if row['verify_attempts'] > 5:
        row['next_check_at'] = after(3600)
    valid = equivalent(captured, row['original']) and (lower is None or moment >= lower - timedelta(minutes=5))
    valid = valid and (upper is None or moment <= upper)
    if valid and verify_snapshot(snap, row['original'], row.get('expected_blobs', ()), row.get('repo_id')):
        snap['verified_at'] = now()
        if not valid_snapshot({'original': row['original'], 'snapshot': snap}):
            row.pop('candidate', None)
            row.update(error='invalid-capture-response', next_check_at=after(86400))
            return
        # Keep the first preserved version: subsequent owner edits must not
        # replace the research we captured when it was originally indexed.
        if not valid_snapshot(row):
            row['snapshot'] = snap
        else:
            row['latest_snapshot'] = snap
        row.update(status='available', attempts=0, next_check_at=after(30 * 86400))
        row.pop('error', None)
        row.pop('bad_capture', None)
    else:
        row.update(error='capture-content-unverified', bad_capture=True,
                   next_check_at=after(min(7 * 86400, 3600 * 2 ** min(row.get('attempts', 0), 8))))
    row.pop('candidate', None)
    row.pop('verify_attempts', None)


def capture_failure(row: dict, reason: str) -> None:
    row['error'] = reason
    if problem := service_error(reason):
        raise problem
    if reason == 'error:too-many-daily-captures':
        row['next_check_at'] = after(86400)
    if reason in {'error:too-many-requests', 'error:max-daily-bandwidth-host'}:
        row['host_retry_after'] = after(60 if reason == 'error:too-many-requests' else 86400)


def process(key: str, target: dict, rows: dict, client: Client, *, capture: bool) -> None:
    row = rows.setdefault(key, {**target, 'attempts': 0})
    for field in ('not_before', 'repo_id', 'parent', 'parent_original', 'expected_blobs'):
        row.pop(field, None)
    row.update(target)  # Drop corrected CVE associations; don't union stale ones.
    row.update(checked_at=now(), status='retry')
    unavailable = link_health.unavailable(row['original']) or bool(row.get('parent') and link_health.unavailable(row['parent']))
    if unavailable:
        row.setdefault('unavailable_since', link_health.unavailable_since(row['original'])
                       or link_health.unavailable_since(row.get('parent', '')) or now())
        if valid_snapshot(row):
            row.pop('job_id', None)
            row.pop('candidate', None)
            row.update(status='available', next_check_at=after(30 * 86400))
            return
    else:
        row.pop('unavailable_since', None)
    if row.get('candidate'):
        verify_candidate(row)
        return
    recover_job = False
    if row.get('job_id'):
        row['next_check_at'] = after(30)
        try:
            status = client.status(row['job_id']) if active_job(row) else {}
        except ArchiveError as exc:
            if str(exc) not in {'http-404', 'http-410'}:
                raise
            status = {}
        if status.get('status') == 'pending':
            row.update(status='pending', next_check_at=after(10))
            return
        row.pop('job_id', None)
        if status.get('status') == 'success':
            try:
                row['candidate'] = {'url': snapshot_url(status.get('original_url', row['original']), status['timestamp']),
                                    'timestamp': status['timestamp']}
            except (ValueError, TypeError, KeyError):
                row.update(error='invalid-capture-response', next_check_at=after(3600))
                return
            verify_candidate(row)
            return  # Never resubmit a terminal job in the same run.
        if status.get('status') == 'error':
            row['next_check_at'] = after(3600)
            capture_failure(row, str(status.get('status_ext') or 'capture-error'))
            return
        recover_job = True
    row['attempts'] = row.get('attempts', 0) + 1
    row['next_check_at'] = after(min(7 * 86400, 3600 * 2 ** min(row['attempts'], 8)))
    # Authenticated Save Page Now deduplicates live URLs itself; the public
    # availability API is needed for removed URLs and expired status jobs.
    if not capture or unavailable or recover_job:
        snap = client.lookup(row['original'])
        if snap:
            row['candidate'] = snap
            verify_candidate(row)
            return
    if not capture or unavailable:
        row['status'] = 'not-found'
        return
    day = now()[:10]
    budget = row.setdefault('submissions', {'date': day, 'count': 0})
    if budget['date'] != day:
        budget.update(date=day, count=0)
    if budget['count'] >= 2:
        row['next_check_at'] = after(86400)
        return
    budget['count'] += 1
    row['submitted_at'] = now()
    try:
        response = client.submit(row['original'], retry=bool(row.get('bad_capture')))
    finally:
        # submit() may first wait for its pacing slot. Persist the completion
        # time so a restarted worker cannot underestimate the last request.
        row['submitted_at'] = now()
    job = response.get('job_id')
    if job and re.fullmatch(r'[a-zA-Z0-9-]+', str(job)):
        row.update(job_id=job, status='pending', next_check_at=after(10))
        row.pop('error', None)
    else:
        capture_failure(row, str(response.get('status_ext') or 'capture-not-accepted')[:160])


def credentials() -> tuple[str, str]:
    access, secret = os.environ.get('IA_ACCESS_KEY', ''), os.environ.get('IA_SECRET_KEY', '')
    if bool(access) != bool(secret):
        raise ValueError('Both Internet Archive credentials must be set')
    if not access and not os.environ.get('GITHUB_ACTIONS'):
        path = Path.home() / '.config' / 'pocindex' / 'internet-archive.json'
        if path.exists():
            if path.stat().st_mode & 0o077:
                raise ValueError('Internet Archive credential file must be private (chmod 600)')
            stored = json.loads(path.read_text())
            access, secret = stored['access'], stored['secret']
    return access, secret


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--limit', type=int, default=100)
    parser.add_argument('--max-seconds', type=int, default=1200)
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--directory', type=Path, default=DIRECTORY)
    parser.add_argument('--url', action='append', help='Only process these known inventory URLs')
    parser.add_argument('--merge-from', type=Path)
    parser.add_argument('--stats', action='store_true')
    parser.add_argument('--min-year', type=int, default=2026)
    args = parser.parse_args()
    if args.limit < 1 or args.max_seconds < 1 or args.min_year < 1999:
        parser.error('Run limits must be positive')
    rows = load_records(args.directory)
    if args.merge_from:
        incoming = load_records(args.merge_from)
        for key, row in incoming.items():
            old = rows.get(key, {})
            if old.get('checked_at', '') > row.get('checked_at', ''):
                continue
            if valid_snapshot(old):
                row['snapshot'] = old['snapshot']
            rows[key] = row
        save_records(rows, set(incoming), args.directory)
        control = args.merge_from / 'control.json'
        current = args.directory / 'control.json'
        if control.exists():
            incoming_control = json.loads(control.read_text())
            existing = json.loads(current.read_text()) if current.exists() else {}
            if incoming_control.get('retry_after', '') > existing.get('retry_after', ''):
                current.write_text(json.dumps(incoming_control) + '\n')
        return 0
    targets = inventory(args.min_year)
    if args.stats:
        print(json.dumps({'min_year': args.min_year, 'targets': len(targets),
                          'original_urls': sum(not r.get('parent') for r in targets.values()),
                          'source_files': sum(bool(r.get('parent')) for r in targets.values()),
                          'processed': sum(k in rows for k in targets),
                          'snapshots': sum(valid_snapshot(rows.get(k, {})) for k in targets),
                          'states': dict(Counter(rows[k].get('status') for k in targets if k in rows))}, indent=2))
        return 0
    if args.url:
        keys = {identity(url) for url in args.url}
        targets = {key: value for key, value in targets.items() if key in keys}
        if keys - targets.keys():
            parser.error('Requested URL is not in the published-artifact inventory')
    client = Client(*credentials())
    if args.capture and not client.auth:
        parser.error('Authenticated captures require IA_ACCESS_KEY and IA_SECRET_KEY')
    submitted = max((row.get('submitted_at', '') for row in rows.values()), default='')
    if submitted:
        elapsed = (datetime.now(timezone.utc) - datetime.fromisoformat(submitted.replace('Z', '+00:00'))).total_seconds()
        client.last_submit = time.monotonic() - max(0, elapsed)
    control = args.directory / 'control.json'
    if control.exists() and json.loads(control.read_text()).get('retry_after', '') > now():
        print('Archive service cooldown is still active')
        return 0
    slots = 1
    if args.capture:
        try:
            slots = client.capacity()
        except ArchiveError as exc:
            args.directory.mkdir(parents=True, exist_ok=True)
            control.write_text(json.dumps({'retry_after': after(exc.cooldown or 300), 'reason': str(exc)}) + '\n')
            print(f'Archive service requested backoff: {exc}', flush=True)
            return 1 if exc.fatal else 0
    selected = [key for key in targets if not rows.get(key, {}).get('job_id') and not rows.get(key, {}).get('candidate')
                and rows.get(key, {}).get('next_check_at', '') <= now()]
    # New discoveries first, then unsuccessful attempts, then refreshes of
    # already-preserved pages. Failed refreshes never discard a good snapshot.
    selected.sort(key=lambda key: (not valid_snapshot(rows.get(key, {})), targets[key]['priority'], key), reverse=True)
    start = time.monotonic()
    completed = 0
    while time.monotonic() - start < args.max_seconds:
        hosts = {parse.urlsplit(r['original']).hostname for r in rows.values() if r.get('host_retry_after', '') > now()}
        selected = [key for key in selected if parse.urlsplit(targets[key]['original']).hostname not in hosts]
        pending = [key for key in targets if rows.get(key, {}).get('job_id') or rows.get(key, {}).get('candidate')]
        due = [key for key in pending if rows[key].get('next_check_at', '') <= now()
               or rows[key].get('job_id') and not active_job(rows[key])]
        if due:
            key = min(due, key=lambda k: rows[k].get('next_check_at', ''))
        elif selected and completed < args.limit and sum(active_job(rows[k]) for k in pending) < slots:
            key = selected.pop(0)
            completed += 1
        elif pending:
            if all(rows[k].get('next_check_at', '') > after(args.max_seconds - (time.monotonic() - start)) for k in pending):
                break
            time.sleep(5)
            continue
        else:
            break
        attempts = rows.get(key, {}).get('attempts', 0)
        try:
            process(key, targets[key], rows, client, capture=args.capture)
        except ArchiveError as exc:
            rows[key]['error'] = str(exc)
            rows[key]['status'] = 'retry'
            if exc.fatal:
                print(f'Archive authentication failed: {exc}', flush=True)
                return 1
            if exc.cooldown:
                rows[key]['attempts'] = attempts
                rows[key]['next_check_at'] = (datetime.now(timezone.utc) + timedelta(seconds=exc.cooldown)).strftime('%Y-%m-%dT%H:%M:%SZ')
                save_records(rows, {key}, args.directory)
                control.write_text(json.dumps({'retry_after': rows[key]['next_check_at'], 'reason': str(exc)}) + '\n')
                print(f'Archive service requested backoff during {client.operation}: {exc}', flush=True)
                break
        finally:
            save_records(rows, {key}, args.directory)
        print(f'{completed}: {rows[key]["status"]} {targets[key]["original"]}', flush=True)
    print(json.dumps({'processed': completed, 'snapshots': sum(valid_snapshot(r) for r in rows.values())}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
