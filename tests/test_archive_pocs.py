from __future__ import annotations

import copy
import gzip
import io
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import archive_pocs as archive
import build_site
import releases

URL = 'https://github.com/owner/poc'
CVE = 'CVE-2026-1234'


def snapshot(url=URL, stamp=None):
    stamp = stamp or datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
    return {'url': archive.snapshot_url(url, stamp), 'timestamp': stamp, 'verified_at': archive.now()}


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.target = {'original': URL, 'cves': [CVE], 'priority': archive.now()}
        self.rows = {}
        self.client = MagicMock()
        self.client.lookup.return_value = None
        self.client.submit.return_value = {'job_id': 'pending-123'}
        p = patch.object(archive.link_health, 'unavailable', return_value=False)
        self.dead = p.start()
        self.addCleanup(p.stop)

    def test_inventory_limits_cve_year_and_preserves_source_paths(self):
        ledger = {
            'old': {'url': URL + '-old', 'cve': 'CVE-2025-1234'},
            'new': {'url': URL, 'cve': CVE, 'head': 'b' * 40, 'sha': 'a' * 40,
                    'commit_verified': True, 'paths': ['wrong.py'], 'history_paths': ['PoC x.py']},
            'future': {'url': URL, 'cve': 'CVE-2027-4567'},
            'bad': {'url': URL + '-blocked', 'cve': CVE},
            'excluded': {'url': URL + '-excluded', 'cve': CVE},
            'withdrawn': {'url': URL + '-withdrawn', 'cve': CVE, 'gone': '2026-01-01'},
        }
        with patch.object(releases, 'load_ledger', return_value=ledger), \
                patch.object(build_site, 'load_blacklist', return_value={'owner/poc-blocked'}), \
                patch.object(build_site, 'load_source_exclusions', return_value={(CVE, 'owner/poc-excluded')}):
            result = archive.inventory()
        self.assertEqual(len(result), 2)
        self.assertEqual(set(result[URL]['cves']), {CVE, 'CVE-2027-4567'})
        raw = next(v for v in result.values() if v.get('parent'))
        self.assertTrue(raw['original'].endswith('/' + 'a' * 40 + '/PoC%20x.py'))

    def test_snapshot_validation_rejects_fake_hosts_invalid_dates_and_private_urls(self):
        good = snapshot()
        self.assertTrue(archive.valid_snapshot({'snapshot': good}))
        for url in ('http://localhost/a', 'http://127.0.0.1/a', 'http://169.254.169.254/a',
                    'https://user:password@example.com/a', 'javascript:alert(1)', 'https://host.internal/a'):
            self.assertFalse(archive.public_url(url), url)
        for bad in ({**good, 'url': good['url'].replace('web.archive.org', 'web.archive.org.evil.example')},
                    {**good, 'timestamp': '20260231000000'}, {**good, 'verified_at': ''}):
            self.assertFalse(archive.valid_snapshot({'snapshot': bad}))

    def test_first_observation_does_not_disqualify_older_public_captures(self):
        ledger = [{'url': URL, 'cve': CVE, 'seen': '2026-10-21T12:00:00Z'},
                  {'url': URL + '-dated', 'cve': CVE, 'seen': '2026-10-21T12:00:00Z',
                   'source': '2026-05-13'}]
        with patch.object(archive, 'eligible_ledger', return_value=ledger):
            result = archive.inventory()
        self.assertNotIn('not_before', result[URL])
        self.assertEqual(result[URL + '-dated']['not_before'], '2026-05-13T00:00:00Z')

    def test_pinned_file_urls_preserve_bytes_without_additional_github_queries(self):
        parent = URL + '/blob/' + 'b' * 40 + '/path/PoC%20file.py#example'
        with patch.object(archive, 'eligible_ledger', return_value=[{'url': parent, 'cve': CVE}]):
            result = archive.inventory()
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'b' * 40 + '/path/PoC%20file.py'
        self.assertEqual(result[raw]['parent'], archive.identity(parent))
        self.assertEqual(result[raw]['parent_original'], parent)

    def test_lookup_rejects_capture_of_a_different_url(self):
        client = archive.Client()
        snap = snapshot(URL + '-other')
        response = {'archived_snapshots': {'closest': {**snap, 'status': '200', 'available': True}}}
        with patch.object(client, 'json', return_value=response):
            self.assertIsNone(client.lookup(URL))

    def test_existing_capture_is_verified_without_resubmission(self):
        self.client.lookup.return_value = snapshot()
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=False)
        self.assertTrue(archive.valid_snapshot(self.rows[URL]))
        self.client.submit.assert_not_called()

    def test_pending_job_is_checkpointed_and_polled_without_duplicate_submission(self):
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertEqual(self.rows[URL]['job_id'], 'pending-123')
        self.client.status.return_value = {'status': 'pending'}
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.submit.assert_called_once()
        self.client.lookup.assert_called_once_with(URL)
        self.assertEqual(self.rows[URL]['attempts'], 1)

    def test_success_requires_replay_verification(self):
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        snap = snapshot()
        self.client.status.return_value = {'status': 'success', 'timestamp': snap['timestamp'], 'original_url': URL}
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertEqual(self.rows[URL]['status'], 'available')
        self.assertNotIn('job_id', self.rows[URL])
        self.assertEqual(archive.published_snapshots(self.rows)[URL]['url'], snap['url'])

    def test_expired_job_recovers_by_lookup(self):
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.status.side_effect = archive.ArchiveError('http-404')
        self.client.lookup.return_value = snapshot()
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertNotIn('job_id', self.rows[URL])
        self.client.submit.assert_called_once()

    def test_refresh_error_keeps_previous_good_capture(self):
        old = snapshot(stamp='20260101000000')
        self.rows[URL] = {**self.target, 'snapshot': old, 'job_id': 'pending-123', 'attempts': 1}
        self.client.status.return_value = {'status': 'error', 'status_ext': 'error:read-timeout'}
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertEqual(self.rows[URL]['snapshot'], old)
        self.assertEqual(archive.published_snapshots(self.rows)[URL]['url'], old['url'])

    def test_unverified_terminal_job_never_resubmits_in_a_loop(self):
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.status.return_value = {'status': 'success', 'timestamp': snapshot()['timestamp'], 'original_url': URL}
        with patch.object(archive, 'verify_snapshot', return_value=False):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.submit.assert_called_once()
        self.assertNotIn('job_id', self.rows[URL])
        self.assertNotIn('candidate', self.rows[URL])
        self.assertGreater(self.rows[URL]['next_check_at'], archive.now())
        self.assertFalse(archive.valid_snapshot(self.rows[URL]))

    def test_transient_replay_failure_retains_candidate_without_resubmission(self):
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.status.return_value = {'status': 'success', 'timestamp': snapshot()['timestamp'], 'original_url': URL}
        with patch.object(archive, 'verify_snapshot', side_effect=archive.ArchiveError('replay-http-404')):
            with self.assertRaises(archive.ArchiveError):
                archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertIn('candidate', self.rows[URL])
        self.assertNotIn('job_id', self.rows[URL])
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.submit.assert_called_once()
        self.assertTrue(archive.valid_snapshot(self.rows[URL]))

    def test_expired_jobs_do_not_reserve_a_capture_slot(self):
        self.rows[URL] = {**self.target, 'job_id': 'old-job', 'submitted_at': archive.after(-7200)}
        self.assertFalse(archive.active_job(self.rows[URL]))
        archive.process(URL, self.target, self.rows, self.client, capture=False)
        self.client.status.assert_not_called()
        self.client.lookup.assert_called_once_with(URL)
        self.assertNotIn('job_id', self.rows[URL])

    def test_dead_original_with_good_capture_clears_stale_work(self):
        self.rows[URL] = {**self.target, 'snapshot': snapshot(), 'job_id': 'stale',
                          'candidate': snapshot(), 'submitted_at': archive.after(-7200)}
        self.dead.return_value = True
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertNotIn('job_id', self.rows[URL])
        self.assertNotIn('candidate', self.rows[URL])
        self.assertEqual(self.rows[URL]['status'], 'available')

    def test_fragments_never_enter_capture_identity_or_poison_a_shard(self):
        original = URL + '#poc'
        target = {**self.target, 'original': original}
        self.rows[URL] = {**target, 'job_id': 'job', 'submitted_at': archive.now()}
        self.client.status.return_value = {'status': 'success', 'timestamp': snapshot()['timestamp'], 'original_url': original}
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, target, self.rows, self.client, capture=True)
        self.assertNotIn('#', self.rows[URL]['snapshot']['url'])
        self.assertTrue(archive.valid_snapshot(self.rows[URL]))
        with tempfile.TemporaryDirectory() as directory:
            archive.save_records(self.rows, {URL}, Path(directory))
            self.assertEqual(archive.load_records(Path(directory)), self.rows)

    def test_repeated_unverifiable_capture_gets_increasing_backoff(self):
        self.rows[URL] = {**self.target, 'attempts': 7, 'candidate': snapshot()}
        with patch.object(archive, 'verify_snapshot', return_value=False):
            archive.process(URL, self.target, self.rows, self.client, capture=False)
        self.assertGreater(self.rows[URL]['next_check_at'], archive.after(6 * 3600))

    def test_redirect_homepage_and_capture_predating_poc_are_not_published(self):
        for target, captured in ((self.target, snapshot('https://github.com/')),
                                 ({**self.target, 'not_before': archive.now()}, snapshot(stamp='20260101000000'))):
            rows = {URL: {**target, 'candidate': captured}}
            with patch.object(archive, 'verify_snapshot') as replay:
                archive.process(URL, target, rows, self.client, capture=False)
            replay.assert_not_called()
            self.assertFalse(archive.valid_snapshot(rows[URL]))

    def test_account_errors_are_separate_from_target_errors(self):
        self.assertEqual(archive.service_error('error:max-daily-bandwidth').cooldown, 86400)
        for reason in ('error:filesize-limit', 'error:bandwidth-limit-exceeded',
                       'error:too-many-daily-captures', 'error:soft-time-limit-exceeded'):
            self.assertIsNone(archive.service_error(reason), reason)

    def test_daily_submission_budget_is_durable_and_first_capture_is_retained(self):
        self.rows[URL] = {**self.target, 'submissions': {'date': archive.now()[:10], 'count': 2}}
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.submit.assert_not_called()
        old = snapshot(stamp='20260101000000')
        self.rows[URL].update(snapshot=old, candidate=snapshot())
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertEqual(self.rows[URL]['snapshot'], old)

    def test_source_snapshots_are_attached_to_their_published_parent(self):
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/PoC.py'
        rows = {raw: {'original': raw, 'parent': URL, 'snapshot': snapshot(raw)}}
        result = archive.published_snapshots(rows, {URL})
        self.assertEqual(result[URL]['files'][0]['original'], raw)
        self.assertEqual(archive.published_snapshots(rows, set()), {})

    def test_source_file_can_recover_a_dead_parent_without_a_page_capture(self):
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/PoC.py'
        rows = {raw: {'original': raw, 'parent': URL, 'cves': [CVE], 'snapshot': snapshot(raw)}}
        self.dead.return_value = True
        with patch.object(archive, 'eligible_ledger', return_value=[{'cve': CVE, 'url': URL, 'field': 'nuclei'}]):
            self.assertEqual(archive.archived_fallbacks(rows)[CVE], [('nuclei', rows[raw]['snapshot']['url'])])

    def test_recovered_original_keeps_archive_until_it_is_reimported(self):
        self.dead.return_value = False
        self.rows[URL] = {**self.target, 'snapshot': snapshot()}
        with patch.object(archive, 'eligible_ledger', return_value=[{'cve': CVE, 'url': URL, 'gone_reason': 'unavailable'}]):
            self.assertEqual(len(archive.archived_fallbacks(self.rows)[CVE]), 1)

    def test_managed_fallback_does_not_redate_or_remove_legacy_archive_links(self):
        managed = snapshot()['url']
        legacy = archive.snapshot_url(URL + '-legacy', '20200101000000')
        with patch.object(archive, 'load_records', return_value={URL: {**self.target, 'snapshot': snapshot()}}):
            self.assertEqual(releases.published_pairs([{'cve': CVE, 'poc': [managed, legacy]}]), [(CVE, legacy)])
        old = releases.record({}, CVE, URL, observed_at='2026-01-01T00:00:00Z')
        self.dead.return_value = True
        ledger = releases.reconcile({releases.key(CVE, URL): old}, [], observed_at='2026-02-01T00:00:00Z')
        row = ledger[releases.key(CVE, URL)]
        self.assertEqual(row['seen'], '2026-01-01T00:00:00Z')
        self.assertEqual(row['gone_reason'], 'unavailable')

    def test_dead_original_is_only_looked_up_and_blacklist_cannot_be_bypassed(self):
        self.dead.return_value = True
        self.client.lookup.return_value = snapshot()
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.submit.assert_not_called()
        with patch.object(archive, 'eligible_ledger', return_value=[{'cve': CVE, 'url': URL}]):
            self.assertEqual(len(archive.archived_fallbacks(self.rows)[CVE]), 1)
        self.assertFalse(archive.archived_fallbacks(self.rows, blacklist={'owner/poc'}))
        self.assertFalse(archive.archived_fallbacks(self.rows, exclusions={(CVE, 'owner/poc')}))
        self.rows[URL]['parent'] = URL + '-parent'
        self.assertFalse(archive.archived_fallbacks(self.rows))

    def test_cooldown_and_checkpoints_survive_merge(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, destination = root / 'incoming', root / 'current'
            incoming = {URL: {**self.target, 'checked_at': archive.now(), 'status': 'retry'}}
            existing = {URL: {**self.target, 'checked_at': '2026-01-01', 'snapshot': snapshot()}}
            archive.save_records(incoming, {URL}, source)
            archive.save_records(existing, {URL}, destination)
            control = {'retry_after': archive.after(300), 'reason': 'http-429'}
            (source / 'control.json').write_text(json.dumps(control))
            with patch.object(sys, 'argv', ['archive', '--directory', str(destination), '--merge-from', str(source)]):
                self.assertEqual(archive.main(), 0)
            self.assertTrue(archive.valid_snapshot(archive.load_records(destination)[URL]))
            self.assertEqual(json.loads((destination / 'control.json').read_text()), control)

    def test_quota_and_retry_after_are_respected(self):
        client = archive.Client('dummy', 'dummy')
        with patch.object(client, 'json', return_value={'daily_captures': 30000, 'daily_captures_limit': 30000, 'available': 3}):
            with self.assertRaises(archive.ArchiveError) as result:
                client.capacity()
            self.assertEqual(result.exception.cooldown, 86400)
        self.assertEqual(archive.retry_delay('1200'), 1200)
        self.assertGreaterEqual(archive.retry_delay('invalid'), 300)
        opener = MagicMock()
        opener.open.side_effect = HTTPError('https://web.archive.org/save', 429, 'wait', {'Retry-After': '600'}, None)
        with patch.object(archive.request, 'build_opener', return_value=opener):
            with self.assertRaises(archive.ArchiveError) as result:
                client.submit(URL)
            self.assertEqual(result.exception.cooldown, 600)

    def test_capture_uses_only_explicit_url_and_never_archives_errors(self):
        client = archive.Client('dummy', 'dummy')
        with patch.object(client, 'json', return_value={'job_id': '1'}) as send:
            client.submit(URL)
        payload = send.call_args.args[1]
        self.assertEqual(payload['capture_all'], '0')
        self.assertEqual(payload['capture_outlinks'], '0')
        self.assertEqual(payload['if_not_archived_within'], '30d')

    def test_live_page_reuses_existing_snapshot_in_capture_mode(self):
        self.client.lookup.return_value = snapshot()
        with patch.object(archive, 'verify_snapshot', return_value=True):
            archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.assertTrue(archive.valid_snapshot(self.rows[URL]))
        self.client.submit.assert_not_called()

    def test_negative_lookup_is_immediately_ready_for_capture(self):
        archive.process(URL, self.target, self.rows, self.client, capture=False)
        self.assertEqual(self.rows[URL]['next_check_at'], '')
        archive.process(URL, self.target, self.rows, self.client, capture=True)
        self.client.lookup.assert_called_once()
        self.client.submit.assert_called_once()

    def test_transport_error_is_not_an_account_cooldown(self):
        from urllib.error import URLError
        opener = MagicMock()
        opener.open.side_effect = URLError(ConnectionResetError())
        with patch.object(archive.request, 'build_opener', return_value=opener):
            with self.assertRaises(archive.ArchiveError) as result:
                archive.Client().lookup(URL)
        self.assertEqual(result.exception.cooldown, 0)
        self.assertEqual(str(result.exception), 'transport-ConnectionResetError')

    def test_old_unseen_pages_and_files_cannot_be_starved_by_new_pages(self):
        targets = {f'{URL}/{i}': {**self.target, 'priority': '2026-10-22'} for i in range(100)}
        targets[URL] = {**self.target, 'priority': ''}
        targets['file'] = {**self.target, 'parent': URL, 'priority': '2026-01-01'}
        selected = archive.select_targets(targets, {})
        self.assertIn(URL, selected[:4])
        self.assertIn('file', selected[:4])
        self.assertEqual(len(selected), len(set(selected)))

    def test_lookup_sweep_continues_after_one_connection_failure(self):
        urls = [URL + str(i) for i in range(3)]
        targets = {u: {**self.target, 'original': u} for u in urls}
        def lookup(url):
            if url == urls[0]:
                raise archive.ArchiveError('transport-ConnectionResetError')
            return snapshot(url)
        self.client.lookup.side_effect = lookup
        with tempfile.TemporaryDirectory() as directory, patch.object(archive, 'verify_snapshot', return_value=True):
            archive.lookup_pages(targets, self.rows, self.client, Path(directory), 3, 10)
            self.assertEqual(len(archive.load_records(Path(directory))), 3)
            self.assertEqual(sum(archive.valid_snapshot(r) for r in self.rows.values()), 2)
            self.assertFalse((Path(directory) / 'lookup-control.json').exists())

    def test_capacity_uses_documented_millisecond_cache_buster(self):
        client = archive.Client('dummy', 'dummy')
        with patch.object(client, 'json', return_value={'available': 3}) as call, patch.object(archive.time, 'time', return_value=1234.5):
            self.assertEqual(client.capacity(), 2)
        call.assert_called_once_with(archive.API + '/status/user?_t=1234500', auth=True)

    def test_target_access_failure_does_not_masquerade_as_bad_credentials(self):
        client = archive.Client('dummy', 'dummy')
        opener = MagicMock()
        opener.open.side_effect = HTTPError(archive.API, 401, 'target access denied', {}, None)
        with patch.object(archive.request, 'build_opener', return_value=opener), patch.object(client, 'account', return_value={'available': 0}):
            with self.assertRaises(archive.ArchiveError) as result:
                client.submit(URL)
        self.assertFalse(result.exception.fatal)
        self.assertEqual(str(result.exception), 'target-http-401')

    def test_newer_negative_checkpoint_cannot_discard_a_verified_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / 'source', Path(directory) / 'destination'
            archive.save_records({URL: {**self.target, 'snapshot': snapshot(), 'checked_at': '2026-10-21T10:00:00Z'}}, {URL}, source)
            archive.save_records({URL: {**self.target, 'status': 'retry', 'checked_at': '2026-10-21T11:00:00Z'}}, {URL}, destination)
            with patch.object(sys, 'argv', ['archive_pocs', '--directory', str(destination), '--merge-from', str(source)]):
                archive.main()
            self.assertTrue(archive.valid_snapshot(archive.load_records(destination)[URL]))

    def test_lookup_cooldown_does_not_block_pinned_source_submissions(self):
        self.client.lookup_retry_after = archive.after(300)
        target = {**self.target, 'parent': URL + '/parent'}
        archive.process(URL, target, self.rows, self.client, capture=True)
        self.client.submit.assert_called_once()
        self.client.lookup.assert_not_called()

    def test_replay_redirect_to_another_original_is_not_a_snapshot_of_this_poc(self):
        snap = snapshot()
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.url = snap['url'].replace(snap['timestamp'] + '/', snap['timestamp'] + 'id_/') + '-other'
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(archive.request, 'build_opener', return_value=opener):
            self.assertFalse(archive.verify_snapshot(snap, URL))

    def test_looked_up_new_page_and_small_repositories_keep_capture_slots(self):
        targets = {f'file-{i}': {**self.target, 'parent': 'large'} for i in range(70)}
        targets['small'] = {**self.target, 'parent': 'small-repo'}
        targets[URL] = self.target
        targets['old'] = {**self.target, 'priority': ''}
        rows = {URL: {**self.target, 'checked_at': archive.now(), 'lookup_checked_at': archive.now()}}
        selected = archive.select_targets(targets, rows, capture=True)
        self.assertIn(URL, selected[:4])
        self.assertIn('small', selected[:4])

    def test_repeated_transport_errors_trip_a_service_breaker(self):
        client = archive.Client()
        for i in range(4):
            self.assertEqual(client.failure(str(i % 3), archive.ArchiveError('transport-ConnectionResetError')).cooldown, 0)
        self.assertEqual(client.failure('third', archive.ArchiveError('replay-URLError')).cooldown, 900)

    def test_availability_breaker_does_not_pause_capture_api(self):
        for operation in ('availability', 'replay'):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                self.client.operation = operation
                self.client.lookup.side_effect = archive.ArchiveError('service-transport-failures', cooldown=900)
                archive.lookup_pages({URL: self.target}, {}, self.client, Path(directory), 1, 10)
                self.assertTrue((Path(directory) / 'lookup-control.json').exists())
                self.assertEqual((Path(directory) / 'control.json').exists(), operation == 'replay')

    def test_capture_limit_exits_without_waiting_for_an_unrelated_host_cooldown(self):
        blocked = 'https://example.com/poc'
        targets = {u: {**self.target, 'original': u} for u in (URL, URL + '-other', blocked)}
        def process(key, target, rows, client, *, capture):
            rows[key] = {**target, 'status': 'not-found'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            archive.save_records({blocked: {**targets[blocked], 'host_retry_after': archive.after(86400)}}, {blocked}, path)
            with patch.object(archive, 'inventory', return_value=targets), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive.Client, 'capacity', return_value=2), \
                    patch.object(archive, 'process', side_effect=process) as visit, \
                    patch.object(archive.time, 'sleep', side_effect=AssertionError('Unexpected idle wait')), \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', str(path), '--limit', '1']):
                self.assertEqual(archive.main(), 0)
                self.assertEqual(visit.call_count, 1)

    def test_capture_loop_serves_new_targets_and_keeps_candidate_backoff(self):
        pending = URL + '-pending'
        target = {**self.target, 'original': pending}
        visited = []
        def process(key, target, rows, client, *, capture):
            visited.append(key)
            if key == pending:
                rows[key]['next_check_at'] = archive.after(3600)
                raise archive.ArchiveError('replay-URLError')
            rows[key] = {**target, 'status': 'not-found'}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            archive.save_records({pending: {**target, 'candidate': snapshot(pending), 'next_check_at': ''}}, {pending}, path)
            with patch.object(archive, 'inventory', return_value={URL: self.target, pending: target}), \
                    patch.object(archive, 'credentials', return_value=('dummy', 'dummy')), \
                    patch.object(archive.Client, 'capacity', return_value=2), \
                    patch.object(archive, 'process', side_effect=process), \
                    patch.object(sys, 'argv', ['archive_pocs', '--capture', '--directory', str(path), '--limit', '1', '--max-seconds', '2']):
                self.assertEqual(archive.main(), 0)
            saved = archive.load_records(path)[pending]
        self.assertEqual(visited, [URL, pending])
        self.assertGreater(saved['next_check_at'], archive.after(3500))

    def test_shared_file_is_published_under_each_allowed_parent(self):
        raw = 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/poc.py'
        other = URL + '/blob/main/poc.py'
        rows = {raw: {'original': raw, 'snapshot': snapshot(raw), 'parent': URL,
                      'parents': {URL: URL, other: other}}}
        published = archive.published_snapshots(rows, allowed={URL, other})
        self.assertEqual(published[URL]['files'], published[other]['files'])

    def test_replay_rejects_login_shells_errors_and_external_redirects(self):
        snap = snapshot()
        response = MagicMock()
        response.__enter__.return_value = response
        response.status = 200
        response.url = snap['url'].replace(snap['timestamp'] + '/', snap['timestamp'] + 'id_/')
        response.headers = {'Content-Type': 'text/html'}
        opener = MagicMock()
        opener.open.return_value = response
        with patch.object(archive.request, 'build_opener', return_value=opener):
            for body in (b'', b'<title>404 Not Found</title>', b'<title>Sign in to GitHub</title>'):
                response.read.return_value = body
                self.assertFalse(archive.verify_snapshot(copy.deepcopy(snap), URL))
                self.assertFalse(archive.verify_snapshot(copy.deepcopy(snap), 'https://raw.githubusercontent.com/owner/poc/' + 'a' * 40 + '/poc.py'))
            response.read.return_value = b'<title>PoC for CVE-2026-4044</title><article>research</article>'
            self.assertTrue(archive.verify_snapshot(snap, URL))
            self.assertFalse(archive.verify_snapshot(snap, 'https://hackerone.com/reports/1234'))
        redirect = archive.ReplayRedirect()
        self.assertIsNone(redirect.redirect_request(None, None, 302, '', {}, 'http://127.0.0.1/private'))
        self.assertIsNone(archive.NoRedirect().redirect_request(None, None, 302, '', {}, 'https://archive.org/'))

    def test_gzip_replay_is_decoded_before_content_and_hash_validation(self):
        response = io.BytesIO(gzip.compress(b'<title>Sign in to GitHub</title>'))
        response.headers = {'Content-Encoding': 'gzip'}
        self.assertEqual(archive.response_bytes(response, 1000), b'<title>Sign in to GitHub</title>')
        response = io.BytesIO(gzip.compress(b'x' * 1001))
        response.headers = {'Content-Encoding': 'gzip'}
        with self.assertRaisesRegex(archive.ArchiveError, 'too-large'):
            archive.response_bytes(response, 1000)

    def test_corrupt_compressed_responses_are_target_errors(self):
        for body in (b'not-gzip', gzip.compress(b'poc')[:-8], b'\x1f\x8b\x08\x00' + b'\x00' * 6 + b'\x07'):
            with self.subTest(body=body):
                response = io.BytesIO(body)
                response.headers = {'Content-Encoding': 'gzip'}
                with self.assertRaisesRegex(archive.ArchiveError, 'invalid-compressed-response'):
                    archive.response_bytes(response, 1000)


if __name__ == '__main__':
    unittest.main()
