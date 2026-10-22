from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import archive_sources as sources

REVISION = 'a' * 40
CVE = 'CVE-2026-1234'
URL = 'https://github.com/owner/poc'
BODY = b"import requests\nresponse = requests.post('http://example.invalid/', data={'payload': 'test'})\n"


def entry(path, body=BODY):
    return {'path': path, 'type': 'blob', 'mode': '100644', 'size': len(body),
            'sha': hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()}


class Client:
    def __init__(self, tree, body=BODY):
        self.entries, self.body, self.urls = tree, body, []

    def json(self, url):
        self.urls.append(url)
        return {'tree': self.entries, 'truncated': False} if '/git/trees/' in url else {'sha': REVISION}

    def read(self, url):
        self.urls.append(url)
        return self.body


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.target = {'original': URL, 'cves': [CVE]}
        p = patch.object(sources.source_artifacts, 'load_reviews', return_value=[])
        p.start()
        self.addCleanup(p.stop)

    def test_partial_scan_resumes_without_replacing_verified_files(self):
        client = Client([entry('poc.py'), entry('exploit.py')])
        first = sources.inspect(self.target, {}, client, file_limit=1)
        self.assertFalse(first['complete'])
        self.assertEqual(len(first['files']), 1)
        client.urls.clear()
        second = sources.inspect(self.target, first, client, file_limit=1)
        self.assertTrue(second['complete'])
        self.assertEqual(len(second['files']), 2)
        raw = [url for url in client.urls if 'raw.githubusercontent.com' in url]
        self.assertEqual(len(raw), 1)
        self.assertIn('/' + REVISION + '/', raw[0])

    def test_explicit_nuclei_file_is_preserved_and_siblings_are_not(self):
        body = b'id: CVE-2026-1234\nhttp:\n  - method: GET\n    path: ["{{BaseURL}}/poc"]\n'
        target = {**self.target, 'original': URL + '/blob/main/http/CVE-2026-1234.yaml'}
        client = Client([entry('http/CVE-2026-1234.yaml', body), entry('other.yaml', body)], body)
        result = sources.inspect(target, {}, client)
        self.assertEqual([r['path'] for r in result['files']], ['http/CVE-2026-1234.yaml'])

    def test_wrong_source_bytes_never_enter_capture_queue(self):
        result = sources.inspect(self.target, {}, Client([entry('poc.py')], b'Not Found'))
        self.assertEqual(result['files'], [])
        self.assertEqual(result['error'], 'source-hash-mismatch')
        self.assertFalse(result['complete'])

    def test_poc_covering_two_published_cves_is_not_rejected_by_its_filename(self):
        target = {**self.target, 'cves': [CVE, 'CVE-2026-5678']}
        result = sources.inspect(target, {}, Client([entry('CVE-2026-1234-CVE-2026-5678.py')]))
        self.assertEqual(result['files'][0]['cves'], target['cves'])

    def test_named_file_does_not_inherit_its_sibling_cve(self):
        target = {**self.target, 'cves': [CVE, 'CVE-2026-5678']}
        result = sources.inspect(target, {}, Client([entry('CVE-2026-1234.py')]))
        self.assertEqual(result['files'][0]['cves'], [CVE])

    def test_issues_do_not_archive_unrelated_repository_code(self):
        self.assertTrue(sources.repository_source(URL))
        self.assertTrue(sources.repository_source(URL + '/blob/main/poc.py'))
        self.assertFalse(sources.repository_source(URL + '/issues/1'))
        self.assertFalse(sources.repository_source(URL + '/pull/2'))

    def test_scan_rejects_placeholders_and_ignores_vendored_code(self):
        client = Client([entry('poc.py'), entry('node_modules/poc.py')], b'pass\n')
        client.entries[0] = entry('poc.py', b'pass\n')
        result = sources.inspect(self.target, {}, client)
        self.assertEqual(result['files'], [])
        self.assertEqual(result['candidate_files'], 1)
        self.assertTrue(result['complete'])


if __name__ == '__main__':
    unittest.main()
