from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import build_site
import sync_repo_metadata as metadata
from update_cves import GitHubClient


class RepositoryMetadataTests(unittest.TestCase):
    def setUp(self):
        health = patch('link_health.load', return_value={'repositories': {}, 'urls': {}})
        health.start()
        self.addCleanup(health.stop)

    def test_priority_covers_missing_curated_and_frontpage_repositories(self):
        entries = [{"poc": ["https://github.com/owner/older", "https://github.com/owner/front"],
                    "collections": ["https://github.com/collection/new/blob/main/poc.py"],
                    "nuclei": ["https://github.com/vendor/templates/blob/main/check.yaml"]}]
        stored = {"owner/older": [1, ""], "owner/front": [0, ""], "vendor/templates": [100, ""]}
        selected, cursor = metadata.scope(entries, stored, [{"url": "https://github.com/owner/front"}],
                                          "owner/front", 1)
        self.assertEqual(selected, ["collection/new", "owner/front", "owner/older"])
        self.assertEqual(cursor, "owner/older")

    def test_partial_failure_keeps_zero_and_alias_keys_without_inventing_counts(self):
        public = {"nameWithOwner": "renamed/new", "isPrivate": False, "visibility": "PUBLIC",
                  "stargazerCount": 0, "pushedAt": "2026-10-21T09:00:00Z"}
        payload = {"data": {"r0": public, "r1": None, "r2": None,
                            "r3": {**public, "stargazerCount": None},
                            "r4": {**public, "visibility": "PRIVATE"}},
                   "errors": [{"type": "NOT_FOUND", "path": ["r1"]},
                              {"type": "INTERNAL", "path": ["r2"]}]}
        with patch.object(metadata, "http_json", return_value=payload):
            readings, unavailable, failed = metadata.survey(
                ["owner/old", "owner/deleted", "owner/failed", "owner/partial", "owner/private"], GitHubClient("test"))
        self.assertEqual(readings, {"owner/old": [0, "2026-10-21"]})
        self.assertEqual(unavailable, {"owner/deleted", "owner/private"})
        self.assertEqual(failed, {"owner/failed", "owner/partial"})

    def test_rest_observations_fill_the_same_cache_used_by_search(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "metadata.json"
            target.write_text('{"existing/poc":[50,"2026-01-01"]}')
            with patch.object(metadata, "METADATA", target):
                metadata.remember([
                    {"html_url": "https://github.com/Owner/New/blob/main/poc.py", "stargazers_count": 0,
                     "pushed_at": "2026-10-21T09:00:00Z"},
                    {"html_url": "https://github.com/owner/unknown", "stargazers_count": None},
                    {"html_url": "https://github.com/owner/private", "stargazers_count": 100, "private": True},
                ])
            self.assertEqual(json.loads(target.read_text()),
                             {"existing/poc": [50, "2026-01-01"], "owner/new": [0, "2026-10-21"]})

    def test_site_keeps_metadata_for_every_published_source_field(self):
        entries = [{field: [f"https://github.com/owner/{field}/blob/main/poc.txt"]
                    for field in ["poc", *(field for _, field in build_site.CURATED)]}]
        stored = {f"owner/{field}": [0, "2026-10-21"] for field in entries[0]}
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "metadata.json"
            target.write_text(json.dumps(stored | {"unlinked/repo": [50, ""]}))
            with patch.object(build_site, "REPO_META", target):
                self.assertEqual(build_site.build_repo_meta(entries), stored)

    def test_invalid_repository_cache_cannot_silently_erase_all_columns(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "metadata.json"
            for content in ('{', '[]', '{"owner/poc":[null,"2026-10-21"]}'):
                target.write_text(content)
                with self.subTest(content=content), patch.object(build_site, "REPO_META", target):
                    with self.assertRaises(ValueError):
                        build_site.build_repo_meta([])

    def test_refresh_failure_keeps_cached_values_and_advances_rotation(self):
        entries = [{"poc": ["https://github.com/owner/a", "https://github.com/owner/b"]}]
        with tempfile.TemporaryDirectory() as directory:
            cache, state = Path(directory) / 'metadata.json', Path(directory) / 'state.json'
            cache.write_text(json.dumps({'owner/a': [7, '2026-10-20'], 'owner/b': [1, '2026-10-20']}))
            with patch.multiple(metadata, METADATA=cache, STATE=state), \
                    patch.multiple(build_site, build_cve_list=lambda blocked: (entries, 1),
                                   build_trending=lambda blocked: [], build_landed=lambda *args: []), \
                    patch.object(metadata, 'survey', return_value=({}, set(), {'owner/a'})), \
                    patch.dict(metadata.os.environ, {'GITHUB_TOKEN': 'test'}), \
                    patch.object(sys, 'argv', ['sync_repo_metadata', '--limit', '1', '--references', '0']), \
                    patch('audit_poc_links.prune_unavailable'):
                self.assertEqual(metadata.main(), 1)
            saved = json.loads(state.read_text())
            self.assertEqual(saved['cursor'], 'owner/a')
            self.assertIn('owner/a', saved['retries'])
            self.assertEqual(json.loads(cache.read_text())['owner/a'][0], 7)
            selected, cursor = metadata.scope(entries, {}, [], saved['cursor'], 1, {'owner/a'})
            self.assertEqual((selected, cursor), (['owner/b'], 'owner/b'))

    def test_offline_validation_does_not_depend_on_epss_or_write_outputs(self):
        with patch.multiple(build_site, build_cve_list=lambda blocked: ([], 0),
                            build_repo_meta=lambda entries: {}, build_kev=lambda entries: {},
                            build_nuclei=lambda entries: {}, build_metadata=lambda entries: {},
                            build_trending=lambda blocked: []), \
                patch.object(build_site, 'build_epss', side_effect=RuntimeError('EPSS outage')) as epss, \
                patch.object(build_site, 'write_json') as write, \
                patch.object(sys, 'argv', ['build_site', '--offline']):
            self.assertEqual(build_site.main(), 0)
            epss.assert_not_called()
            write.assert_not_called()


if __name__ == "__main__":
    unittest.main()
