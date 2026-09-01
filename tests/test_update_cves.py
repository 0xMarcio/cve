from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import update_cves


class RepositoryClassificationTests(unittest.TestCase):
    def repo(self, name: str, description: str = "", readme: str = "") -> dict:
        return {
            "nameWithOwner": name,
            "url": f"https://github.com/{name}",
            "description": description,
            "isFork": False,
            "isArchived": False,
            "repositoryTopics": {"nodes": []},
            "readmeMd": {"text": readme},
        }

    def test_accepts_cve_named_repository(self) -> None:
        repo = self.repo(
            "AcmeSecurity/CVE-2026-31431-PoC",
            "Proof of concept for Linux privilege escalation",
            "CVE-2026-31431 proof of concept.",
        )
        self.assertEqual(
            update_cves.qualifying_repo_cves(repo, 2026, []),
            {"CVE-2026-31431"},
        )

    def test_rejects_generic_readme_reference(self) -> None:
        repo = self.repo(
            "AcmeSecurity/kernel-notes",
            "Linux security notes",
            "A linked exploit mentions CVE-2026-31431 as a proof of concept.",
        )
        repo["root"] = {"entries": [{"name": "index.js"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(repo, 2026, []), set())

    def test_accepts_readme_poc_with_repository_intent(self) -> None:
        repo = self.repo(
            "AcmeSecurity/kernel-exploits",
            "Linux exploit research",
            "Proof of concept for CVE-2026-31431 with reproduction steps.",
        )
        self.assertEqual(
            update_cves.qualifying_repo_cves(repo, 2026, []),
            {"CVE-2026-31431"},
        )

    def test_rejects_related_repository_links(self) -> None:
        repo = self.repo(
            "AcmeSecurity/CVE-2026-31431-PoC",
            "Proof of concept for CVE-2026-31431",
            "Related exploit: CVE-2026-41940 PoC https://github.com/AcmeSecurity/other",
        )
        self.assertEqual(
            update_cves.qualifying_repo_cves(repo, 2026, []),
            {"CVE-2026-31431"},
        )

    def test_accepts_multiple_pocs_implemented_in_one_repository(self) -> None:
        repo = self.repo(
            "AcmeSecurity/CVE-2026-31431-PoC",
            "Proof of concept for CVE-2026-31431",
            "This repository also includes a proof of concept for CVE-2026-41940.",
        )
        repo["root"] = {"entries": [{"name": "CVE-2026-41940.py"}]}
        self.assertEqual(
            update_cves.qualifying_repo_cves(repo, 2026, []),
            {"CVE-2026-31431", "CVE-2026-41940"},
        )

    def test_rejects_readme_reference_when_repository_names_another_cve(self) -> None:
        repo = self.repo(
            "AcmeSecurity/CVE-2026-20841-PoC",
            "Proof of concept for CVE-2026-20841",
            "The approach resembles the CVE-2016-0856 exploit.",
        )
        repo["repositoryTopics"] = {
            "nodes": [
                {"topic": {"name": "cve-2016-0856"}},
                {"topic": {"name": "cve-2026-20841"}},
            ]
        }
        repo["root"] = {"entries": [{"name": "PoC.md"}]}
        self.assertEqual(update_cves.qualifying_repo_cves(repo, 2016, []), set())
        self.assertEqual(
            update_cves.qualifying_repo_cves(repo, 2026, []),
            {"CVE-2026-20841"},
        )

    def test_rejects_profile_and_checker_repositories(self) -> None:
        profile = self.repo(
            "AcmeSecurity/AcmeSecurity",
            "Security engineer profile",
            "Proof of concept for CVE-2026-31431.",
        )
        checker = self.repo(
            "AcmeSecurity/CVE-2026-31431-checker",
            "Safe vulnerability checker",
            "Checks whether CVE-2026-31431 is present.",
        )
        self.assertEqual(update_cves.qualifying_repo_cves(profile, 2026, []), set())
        self.assertEqual(update_cves.qualifying_repo_cves(checker, 2026, []), set())

    def test_rejects_large_cve_collection(self) -> None:
        entries = "\n".join(
            f"Proof of concept for CVE-2026-{number:04d}"
            for number in range(1000, 1027)
        )
        repo = self.repo("AcmeSecurity/exploit-collection", "Exploit collection", entries)
        self.assertEqual(update_cves.qualifying_repo_cves(repo, 2026, []), set())

    def test_rejects_cve_corpora_and_datasets(self) -> None:
        corpus = self.repo(
            "AcmeSecurity/vulnerability-corpus",
            "Machine-readable PoC corpus",
            "CVE-2026-31431 proof-of-concept metadata.",
        )
        dataset = self.repo(
            "AcmeSecurity/exploit-dataset",
            "CVE exploit dataset",
            "CVE-2026-31431 proof-of-concept metadata.",
        )
        self.assertEqual(update_cves.qualifying_repo_cves(corpus, 2026, []), set())
        self.assertEqual(update_cves.qualifying_repo_cves(dataset, 2026, []), set())

    def test_rejects_poc_indexes_and_defensive_tools(self) -> None:
        index = self.repo(
            "AcmeSecurity/searchpoc",
            "Search for proof-of-concept links by CVE ID",
            "CVE-2026-31431 PoC: https://github.com/example/repository",
        )
        shield = self.repo(
            "AcmeSecurity/http-shield",
            "Blocks exploitation attempts",
            "Protects against CVE-2026-31431 exploit traffic.",
        )
        self.assertEqual(update_cves.qualifying_repo_cves(index, 2026, []), set())
        self.assertEqual(update_cves.qualifying_repo_cves(shield, 2026, []), set())

    def test_keeps_specific_cve_poc_scanner(self) -> None:
        repo = self.repo(
            "AcmeSecurity/CVE-2026-31431-PoC-Scanner",
            "Proof-of-concept scanner for CVE-2026-31431",
        )
        repo["root"] = {"entries": [{"name": "scan.py"}]}
        self.assertEqual(
            update_cves.qualifying_repo_cves(repo, 2026, []),
            {"CVE-2026-31431"},
        )

    def test_blacklist_matches_exact_owner_and_repository(self) -> None:
        blacklist = ["mirror-org/poc-corpus"]
        self.assertTrue(update_cves.is_blacklisted_repo("mirror-org/poc-corpus", blacklist))
        self.assertFalse(update_cves.is_blacklisted_repo("source-org/poc-corpus", blacklist))


class ReferenceAndMarkdownTests(unittest.TestCase):
    def record(self) -> dict:
        return {
            "cveMetadata": {"cveId": "CVE-2026-31431", "state": "PUBLISHED"},
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "Linux kernel vulnerability."}],
                    "affected": [
                        {
                            "product": "Linux",
                            "versions": [{"version": "4.14", "status": "affected"}],
                        }
                    ],
                    "problemTypes": [],
                    "references": [
                        {"url": "https://research.example/copy-fail", "tags": ["exploit"]},
                        {"url": "https://vendor.example/advisory", "tags": ["vendor-advisory"]},
                    ],
                },
                "adp": [
                    {
                        "references": [
                            {
                                "url": "https://database.example/CVE-2026-31431-exploit",
                                "tags": ["exploit"],
                            }
                        ]
                    }
                ],
            },
        }

    def test_uses_cna_and_adp_poc_references(self) -> None:
        self.assertEqual(
            update_cves.poc_references(self.record()),
            [
                "https://research.example/copy-fail",
                "https://database.example/CVE-2026-31431-exploit",
            ],
        )

    def test_excludes_blacklisted_github_references(self) -> None:
        record = self.record()
        record["containers"]["cna"]["references"].append(
            {"url": "https://github.com/AcmeSecurity/poc-index", "tags": ["exploit"]}
        )
        self.assertEqual(
            update_cves.poc_references(record, {"acmesecurity/poc-index"}),
            [
                "https://research.example/copy-fail",
                "https://database.example/CVE-2026-31431-exploit",
            ],
        )

    def test_preserves_markdown_layout(self) -> None:
        details = update_cves.details_from_record(self.record())
        self.assertIsNotNone(details)
        details.description = "Linux kernel vulnerability. \r\n\tAdditional context.\t"
        markdown = update_cves.build_markdown(
            "CVE-2026-31431",
            details,
            ["https://github.com/AcmeSecurity/CVE-2026-31431-PoC"],
            ["https://research.example/copy-fail"],
        )
        self.assertIn(
            "### [CVE-2026-31431](https://www.cve.org/CVERecord?id=CVE-2026-31431)",
            markdown,
        )
        self.assertIn(
            "### Description\n\nLinux kernel vulnerability.\n    Additional context.",
            markdown,
        )
        self.assertIn("#### Reference\n- https://research.example/copy-fail", markdown)
        self.assertIn(
            "#### Github\n- https://github.com/AcmeSecurity/CVE-2026-31431-PoC",
            markdown,
        )
        self.assertTrue(markdown.endswith("\n"))
        self.assertFalse(markdown.endswith("\n\n"))

    def test_existing_markdown_changes_only_poc_sections(self) -> None:
        original = """### [CVE-2026-31431](https://cve.mitre.org/)
![](existing-badge)

### Description

Keep this description unchanged.

### POC

#### Reference
No PoCs from references.

#### Github
No PoCs found on GitHub currently.

"""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "CVE-2026-31431.md"
            path.write_text(original, encoding="utf-8")
            changed = update_cves.update_existing_markdown(
                path,
                ["https://github.com/AcmeSecurity/CVE-2026-31431-PoC"],
                ["https://research.example/copy-fail"],
                dry_run=False,
            )
            updated = path.read_text(encoding="utf-8")
        self.assertTrue(changed)
        self.assertIn("![](existing-badge)", updated)
        self.assertIn("Keep this description unchanged.", updated)
        self.assertIn("#### Reference\n- https://research.example/copy-fail\n\n#### Github", updated)
        self.assertTrue(updated.endswith("\n\n"))


if __name__ == "__main__":
    unittest.main()
