import json
import unittest
from unittest.mock import patch

from ghsa_repro.github import collect_advisories, collect_published_year


class Response:
    def __init__(self, value, link=None):
        self.value = value
        self.headers = {"Link": link} if link else {}

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return json.dumps(self.value).encode()


class GithubTests(unittest.TestCase):
    def test_explicit_collection_preserves_order_and_deduplicates(self):
        def fetch(ghsa_id, token_env):
            self.assertEqual(token_env, "TEST_TOKEN")
            return {
                "ghsa_id": ghsa_id,
                "cve_id": None,
                "published_at": "2026-01-01T00:00:00Z",
                "severity": "critical",
                "summary": ghsa_id,
                "html_url": f"https://github.com/advisories/{ghsa_id}",
                "cvss": {},
                "withdrawn_at": None,
                "vulnerabilities": [],
            }, None

        ids = ["GHSA-abcd-1234-efgh", "GHSA-1111-2222-3333"]
        with patch("ghsa_repro.github.fetch_advisory", side_effect=fetch):
            records = collect_advisories(ids + ids[:1], token_env="TEST_TOKEN")
        self.assertEqual([record["ghsa_id"] for record in records], ids)

    def test_explicit_collection_fails_atomically_on_fetch_error(self):
        with patch(
            "ghsa_repro.github.fetch_advisory",
            return_value=(None, "GitHub Advisory API returned HTTP 404"),
        ), self.assertRaisesRegex(RuntimeError, "GHSA-abcd-1234-efgh"):
            collect_advisories(["GHSA-abcd-1234-efgh"])

    def test_collection_paginates_and_excludes_withdrawn(self):
        pages = [
            Response(
                [
                    {
                        "ghsa_id": "GHSA-abcd-1234-efgh",
                        "cve_id": "CVE-2023-1234",
                        "published_at": "2023-02-01T00:00:00Z",
                        "severity": "critical",
                        "summary": "Example",
                        "html_url": "https://github.com/advisories/GHSA-abcd-1234-efgh",
                        "cvss": {"vector_string": "CVSS:3.1/test"},
                        "withdrawn_at": None,
                        "vulnerabilities": [
                            {
                                "package": {"ecosystem": "pip", "name": "demo"},
                                "vulnerable_version_range": "< 2",
                                "first_patched_version": "2",
                            }
                        ],
                    }
                ],
                '<https://api.github.test/page2>; rel="next"',
            ),
            Response(
                [
                    {
                        "ghsa_id": "GHSA-1111-2222-3333",
                        "cve_id": None,
                        "published_at": "2023-03-01T00:00:00Z",
                        "severity": "critical",
                        "summary": "Withdrawn",
                        "html_url": None,
                        "cvss": {},
                        "withdrawn_at": "2023-04-01T00:00:00Z",
                        "vulnerabilities": [],
                    }
                ]
            ),
        ]
        seen = []

        def opener(request, timeout):
            seen.append((request.full_url, timeout, request.headers))
            return pages.pop(0)

        records = collect_published_year(2023, "critical", opener=opener)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["packages"][0]["name"], "demo")
        self.assertEqual(len(seen), 2)
        self.assertIn("published=2023-01-01..2023-12-31", seen[0][0])


if __name__ == "__main__":
    unittest.main()
