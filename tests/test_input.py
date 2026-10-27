import json
import tempfile
import unittest
from pathlib import Path

from ghsa_repro.config import load_config
from ghsa_repro.input import load_input, validate_input_record

ROOT = Path(__file__).resolve().parents[1]


class InputTests(unittest.TestCase):
    def test_example_and_config_are_valid(self):
        records = load_input(ROOT / "examples/input.jsonl")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["severity"], "critical")
        config = load_config(ROOT / "config.example.json")
        self.assertEqual(config.provider.model, "glm-5.3")
        self.assertEqual(config.provider.api_key_env, "GLM_API_KEY_SECLAB")
        self.assertNotIn("api_key", config.public_dict()["provider"])

    def test_legacy_csv_is_normalized_with_explicit_assumption(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "input.csv"
            source.write_text(
                "ghsa_id,cve,published,package,summary,cvss_vector\n"
                "GHSA-abcd-1234-efgh,CVE-2022-1234,2023-01-02T03:04:05Z,npm:demo,Example,CVSS:3.1/test\n",
                encoding="utf-8",
            )
            records = load_input(source, assumed_severity="critical")
        self.assertEqual(records[0]["cve_id"], "CVE-2022-1234")
        self.assertEqual(records[0]["packages"][0]["ecosystem"], "npm")
        self.assertEqual(records[0]["packages"][0]["name"], "demo")

    def test_duplicates_and_unknown_fields_fail_closed(self):
        value = json.loads((ROOT / "examples/input.jsonl").read_text())
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            validate_input_record({**value, "unexpected": True})
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "input.jsonl"
            source.write_text(json.dumps(value) + "\n" + json.dumps(value) + "\n")
            with self.assertRaisesRegex(ValueError, "duplicate GHSA"):
                load_input(source)


if __name__ == "__main__":
    unittest.main()
