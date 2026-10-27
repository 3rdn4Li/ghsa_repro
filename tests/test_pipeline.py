import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ghsa_repro.config import load_config
from ghsa_repro.pipeline import (
    codex_command,
    initialize_run,
    load_run,
    render_prompt,
    summarize,
)
from ghsa_repro.records import validate_record

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40


class PipelineTests(unittest.TestCase):
    def test_provider_command_respects_output_schema_capability(self):
        config = load_config(ROOT / "config.example.json")
        command = codex_command(
            config,
            "/usr/bin/codex",
            Path("/run/target"),
            Path("/run/output.json"),
            Path("/run/schema.json"),
            "safe prompt",
            "http://127.0.0.1:12345",
        )
        self.assertNotIn("--output-schema", command)
        self.assertNotIn("secret-value", " ".join(command))
        responses = replace(
            config,
            provider=replace(
                config.provider, wire_api="responses", supports_output_schema=True
            ),
        )
        command = codex_command(
            responses,
            "/usr/bin/codex",
            Path("/run/target"),
            Path("/run/output.json"),
            Path("/run/schema.json"),
            "safe prompt",
            "https://example.test/v1",
        )
        self.assertIn("--output-schema", command)

    def test_initialize_is_immutable_and_resumable(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = Path(temporary) / "runs" / "2023-critical"
            result = initialize_run(
                ROOT / "examples/input.jsonl", ROOT / "config.example.json", run
            )
            self.assertEqual(result["targets"], 1)
            paths, config, manifest = load_run(run)
            self.assertEqual(len(manifest), 1)
            self.assertEqual(paths.manifest.stat().st_mode & 0o777, 0o444)
            self.assertNotIn("secret", paths.config.read_text().lower())
            self.assertEqual(summarize(paths, config)["completed"], 0)
            with self.assertRaises(FileExistsError):
                initialize_run(
                    ROOT / "examples/input.jsonl", ROOT / "config.example.json", run
                )

    def test_prompt_is_year_agnostic(self):
        item = {
            "target_id": "GHSA-abcd-1234-efgh",
            "cve_id": "CVE-2022-1234",
            "published_at": "2023-01-02T00:00:00Z",
            "severity": "critical",
            "packages": [],
            "summary": "Example",
            "cvss_vector": None,
            "advisory_year_month": "2023-01",
        }
        prompt = render_prompt(item, 2)
        self.assertIn("GHSA-abcd-1234-efgh", prompt)
        self.assertIn("attempts/02/record.json", prompt)
        self.assertNotIn("ghsa-2024-critical.csv", prompt)
        self.assertNotRegex(prompt, r"\{\{[A-Z0-9_]+\}\}")

    def test_record_and_artifact_contract(self):
        item = {"target_id": "GHSA-abcd-1234-efgh", "advisory_year_month": "2023-01"}
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / item["target_id"]
            attempt = target / "attempts/01"
            for relative in (
                "artifacts/README.md",
                "artifacts/prepare-env.sh",
                "artifacts/run-poc.sh",
                "artifacts/observations.json",
                "artifacts/logs/poc.stdout.log",
                "artifacts/logs/poc.stderr.log",
                "report.md",
            ):
                path = attempt / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("test\n")
            record = {
                "schema_version": 1,
                "target_id": item["target_id"],
                "source": "GHSA",
                "repository": "https://github.com/example/project",
                "recorded_vulnerable_commit": None,
                "proposed_fixed_commit": None,
                "original_exclusion_reason": None,
                "rejected_candidates": [],
                "advisory_year_month": "2023-01",
                "audited_at": "2026-01-01T00:00:00Z",
                "current_default": {
                    "ref": "refs/heads/main",
                    "commit": SHA,
                    "resolved_at": "2026-01-01T00:00:00Z",
                },
                "maintained_branches_examined": [],
                "reported_root_cause": "root cause",
                "attacker_boundary": "remote input",
                "current_status": "fixed_current_default",
                "proof_level": "executable",
                "equivalent_paths_checked": ["primary path"],
                "reproduction": {
                    "environment_preparation_commands": [],
                    "commands": ["test"],
                    "observations": ["fixed"],
                    "old_poc_result": "not applicable",
                    "current_equivalent_path_result": "not reachable",
                },
                "current_source_evidence": [
                    {
                        "url": "https://github.com/example/project/blob/a/file",
                        "commit": SHA,
                        "path": "file",
                        "lines": "1-2",
                        "finding": "fixed",
                    }
                ],
                "complete_fix_outside_recorded_descendant_history": False,
                "earliest_complete_current_fix": None,
                "artifact_root": "attempts/01/artifacts",
                "reasoning": "evidence supports fix",
            }
            self.assertEqual(validate_record(record, item, attempt), [])
            record["current_source_evidence"][0]["commit"] = "b" * 40
            self.assertIn(
                "source evidence must bind to the current-default commit",
                validate_record(record, item, attempt),
            )


if __name__ == "__main__":
    unittest.main()
