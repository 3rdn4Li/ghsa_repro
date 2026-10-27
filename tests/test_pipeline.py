import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from ghsa_repro.config import load_config
from ghsa_repro.pipeline import (
    _publish_record,
    codex_command,
    initialize_run,
    load_run,
    render_prompt,
    summarize,
)
from ghsa_repro.records import validate_record
from ghsa_repro.storage import RunPaths

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

        chatgpt = load_config(ROOT / "config.daybreak.example.json")
        command = codex_command(
            chatgpt,
            "/usr/bin/codex",
            Path("/run/target"),
            Path("/run/output.json"),
            Path("/run/schema.json"),
            "safe prompt",
            None,
        )
        joined = " ".join(command)
        self.assertIn('model_provider="openai"', joined)
        self.assertNotIn("model_providers.openai.base_url", joined)
        self.assertNotIn("env_key", joined)

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
        prompt = render_prompt(item, 2, ["glm53", "daybreak"])
        self.assertIn("GHSA-abcd-1234-efgh", prompt)
        self.assertIn("attempts/02/record.json", prompt)
        self.assertNotIn("ghsa-2024-critical.csv", prompt)
        self.assertIn("archived-inputs/prior-audits", prompt)
        self.assertIn("impact-reassessment", prompt)
        self.assertNotRegex(prompt, r"\{\{[A-Z0-9_]+\}\}")

    def test_record_and_artifact_contract(self):
        item = {
            "target_id": "GHSA-abcd-1234-efgh",
            "advisory_year_month": "2023-01",
            "severity": "critical",
        }
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
                "schema_version": 2,
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
                "reported_severity": "critical",
                "reported_impact": "remote code execution",
                "current_severity": "none",
                "current_impact": "reported sink is not reachable",
                "impact_equivalence": "not_reached",
                "attacker_prerequisite_change": "unchanged",
                "risk_change": "not_reachable",
                "risk_comparison": "the original remote impact is no longer reachable",
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
            record["current_impact"] = "not reachable; sk-examplecredential0123456789"
            paths = RunPaths(Path(temporary) / "publication-run")
            _publish_record(paths, record)
            publication = paths.published_records / f"{item['target_id']}.json"
            self.assertEqual(publication.stat().st_mode & 0o777, 0o644)
            self.assertNotIn("sk-examplecredential", publication.read_text())
            self.assertNotIn("reproduction", json.loads(publication.read_text()))
            record["current_source_evidence"][0]["commit"] = "b" * 40
            self.assertIn(
                "source evidence must bind to the current-default commit",
                validate_record(record, item, attempt),
            )

    def test_reachable_status_cannot_hide_risk_downgrade(self):
        item = {
            "target_id": "GHSA-abcd-1234-efgh",
            "advisory_year_month": "2023-01",
            "severity": "critical",
        }
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / item["target_id"]
            attempt = target / "attempts/01"
            for relative in (
                "artifacts/README.md",
                "artifacts/prepare-env.sh",
                "artifacts/run-poc.sh",
                "artifacts/observations.json",
                "report.md",
            ):
                path = attempt / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("test\n")
            record = {
                "schema_version": 2,
                "target_id": item["target_id"],
                "source": "GHSA",
                "repository": "https://github.com/example/project",
                "recorded_vulnerable_commit": None,
                "proposed_fixed_commit": None,
                "original_exclusion_reason": None,
                "rejected_candidates": [],
                "advisory_year_month": "2023-01",
                "audited_at": "2026-01-01T00:00:00Z",
                "current_default": {"ref": "refs/heads/main", "commit": SHA, "resolved_at": "2026-01-01T00:00:00Z"},
                "maintained_branches_examined": [],
                "reported_root_cause": "object injection",
                "attacker_boundary": "untrusted deserialization",
                "reported_severity": "critical",
                "reported_impact": "remote code execution",
                "current_severity": "high",
                "current_impact": "attacker-selected class instantiation followed by a fatal error",
                "impact_equivalence": "reduced",
                "attacker_prerequisite_change": "unchanged",
                "risk_change": "downgraded",
                "risk_comparison": "the historical command-execution suffix no longer completes",
                "current_status": "partially_fixed_but_same_vulnerability_reachable",
                "proof_level": "static_strong",
                "equivalent_paths_checked": ["historical command suffix"],
                "reproduction": {
                    "environment_preparation_commands": [],
                    "commands": [],
                    "observations": [],
                    "old_poc_result": "blocked before command execution",
                    "current_equivalent_path_result": "class instantiation only",
                },
                "current_source_evidence": [{"url": "https://github.com/example/project/blob/a/file", "commit": SHA, "path": "file", "lines": "1-2", "finding": "residual gadget"}],
                "complete_fix_outside_recorded_descendant_history": None,
                "earliest_complete_current_fix": None,
                "artifact_root": "attempts/01/artifacts",
                "reasoning": "impact is reduced",
            }
            errors = validate_record(record, item, attempt)
            self.assertIn(
                "reachable status requires the reported impact or greater", errors
            )
            self.assertIn(
                "reachable status requires unchanged_or_higher risk", errors
            )
            record["current_status"] = "risk_downgraded_current_default"
            self.assertEqual(validate_record(record, item, attempt), [])

    def test_reassessment_freezes_prior_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            temporary = Path(temporary)
            prior = temporary / "prior"
            prior.mkdir()
            prior.joinpath("GHSA-xxxx-yyyy-zzzz.json").write_text(
                '{"target_id":"GHSA-xxxx-yyyy-zzzz","model":"old",'
                '"note":"sk-examplecredential0123456789"}\n'
            )
            run = temporary / "runs" / "reassessment"
            initialize_run(
                ROOT / "examples/input.jsonl",
                ROOT / "config.example.json",
                run,
                selected_targets=["GHSA-xxxx-yyyy-zzzz"],
                prior_record_sets={"old-model": prior},
                run_kind="impact_reassessment",
            )
            frozen = run / "prior-records/old-model/GHSA-xxxx-yyyy-zzzz.json"
            self.assertTrue(frozen.is_file())
            self.assertEqual(frozen.stat().st_mode & 0o777, 0o444)
            self.assertNotIn("sk-examplecredential", frozen.read_text())
            metadata = json.loads((run / "input-metadata.json").read_text())
            self.assertEqual(metadata["prior_record_sets"][0]["redactions"], 1)


if __name__ == "__main__":
    unittest.main()
