import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from ghsa_repro.sequence import run_sequence


class SequenceTests(unittest.TestCase):
    @patch("ghsa_repro.sequence.summarize")
    @patch("ghsa_repro.sequence.load_run")
    @patch("ghsa_repro.sequence.AuditPipeline")
    def test_stops_before_next_run_when_current_is_incomplete(
        self, pipeline_class, load_run, summarize
    ):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first, second = root / "first", root / "second"
            first.mkdir()
            second.mkdir()
            paths, config = Mock(), Mock()
            config.codex.default_jobs = 48
            config.codex.timeout_seconds = 7200
            load_run.return_value = (paths, config, [{"target_id": "GHSA-abcd-1234-efgh"}])
            summarize.return_value = {"completed": 0, "remaining": 1}
            pipeline_class.return_value.run.return_value = {
                "finished_at": "2026-01-01T00:00:00Z",
                "summary": {"completed": 0, "remaining": 1, "failures": 1},
            }
            result = run_sequence([first, second], root / "sequence.json", jobs=48)
            self.assertEqual(result["status"], "stopped_incomplete")
            self.assertEqual(result["current_run"], str(first.resolve()))
            self.assertEqual(load_run.call_count, 1)
            pipeline_class.return_value.run.assert_called_once_with(
                jobs=48, timeout_seconds=7200, target_ids=[]
            )

    def test_rejects_duplicate_runs(self):
        with tempfile.TemporaryDirectory() as temporary:
            run = Path(temporary)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                run_sequence([run, run], run / "state.json")


if __name__ == "__main__":
    unittest.main()
