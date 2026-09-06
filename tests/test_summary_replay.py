import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location("replay_summaries", Path(__file__).resolve().parents[1] / "tools/replay_summaries.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ReplayTests(unittest.TestCase):
    def test_actual_handler_uses_only_cached_transcript_and_captured_posts(self):
        text = "The Trail Blazers episode discusses John Morant's passing."
        cached = {"full_text": text, "segments": [(0, 4, text)], "provider": "cached",
                  "title": "Trail Blazers passing", "show_name": "Test show"}
        for mode in ("blazers", "national", "high_volume"):
            with self.subTest(mode=mode):
                model = Mock()
                model.summarize_json.return_value = {"is_blazers": True, "summary": text}
                model.fact_check_summary_json.return_value = {
                    "summary": "The episode discusses Ja Morant's passing.", "fact_check_passed": True,
                    "blazers_context_confirmed": True, "current_status_claims": False,
                    "entity_ids": ["ja_morant"], "source_evidence_ids": ["E002"],
                }
                with patch.object(runner.worker, "Database", side_effect=AssertionError("No production database")), patch(
                    "requests.sessions.Session.request", side_effect=AssertionError("No external requests"),
                ):
                    result = runner.replay(
                        {"id": "test", "video_id": "video123456", "mode": mode}, cached,
                        {"keywords_positive": ["trail blazers"]}, model,
                    )
                self.assertEqual(result["validation_reason"], "")
                self.assertEqual(len(result["captured_posts"]), 1)
                self.assertEqual(result["captured_posts"][0]["summary"], "The episode discusses Ja Morant's passing.")
                model.summarize_json.assert_called_once()
                model.fact_check_summary_json.assert_called_once()

    def test_national_keyword_gate_still_runs_before_gemini(self):
        model = Mock()
        result = runner.replay(
            {"id": "test", "video_id": "video123456", "mode": "national"},
            {"full_text": "Soccer discussion.", "segments": [(0, 3, "Soccer discussion.")],
             "provider": "cached", "title": "Soccer", "show_name": "Test"},
            {"keywords_positive": ["trail blazers"]}, model,
        )
        self.assertEqual(result["validation_reason"], "review_not_reached")
        self.assertEqual(result["captured_posts"], [])
        model.summarize_json.assert_not_called()
