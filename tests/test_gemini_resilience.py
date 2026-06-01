import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from main import (  # noqa: E402
    _is_daily_quota_payload,
    _next_pacific_quota_reset,
    _retry_delay_seconds_from_payload,
    _thinking_config_for_model,
)


class GeminiResilienceTests(unittest.TestCase):
    def test_retry_delay_parses_fractional_seconds(self):
        payload = {"error": {"details": [{"retryDelay": "55.118534056s"}]}}

        self.assertEqual(_retry_delay_seconds_from_payload(payload), 55)

    def test_daily_quota_payload_detection(self):
        payload = {
            "error": {
                "message": "Quota exceeded",
                "details": [
                    {
                        "violations": [
                            {
                                "quotaId": "GenerateRequestsPerDayPerProjectPerModel-FreeTier",
                                "quotaMetric": "generativelanguage.googleapis.com/generate_content_free_tier_requests",
                            }
                        ]
                    }
                ],
            }
        }

        self.assertTrue(_is_daily_quota_payload(payload))

    def test_daily_quota_reset_uses_pacific_midnight(self):
        now = datetime(2026, 6, 1, 4, 30, tzinfo=timezone.utc)

        self.assertEqual(_next_pacific_quota_reset(now), datetime(2026, 6, 1, 7, 5, tzinfo=timezone.utc))

    def test_gemini_3_uses_thinking_level(self):
        config = _thinking_config_for_model("gemini-3.1-flash-lite", "low")

        self.assertEqual(getattr(config.thinking_level, "value", config.thinking_level), "LOW")
        self.assertIsNone(config.thinking_budget)

    def test_gemini_25_keeps_thinking_budget_disabled(self):
        config = _thinking_config_for_model("gemini-2.5-flash-lite", "low")

        self.assertEqual(config.thinking_budget, 0)
        self.assertIsNone(config.thinking_level)


if __name__ == "__main__":
    unittest.main()
