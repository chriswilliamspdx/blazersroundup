import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from retry import next_retry_at_for_attempt, transcript_retry_due  # noqa: E402


class RetryTests(unittest.TestCase):
    def test_exponential_retry_schedule(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)

        self.assertEqual(next_retry_at_for_attempt(now, 1, 60, 5), now + timedelta(minutes=60))
        self.assertEqual(next_retry_at_for_attempt(now, 3, 60, 5), now + timedelta(minutes=240))
        self.assertIsNone(next_retry_at_for_attempt(now, 5, 60, 5))

    def test_retry_due_logic(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)

        self.assertTrue(transcript_retry_due(None, 5, now))
        self.assertFalse(
            transcript_retry_due(
                {"attempt_count": 1, "next_retry_at": now + timedelta(minutes=1)},
                5,
                now,
            )
        )
        self.assertTrue(
            transcript_retry_due(
                {"attempt_count": 1, "next_retry_at": now - timedelta(minutes=1)},
                5,
                now,
            )
        )
        self.assertFalse(
            transcript_retry_due(
                {"attempt_count": 5, "next_retry_at": None},
                5,
                now,
            )
        )


if __name__ == "__main__":
    unittest.main()
