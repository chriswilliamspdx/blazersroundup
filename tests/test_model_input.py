import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from text_utils import build_model_input  # noqa: E402


class ModelInputTests(unittest.TestCase):
    def test_includes_title_and_keyword_context(self):
        text = build_model_input(
            mode="blazers",
            title="Blazers Media Day",
            video_id="abc123",
            direct_keyword_hit=False,
            transcript_text="Opening banter before the basketball talk.",
        )

        self.assertIn("Feed type: blazers", text)
        self.assertIn("Episode title: Blazers Media Day", text)
        self.assertIn("YouTube video ID: abc123", text)
        self.assertIn("Direct keyword hit in transcript: no", text)
        self.assertIn("Opening banter", text)


if __name__ == "__main__":
    unittest.main()
