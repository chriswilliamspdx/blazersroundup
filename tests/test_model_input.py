import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from text_utils import build_model_input  # noqa: E402
from main import youtube_api_item_to_entry, youtube_uploads_playlist_id  # noqa: E402


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

    def test_youtube_uploads_playlist_id(self):
        self.assertEqual(youtube_uploads_playlist_id("UCabc123"), "UUabc123")
        self.assertIsNone(youtube_uploads_playlist_id("PLabc123"))

    def test_youtube_api_item_to_entry(self):
        entry = youtube_api_item_to_entry(
            {
                "snippet": {
                    "title": "Latest Blazers episode",
                    "publishedAt": "2026-06-01T12:00:00Z",
                    "resourceId": {"videoId": "abc123"},
                },
                "contentDetails": {
                    "videoId": "abc123",
                    "videoPublishedAt": "2026-06-01T11:59:00Z",
                },
            }
        )

        self.assertEqual(entry["yt_videoid"], "abc123")
        self.assertEqual(entry["title"], "Latest Blazers episode")
        self.assertEqual(entry["published"], "2026-06-01T11:59:00Z")
        self.assertEqual(entry["link"], "https://www.youtube.com/watch?v=abc123")


if __name__ == "__main__":
    unittest.main()
