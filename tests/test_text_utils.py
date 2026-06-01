import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from text_utils import clamp_heading_with_link, clamp_text, first_keyword_hit, fmt_mmss, transcript_window, youtube_link  # noqa: E402


class TextUtilsTests(unittest.TestCase):
    def test_keyword_detection_and_timestamp_link(self):
        segments = [
            (10.7, 2.0, "Opening notes"),
            (65.2, 4.0, "A Portland Trail Blazers trade idea"),
        ]

        start, text = first_keyword_hit(segments, ["trail blazers", "rip city"])

        self.assertEqual(start, 65)
        self.assertEqual(text, "A Portland Trail Blazers trade idea")
        self.assertEqual(fmt_mmss(start), "01:05")
        self.assertEqual(fmt_mmss(3786), "01:03:06")
        self.assertEqual(
            youtube_link("abc123", start),
            "https://www.youtube.com/watch?v=abc123&t=65s",
        )

    def test_fuzzy_name_detection_handles_transcript_misspellings(self):
        segments = [
            (12.0, 2.0, "They talked about Shaydon Sharp attacking closeouts."),
            (30.0, 2.0, "No other Portland context."),
        ]

        start, text = first_keyword_hit(segments, ["shaedon sharpe"])

        self.assertEqual(start, 12)
        self.assertIn("Shaydon Sharp", text)

    def test_fuzzy_detection_does_not_apply_to_single_words(self):
        segments = [(40.0, 2.0, "The window glazers were mentioned.")]

        start, text = first_keyword_hit(segments, ["blazers"])

        self.assertIsNone(start)
        self.assertIsNone(text)

    def test_transcript_window(self):
        segments = [
            (0, 1, "before"),
            (30, 1, "start"),
            (90, 1, "middle"),
            (240, 1, "after"),
        ]

        self.assertEqual(transcript_window(segments, 30, window_seconds=100), "start middle")

    def test_clamp_text(self):
        self.assertEqual(clamp_text("  one   two  ", 300), "one two")
        self.assertEqual(clamp_text("one   two\n three   four", 300), "one two\nthree four")
        self.assertEqual(clamp_text("abcdef", 5), "ab...")

    def test_clamp_heading_with_link_preserves_link_line(self):
        text = clamp_heading_with_link("A" * 400, "01:03:06 https://example.com/watch?v=abc&t=3786s", 100)

        self.assertTrue(text.endswith("01:03:06 https://example.com/watch?v=abc&t=3786s"))
        self.assertLessEqual(len(text), 100)


if __name__ == "__main__":
    unittest.main()
