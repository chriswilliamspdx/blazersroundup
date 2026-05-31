import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from transcript_providers import parse_json3_to_segments, parse_vtt_to_segments  # noqa: E402


class TranscriptParsingTests(unittest.TestCase):
    def test_parse_json3_to_segments(self):
        body = json.dumps(
            {
                "events": [
                    {
                        "tStartMs": 1234,
                        "dDurationMs": 2500,
                        "segs": [{"utf8": "Deni "}, {"utf8": "Avdija"}],
                    },
                    {"tStartMs": 4000, "segs": [{"utf8": "\n"}]},
                ]
            }
        )

        segments = parse_json3_to_segments(body)

        self.assertEqual(segments, [(1.234, 2.5, "Deni Avdija")])

    def test_parse_vtt_to_segments(self):
        body = """WEBVTT

00:00:05.000 --> 00:00:07.500
Trail Blazers segment starts

2
00:00:08.000 --> 00:00:10.000
<c>Scoot Henderson</c> update
"""

        segments = parse_vtt_to_segments(body)

        self.assertEqual(
            segments,
            [
                (5.0, 2.5, "Trail Blazers segment starts"),
                (8.0, 2.0, "Scoot Henderson update"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
