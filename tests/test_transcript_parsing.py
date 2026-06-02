import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from transcript_providers import (  # noqa: E402
    _candidate_proxy_tokens,
    _proxy_from_raw_list_token,
    cookiefile_from_env,
    parse_json3_to_segments,
    parse_vtt_to_segments,
)


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

    def test_cookiefile_from_env_writes_private_cookie_text(self):
        import os

        original_path = os.environ.pop("YTDLP_COOKIES", None)
        original_text = os.environ.get("YTDLP_COOKIES_TEXT")
        original_b64 = os.environ.pop("YTDLP_COOKIES_B64", None)
        try:
            os.environ["YTDLP_COOKIES_TEXT"] = "# Netscape HTTP Cookie File\n.youtube.com\tTRUE\t/\tTRUE\t0\tSID\tfake"

            cookie_path = cookiefile_from_env()

            self.assertEqual(Path(cookie_path).name, "ytdlp-cookies.txt")
            self.assertTrue(Path(cookie_path).exists())
            self.assertIn("Netscape HTTP Cookie File", Path(cookie_path).read_text(encoding="utf-8"))
        finally:
            if original_path is not None:
                os.environ["YTDLP_COOKIES"] = original_path
            else:
                os.environ.pop("YTDLP_COOKIES", None)
            if original_text is not None:
                os.environ["YTDLP_COOKIES_TEXT"] = original_text
            else:
                os.environ.pop("YTDLP_COOKIES_TEXT", None)
            if original_b64 is not None:
                os.environ["YTDLP_COOKIES_B64"] = original_b64
            else:
                os.environ.pop("YTDLP_COOKIES_B64", None)

    def test_raw_proxy_tokens_are_split_from_public_lists(self):
        body = """# comments are ignored
http://1.2.3.4:8080 5.6.7.8:3128
https://proxy.example.com:443, socks5://9.9.9.9:1080 garbage
"""

        self.assertEqual(
            _candidate_proxy_tokens(body),
            [
                "http://1.2.3.4:8080",
                "5.6.7.8:3128",
                "https://proxy.example.com:443",
                "socks5://9.9.9.9:1080",
                "garbage",
            ],
        )

    def test_raw_proxy_parser_keeps_supported_http_proxies(self):
        self.assertEqual(_proxy_from_raw_list_token("1.2.3.4:8080"), "http://1.2.3.4:8080")
        self.assertEqual(_proxy_from_raw_list_token("https://proxy.example.com:443"), "https://proxy.example.com:443")
        self.assertIsNone(_proxy_from_raw_list_token("socks5://9.9.9.9:1080"))
        self.assertIsNone(_proxy_from_raw_list_token("not-a-proxy"))
        self.assertIsNone(_proxy_from_raw_list_token("1.2.3.4:99999"))


if __name__ == "__main__":
    unittest.main()
