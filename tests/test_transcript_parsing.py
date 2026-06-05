import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from transcript_providers import (  # noqa: E402
    PROXY_HEALTH_CACHE,
    TranscriptError,
    TranscriptSettings,
    _candidate_proxy_tokens,
    _next_usable_proxy,
    _ordered_proxy_factories,
    _pick_caption_track,
    _proxy_from_raw_list_token,
    _record_proxy_failure,
    _record_proxy_success,
    cookiefile_from_env,
    fetch_transcript,
    parse_json3_to_segments,
    parse_vtt_to_segments,
    settings_from_env,
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

    def test_pick_caption_track_accepts_english_auto_caption_variant(self):
        info = {
            "subtitles": {},
            "automatic_captions": {
                "en-orig": [{"ext": "vtt", "url": "https://example.com/en-orig.vtt"}],
            },
        }

        self.assertEqual(_pick_caption_track(info), ("https://example.com/en-orig.vtt", "vtt"))

    def test_pick_caption_track_falls_back_to_auto_caption_for_same_language(self):
        info = {
            "subtitles": {
                "en": [{"ext": "srv1", "url": "https://example.com/en.srv1"}],
            },
            "automatic_captions": {
                "en": [{"ext": "json3", "url": "https://example.com/en.json3"}],
            },
        }

        self.assertEqual(_pick_caption_track(info), ("https://example.com/en.json3", "json3"))

    def test_pick_caption_track_reports_available_caption_keys(self):
        info = {
            "subtitles": {"fr": [{"ext": "vtt", "url": "https://example.com/fr.vtt"}]},
            "automatic_captions": {"es": [{"ext": "vtt", "url": "https://example.com/es.vtt"}]},
        }

        with self.assertRaises(TranscriptError) as ctx:
            _pick_caption_track(info)

        self.assertEqual(ctx.exception.error_type, "NoCaptionTrack")
        self.assertIn("subtitles=fr", str(ctx.exception))
        self.assertIn("automatic_captions=es", str(ctx.exception))

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

    def test_unhealthy_proxy_is_skipped_until_success_clears_it(self):
        PROXY_HEALTH_CACHE.clear()
        settings = TranscriptSettings(
            proxy_bad_cooldown_seconds=60,
            proxy_blocked_cooldown_seconds=3600,
            proxy_selection_attempts=3,
        )
        bad_proxy = "http://1.2.3.4:8080"
        good_proxy = "http://5.6.7.8:3128"
        proxies = [bad_proxy, good_proxy]
        calls = {"index": -1}

        def next_proxy():
            calls["index"] = (calls["index"] + 1) % len(proxies)
            return proxies[calls["index"]]

        _record_proxy_failure(bad_proxy, "IpBlocked", settings)

        self.assertEqual(_next_usable_proxy("test", next_proxy, settings), good_proxy)

        _record_proxy_success(bad_proxy)

        self.assertEqual(_next_usable_proxy("test", next_proxy, settings), bad_proxy)

    def test_persistent_proxy_memory_skips_unavailable_proxy(self):
        class Memory:
            def proxy_available(self, proxy_url):
                return proxy_url != "http://1.2.3.4:8080"

        settings = TranscriptSettings(proxy_selection_attempts=3)
        proxies = ["http://1.2.3.4:8080", "http://5.6.7.8:3128"]
        calls = {"index": -1}

        def next_proxy():
            calls["index"] = (calls["index"] + 1) % len(proxies)
            return proxies[calls["index"]]

        self.assertEqual(
            _next_usable_proxy("test", next_proxy, settings, proxy_memory=Memory()),
            "http://5.6.7.8:3128",
        )

    def test_proxy_strategy_prefers_good_pool_most_of_the_time(self):
        settings = TranscriptSettings(proxy_good_first_ratio=0.8, proxy_good_attempts=1)
        fresh = [("proxylist", lambda: "http://fresh.example:8080", 2)]

        with patch("transcript_providers.random.random", return_value=0.1):
            plan = _ordered_proxy_factories(lambda: "http://good.example:8080", fresh, settings)

        self.assertEqual([source for source, _next_proxy, _attempts in plan], ["reputation", "proxylist"])

    def test_proxy_strategy_sometimes_tests_fresh_sources_first(self):
        settings = TranscriptSettings(proxy_good_first_ratio=0.8, proxy_good_attempts=1)
        fresh = [("proxylist", lambda: "http://fresh.example:8080", 2)]

        with patch("transcript_providers.random.random", return_value=0.95):
            plan = _ordered_proxy_factories(lambda: "http://good.example:8080", fresh, settings)

        self.assertEqual([source for source, _next_proxy, _attempts in plan], ["proxylist", "reputation"])

    def test_cookie_backed_proxy_ytdlp_retries_are_suppressed(self):
        logs = []
        settings = TranscriptSettings(
            proxy_enabled=True,
            proxy_sources=["proxylist"],
            proxy_attempts=1,
            proxy_ytdlp_enabled=True,
            proxy_ytdlp_attempts=1,
            ytdlp_cookies="cookies.txt",
            proxy_selection_attempts=1,
        )

        with patch(
            "transcript_providers.fetch_with_youtube_transcript_api",
            side_effect=TranscriptError("blocked", "RequestBlocked", transient=True),
        ), patch(
            "transcript_providers.fetch_with_ytdlp",
            side_effect=TranscriptError("blocked", "HTTPError", transient=True),
        ) as ytdlp, patch(
            "transcript_providers._raw_proxy_list_factory",
            return_value=lambda: "http://1.2.3.4:8080",
        ):
            with self.assertRaises(TranscriptError):
                fetch_transcript("video01", settings, log=lambda *parts: logs.append(" ".join(str(part) for part in parts)))

        self.assertEqual(ytdlp.call_count, 1)
        self.assertIn("skip proxy yt-dlp retries because cookies are configured", logs)

    def test_ytdlp_proxy_retries_default_to_disabled(self):
        import os

        original = os.environ.pop("TRANSCRIPT_PROXY_YTDLP_ENABLED", None)
        try:
            self.assertFalse(settings_from_env().proxy_ytdlp_enabled)
        finally:
            if original is not None:
                os.environ["TRANSCRIPT_PROXY_YTDLP_ENABLED"] = original


if __name__ == "__main__":
    unittest.main()
