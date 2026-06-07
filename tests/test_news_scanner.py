import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from news_scanner import (  # noqa: E402
    NewsSettings,
    build_candidate,
    canonicalize_url,
    google_news_rss_url,
    is_google_related_domain,
    is_non_article_url,
    site_search_query,
    strong_broad_match,
)


class NewsScannerTests(unittest.TestCase):
    def test_canonicalize_removes_tracking_params(self):
        url = canonicalize_url("https://Example.com/story/?utm_source=x&fbclid=abc&id=123#comments")
        self.assertEqual(url, "https://example.com/story?id=123")

    def test_google_news_search_adds_one_day_window(self):
        url = google_news_rss_url('"Portland Trail Blazers"')
        self.assertIn("news.google.com/rss/search", url)
        self.assertIn("Portland+Trail+Blazers", url)
        self.assertIn("when%3A1d", url)

    def test_site_search_uses_domain_and_path(self):
        self.assertEqual(
            site_search_query("https://www.oregonlive.com/blazers/"),
            "site:oregonlive.com/blazers when:1d",
        )

    def test_google_related_domains_are_not_article_sources(self):
        self.assertTrue(is_google_related_domain("ssl.gstatic.com"))
        self.assertTrue(is_google_related_domain("news.google.com"))
        self.assertFalse(is_google_related_domain("oregonlive.com"))

    def test_non_article_urls_are_rejected(self):
        self.assertTrue(is_non_article_url("https://www.google-analytics.com/analytics.js"))
        self.assertTrue(is_non_article_url("https://example.com/static/app.js"))
        self.assertFalse(is_non_article_url("https://www.kgw.com/article/sports/nba/blazers/story-id"))

    def test_broad_match_rejects_generic_portland(self):
        self.assertFalse(strong_broad_match("Portland traffic update", "Portland"))

    def test_broad_match_accepts_team_phrase(self):
        self.assertTrue(strong_broad_match("Portland Trail Blazers injury update", "Portland"))

    def test_source_name_does_not_create_keyword_match(self):
        settings = NewsSettings(
            enabled=True,
            dry_run=True,
            config_path="",
            interval_seconds=3600,
            lookback_hours=24,
            max_posts_per_poll=3,
            max_posts_per_day=8,
            max_entries_per_feed=25,
            max_google_resolves_per_scan=0,
            request_timeout_seconds=10,
            scan_pause_seconds=0,
            require_strong_match_for_broad=True,
            resolve_google_links=False,
            allow_unresolved_google_urls=False,
            web_base_url="https://example.test",
            internal_api_token="token",
        )
        entry = {
            "title": "Buy Tickets for Mariners vs. Tigers on June 7",
            "summary": "Baseball ticket information.",
            "published": "2026-06-06T12:00:00Z",
            "link": "https://ripcityradio.iheart.com/sports/baseball",
            "source": {"title": "Rip City Radio 620 Portland"},
        }
        spec = {"name": "Rip City Radio", "source_type": "site_search", "trust": "trusted"}
        config = {"keywords_positive": ["Rip City", "Portland Trail Blazers"], "junk_words": [], "blocked_sources": []}
        candidate, reason = build_candidate(entry, spec, config, settings, datetime(2026, 6, 5, tzinfo=timezone.utc), {})
        self.assertIsNone(candidate)
        self.assertEqual(reason, "no_keyword")

    def test_blocked_source_name_rejects_unresolved_google_item(self):
        settings = NewsSettings(
            enabled=True,
            dry_run=True,
            config_path="",
            interval_seconds=3600,
            lookback_hours=24,
            max_posts_per_poll=3,
            max_posts_per_day=8,
            max_entries_per_feed=25,
            max_google_resolves_per_scan=0,
            request_timeout_seconds=10,
            scan_pause_seconds=0,
            require_strong_match_for_broad=True,
            resolve_google_links=False,
            allow_unresolved_google_urls=False,
            web_base_url="https://example.test",
            internal_api_token="token",
        )
        entry = {
            "title": "Trail Blazers rumor roundup",
            "summary": "Portland Trail Blazers notes.",
            "published": "2026-06-06T12:00:00Z",
            "link": "https://news.google.com/rss/articles/test?oc=5",
            "source": {"title": "Rip City Project"},
        }
        spec = {"name": "keyword", "source_type": "keyword_search", "trust": "broad"}
        config = {
            "keywords_positive": ["Portland Trail Blazers"],
            "junk_words": [],
            "blocked_sources": [],
            "blocked_source_names": ["Rip City Project"],
        }
        candidate, reason = build_candidate(entry, spec, config, settings, datetime(2026, 6, 5, tzinfo=timezone.utc), {})
        self.assertIsNone(candidate)
        self.assertEqual(reason, "blocked_source_name")


if __name__ == "__main__":
    unittest.main()
