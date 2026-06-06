import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from news_scanner import (  # noqa: E402
    canonicalize_url,
    google_news_rss_url,
    is_google_related_domain,
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

    def test_broad_match_rejects_generic_portland(self):
        self.assertFalse(strong_broad_match("Portland traffic update", "Portland"))

    def test_broad_match_accepts_team_phrase(self):
        self.assertTrue(strong_broad_match("Portland Trail Blazers injury update", "Portland"))


if __name__ == "__main__":
    unittest.main()
