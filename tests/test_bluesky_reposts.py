import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from bluesky_reposts import (  # noqa: E402
    DEFAULT_JUNK_WORDS,
    build_search_queries,
    candidate_reason,
)


def post(text, likes=50, handle="fan.bsky.social", uri="at://did:plc:fan/app.bsky.feed.post/abc", reply=False):
    data = {
        "uri": uri,
        "cid": "bafyrei123",
        "author": {
            "did": "did:plc:fan",
            "handle": handle,
        },
        "record": {
            "text": text,
            "createdAt": "2026-06-06T12:00:00Z",
        },
        "indexedAt": "2026-06-06T12:01:00Z",
        "likeCount": likes,
        "repostCount": 1,
        "quoteCount": 0,
    }
    if reply:
        data["reply"] = {"root": {"uri": "at://root", "cid": "root"}, "parent": {"uri": "at://parent", "cid": "parent"}}
    return data


class BlueskyRepostTests(unittest.TestCase):
    def setUp(self):
        self.keywords = [
            "portland trail blazers",
            "shaedon sharpe",
            "shaydon sharp",
            "robert williams",
            "time lord",
            "blazers",
            "rip city",
        ]

    def test_ready_when_recent_post_has_keyword_and_threshold(self):
        ok, reason = candidate_reason(
            post("Shaedon Sharpe has the Blazers timeline looking fun.", likes=74),
            keywords=self.keywords,
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertTrue(ok)
        self.assertEqual(reason, "ready")

    def test_below_threshold_stays_candidate(self):
        ok, reason = candidate_reason(
            post("Rip City is talking about Shaydon Sharp tonight.", likes=49),
            keywords=self.keywords,
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertTrue(ok)
        self.assertEqual(reason, "below_threshold")

    def test_junk_posts_are_blocked(self):
        ok, reason = candidate_reason(
            post("Blazers parlay odds look tempting tonight.", likes=100),
            keywords=self.keywords,
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertFalse(ok)
        self.assertEqual(reason, "junk")

    def test_bot_posts_are_blocked(self):
        ok, reason = candidate_reason(
            post("Blazers news", likes=100, handle="blazersroundup.bsky.social"),
            keywords=self.keywords,
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["@blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertFalse(ok)
        self.assertEqual(reason, "self_post")

    def test_time_lord_without_basketball_context_is_blocked(self):
        ok, reason = candidate_reason(
            post("The Time Lord reveal in Doctor Who was tremendous.", likes=120),
            keywords=self.keywords,
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertFalse(ok)
        self.assertEqual(reason, "false_positive_context")

    def test_time_lord_with_robert_williams_context_is_ready(self):
        ok, reason = candidate_reason(
            post("Time Lord Robert Williams looks healthy for the Blazers.", likes=120),
            keywords=self.keywords,
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertTrue(ok)
        self.assertEqual(reason, "ready")

    def test_men_in_blazers_phrase_is_blocked(self):
        ok, reason = candidate_reason(
            post("New Men in Blazers episode is up after the Premier League weekend.", likes=120),
            keywords=self.keywords,
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertFalse(ok)
        self.assertEqual(reason, "false_positive_context")

    def test_men_in_blazers_handle_is_blocked(self):
        ok, reason = candidate_reason(
            post("Blazers are back with a new soccer roundup.", likes=120, handle="meninblazers.bsky.social"),
            keywords=self.keywords,
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertFalse(ok)
        self.assertEqual(reason, "false_positive_context")

    def test_search_queries_use_keywords_but_skip_generic_portland(self):
        queries = build_search_queries(
            {"keywords_positive": ["portland", "trail blazers", "shaedon sharpe"]},
            max_queries=10,
        )

        self.assertIn('"trail blazers"', queries)
        self.assertIn('"shaedon sharpe"', queries)
        self.assertNotIn("portland", queries)


if __name__ == "__main__":
    unittest.main()
