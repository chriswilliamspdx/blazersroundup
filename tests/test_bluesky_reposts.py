import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from bluesky_reposts import (  # noqa: E402
    DEFAULT_JUNK_WORDS,
    build_search_queries,
    candidate_reason,
)


CONFIG = yaml.safe_load((ROOT / "config" / "feeds.youtube.yaml").read_text())


def post(
    text,
    likes=50,
    handle="fan.bsky.social",
    uri="at://did:plc:fan/app.bsky.feed.post/abc",
    reply=False,
    reply_shape="top",
):
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
        reply_data = {"root": {"uri": "at://root", "cid": "root"}, "parent": {"uri": "at://parent", "cid": "parent"}}
        if reply_shape in {"top", "both"}:
            data["reply"] = reply_data
        if reply_shape in {"record", "both"}:
            data["record"]["reply"] = reply_data
    return data


class BlueskyRepostTests(unittest.TestCase):
    def setUp(self):
        self.keywords = CONFIG["keywords_positive"]
        self.context_required_keywords = CONFIG["keywords_context_required"]

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

    def test_generic_blazers_game_context_is_blocked_with_or_without_reply_filtering(self):
        text = "(Oops: the OG Ballblazer was an Atari 8-bit game first, about 3 months before it hit C64, apologies to all fans of balls and blazers.)"
        for skip_replies in [True, False]:
            ok, reason = candidate_reason(
                post(text, likes=29, reply=True, reply_shape="record"),
                keywords=self.keywords,
                context_required_keywords=self.context_required_keywords,
                junk_words=DEFAULT_JUNK_WORDS,
                bot_handles=["blazersroundup.bsky.social"],
                min_likes=20,
                skip_replies=skip_replies,
            )
            self.assertFalse(ok)
            self.assertEqual(reason, "reply" if skip_replies else "not_blazers_context")

        ok, reason = candidate_reason(
            post(text, likes=29),
            keywords=self.keywords,
            context_required_keywords=self.context_required_keywords,
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=20,
            skip_replies=True,
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "not_blazers_context")

    def test_basketball_context_cues_are_token_bounded(self):
        for text in ["Blazers pinball game", "Blazers WNBA team"]:
            ok, reason = candidate_reason(
                post(text, likes=120),
                keywords=self.keywords,
                junk_words=DEFAULT_JUNK_WORDS,
                bot_handles=["blazersroundup.bsky.social"],
                min_likes=50,
                skip_replies=True,
            )
            self.assertFalse(ok)
            self.assertEqual(reason, "not_blazers_context")

    def test_nba_context_is_case_insensitive_and_token_bounded(self):
        ok, reason = candidate_reason(
            post("Blazers NBA update", likes=120),
            keywords=["blazers"],
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertTrue(ok)
        self.assertEqual(reason, "ready")

    def test_replies_are_detected_in_top_record_or_both_shapes(self):
        for reply_shape in ["top", "record", "both"]:
            for skip_replies in [True, False]:
                ok, reason = candidate_reason(
                    post("Blazers NBA update", likes=120, reply=True, reply_shape=reply_shape),
                    keywords=["blazers"],
                    junk_words=DEFAULT_JUNK_WORDS,
                    bot_handles=["blazersroundup.bsky.social"],
                    min_likes=50,
                    skip_replies=skip_replies,
                )
                self.assertEqual((ok, reason), (not skip_replies, "ready" if not skip_replies else "reply"))

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

    def test_context_required_owner_name_without_blazers_context_is_blocked(self):
        ok, reason = candidate_reason(
            post("Tom Dundon says the Hurricanes are ready for the playoffs.", likes=120),
            keywords=["Tom Dundon"],
            context_required_keywords=["Tom Dundon"],
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertFalse(ok)
        self.assertEqual(reason, "not_blazers_context")

    def test_context_required_owner_name_with_explicit_trail_blazers_context_is_ready(self):
        ok, reason = candidate_reason(
            post("Tom Dundon is watching the Trail Blazers rebuild.", likes=120),
            keywords=["Tom Dundon"],
            context_required_keywords=["Tom Dundon"],
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertTrue(ok)
        self.assertEqual(reason, "ready")

    def test_aliased_context_required_owner_name_without_blazers_context_is_blocked(self):
        ok, reason = candidate_reason(
            post("Thomas Dundon discusses the Hurricanes offseason.", likes=120),
            keywords=["Thomas Dundon"],
            context_required_keywords=["Tom Dundon", "Thomas Dundon"],
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertFalse(ok)
        self.assertEqual(reason, "not_blazers_context")

    def test_context_required_robert_williams_artist_without_blazers_context_is_blocked(self):
        ok, reason = candidate_reason(
            post("Robert Williams opens a new art exhibit this weekend.", likes=120),
            keywords=["Robert Williams"],
            context_required_keywords=["Robert Williams"],
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertFalse(ok)
        self.assertEqual(reason, "not_blazers_context")

    def test_current_player_keyword_keeps_existing_behavior(self):
        ok, reason = candidate_reason(
            post("Shaedon Sharpe is ready for the Blazers season.", likes=120),
            keywords=["Shaedon Sharpe"],
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertTrue(ok)
        self.assertEqual(reason, "ready")

    def test_context_required_keywords_are_backward_compatible_when_omitted(self):
        ok, reason = candidate_reason(
            post("Tom Dundon is discussed in a basketball trade thread.", likes=120),
            keywords=["Tom Dundon", "basketball"],
            junk_words=DEFAULT_JUNK_WORDS,
            bot_handles=["blazersroundup.bsky.social"],
            min_likes=50,
            skip_replies=True,
        )

        self.assertTrue(ok)
        self.assertEqual(reason, "ready")

    def test_search_queries_use_keywords_but_skip_generic_portland(self):
        queries = build_search_queries(
            {"keywords_positive": ["portland", "trail blazers", "shaedon sharpe"]},
            max_queries=10,
        )

        self.assertIn('"trail blazers"', queries)
        self.assertIn('"shaedon sharpe"', queries)
        self.assertNotIn("portland", queries)

    def test_search_queries_prioritize_canonical_search_keywords_under_cap(self):
        queries = build_search_queries(
            {
                "keywords_positive": ["shaydon sharp", "old alias", "cronin"],
                "keywords_search": ["Portland Trail Blazers", "Joe Cronin", "Joe Ingles"],
            },
            max_queries=7,
        )

        self.assertEqual(
            queries,
            [
                '"portland trail blazers"',
                '"trail blazers"',
                '"rip city"',
                "blazers",
                '"joe cronin"',
                '"joe ingles"',
            ],
        )
        self.assertNotIn('"old alias"', queries)

    def test_search_queries_keep_configured_override(self):
        queries = build_search_queries(
            {"keywords_search": ["Joe Cronin"]},
            max_queries=10,
            configured_queries=["custom phrase", "blazers", "custom phrase"],
        )

        self.assertEqual(queries, ['"custom phrase"', "blazers"])

    def test_search_queries_fall_back_to_aliases_for_old_or_empty_configs(self):
        old_config_queries = build_search_queries(
            {"keywords_positive": ["shaydon sharp", "portland"]},
            max_queries=10,
        )
        empty_canonical_queries = build_search_queries(
            {"keywords_search": [], "keywords_positive": ["shaydon sharp", "portland"]},
            max_queries=10,
        )

        self.assertIn('"shaydon sharp"', old_config_queries)
        self.assertEqual(empty_canonical_queries, old_config_queries)

    def test_search_queries_respect_max_queries(self):
        queries = build_search_queries(
            {"keywords_search": ["one", "two", "three"]},
            max_queries=2,
        )

        self.assertEqual(len(queries), 2)


if __name__ == "__main__":
    unittest.main()
