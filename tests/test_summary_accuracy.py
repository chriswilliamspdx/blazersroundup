import sys
import unittest
from datetime import date
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "worker"))
import main
from summary_accuracy import (
    canonicalize_summary_proper_names, reference_context, reference_is_fresh, validate_review,
)


SOURCE = "The Trail Blazers episode with Mike Richmond and Sean Hiken discusses John Morant's passing."
FINAL = "The episode discusses Ja Morant's passing with Mike Richman and Sean Highkin."


def review(**changes):
    result = {
        "summary": FINAL,
        "fact_check_passed": True,
        "blazers_context_confirmed": True,
        "current_status_claims": False,
        "entity_ids": ["ja_morant", "mike_richman", "sean_highkin"],
        "source_evidence": [SOURCE],
        "corrections": "Corrected names.",
    }
    result.update(changes)
    return result


def settings():
    return SimpleNamespace(
        summary_post_char_limit=250, debug=False, llm_max_calls_per_poll=10,
        llm_max_attempts=3, transcript_max_attempts=3, force_transcript_retry=False,
        dry_run=False,
    )


class SummaryAccuracyTests(unittest.TestCase):
    def test_reported_names_corrected_in_source_context(self):
        self.assertEqual(
            canonicalize_summary_proper_names(SOURCE, mode="national"),
            "The Trail Blazers episode with Mike Richman and Sean Highkin discusses Ja Morant's passing.",
        )
        self.assertEqual(validate_review(review(), SOURCE), (FINAL, ""))

    def test_unrelated_names_and_coach_mori_are_not_guessed(self):
        for text in (
            "John Morant and Mike Richmond open a gallery.",
            "A soccer interview with head coach Mori.",
            "Portland artist Robert Williams discusses his paintings.",
        ):
            with self.subTest(text=text):
                self.assertEqual(canonicalize_summary_proper_names(text), text)
        artist = "The Blazers podcast mentions artist Robert Williams and his paintings."
        self.assertEqual(canonicalize_summary_proper_names(artist, mode="blazers"), artist)

    def test_canonical_name_is_idempotent_and_word_bounded(self):
        text = "Trail Blazers center Robert Williams III discusses defense."
        once = canonicalize_summary_proper_names(text)
        self.assertEqual(once, text)
        self.assertEqual(canonicalize_summary_proper_names(once), once)
        self.assertEqual(
            canonicalize_summary_proper_names("John Moranton talks basketball."),
            "John Moranton talks basketball.",
        )

    def test_draft_cannot_create_identity_evidence(self):
        result = review(summary="The episode discusses Ja Morant's passing.", entity_ids=["ja_morant"])
        source = "The Trail Blazers episode discusses passing and defense."
        result["source_evidence"] = [source]
        self.assertEqual(validate_review(result, source)[1], "unsupported_entity")

    def test_failed_missing_and_malformed_verdicts_fall_back(self):
        for verdict in (False, None, "true", 1):
            with self.subTest(verdict=verdict):
                self.assertEqual(validate_review(review(fact_check_passed=verdict), SOURCE)[1], "review_not_passed")
        self.assertEqual(validate_review([], SOURCE)[1], "review_not_passed")
        self.assertEqual(validate_review(review(blazers_context_confirmed=False), SOURCE)[1], "context_not_confirmed")
        self.assertEqual(validate_review(review(current_status_claims=True), SOURCE)[1], "current_status_claim")

    def test_evidence_must_come_from_original_source(self):
        self.assertEqual(
            validate_review(review(source_evidence=["Ja Morant is Portland's newest star."]), SOURCE)[1],
            "missing_source_evidence",
        )
        source = SOURCE + "\nDirect keyword hit in transcript: yes"
        self.assertEqual(
            validate_review(review(source_evidence=["Direct keyword hit in transcript: yes"]), source)[1],
            "missing_source_evidence",
        )

    def test_all_known_names_must_be_declared_and_unknown_names_removed(self):
        self.assertEqual(validate_review(review(entity_ids=[]), SOURCE)[1], "undeclared_entity")
        unknown = review(summary="The episode discusses Mike D'Antoni's contract.", entity_ids=[])
        self.assertEqual(validate_review(unknown, SOURCE)[1], "unresolved_proper_name")

    def test_length_is_validated_after_canonicalization(self):
        text = "The episode discusses John Morant and " + "defense " * 25 + "passing."
        result = review(summary=text, entity_ids=["ja_morant"])
        self.assertEqual(validate_review(result, SOURCE, limit=100)[1], "length_or_truncation")
        self.assertEqual(validate_review(review(summary=FINAL[:-1]), SOURCE)[1], "incomplete_sentence")
        self.assertEqual(validate_review(review(summary=FINAL[:-1] + "..."), SOURCE)[1], "length_or_truncation")

    def test_expired_roles_are_not_sent_as_current_facts(self):
        self.assertTrue(reference_is_fresh(date(2026, 9, 5)))
        self.assertFalse(reference_is_fresh(date(2026, 10, 5)))
        self.assertFalse(reference_is_fresh(date(2026, 8, 5)))
        fresh = reference_context(SOURCE, today=date(2026, 9, 5))
        expired = reference_context(SOURCE, today=date(2026, 10, 5))
        self.assertIn("Portland Trail Blazers player", fresh)
        self.assertNotIn("Portland Trail Blazers player", expired)
        self.assertIn("Roles have expired", expired)
        self.assertIn("Ja Morant", expired)

    def test_reviewer_failure_preserves_video_post_in_all_feed_modes(self):
        for mode in ("blazers", "national", "high_volume"):
            with self.subTest(mode=mode):
                db = Mock()
                db.already_seen.return_value = False
                db.llm_cooldown_active.return_value = None
                db.summary_retry_ready.return_value = True
                db.transcript_retry_ready.return_value = True
                summarizer = Mock()
                summarizer.summarize_json.return_value = {"is_blazers": True, "summary": FINAL}
                summarizer.fact_check_summary_json.return_value = review(fact_check_passed=False)
                transcript = SimpleNamespace(segments=[(12, 4, SOURCE)], full_text=SOURCE)
                entry = {"title": "Trail Blazers passing", "published": "2026-09-05T12:00:00Z"}
                poll = main.PollContext(llm_limit=10)
                with patch.object(main, "fetch_transcript", return_value=transcript), patch.object(
                    main, "create_thread", return_value=True,
                ) as post:
                    outcome = main.handle_video(
                        settings(), db, summarizer, {"keywords_positive": ["trail blazers"]},
                        None, poll, "feed", "Test show", mode, entry, "video01",
                    )
                self.assertEqual(outcome, main.VIDEO_OK)
                self.assertEqual(poll.llm_calls, 2)
                post.assert_called_once()
                self.assertEqual(post.call_args.args[2], main.safe_fallback_summary(mode, 250))
                self.assertIn("https://www.youtube.com/watch?v=video01", post.call_args.args[1])
                if mode != "blazers":
                    self.assertIn("&t=12s", post.call_args.args[1])
                db.mark_seen.assert_called_once()
                # Raw transcript evidence is preserved, spelling references are appended separately.
                draft_input = summarizer.summarize_json.call_args.args[1]
                self.assertIn("John Morant", draft_input)
                self.assertIn("ja_morant: Ja Morant", draft_input)

    def test_budget_exhaustion_does_not_add_a_review_call(self):
        summarizer = Mock()
        text = main.fact_checked_summary_text(
            settings(), Mock(), summarizer, {}, main.PollContext(llm_limit=0),
            "video01", "national", SOURCE, FINAL,
        )
        self.assertEqual(text, main.safe_fallback_summary("national", 250))
        summarizer.fact_check_summary_json.assert_not_called()

    def test_valid_repaired_summary_is_used_in_every_feed_mode(self):
        for mode in ("blazers", "national", "high_volume"):
            with self.subTest(mode=mode):
                summarizer = Mock()
                summarizer.fact_check_summary_json.return_value = review()
                text = main.fact_checked_summary_text(
                    settings(), Mock(), summarizer, {}, main.PollContext(llm_limit=2),
                    "video01", mode, SOURCE, "The episode features John Morant.",
                )
                self.assertEqual(text, FINAL)
                summarizer.fact_check_summary_json.assert_called_once()

    def test_context_failure_does_not_assert_blazers_topic_in_reply(self):
        summarizer = Mock()
        summarizer.fact_check_summary_json.return_value = review(blazers_context_confirmed=False)
        text = main.fact_checked_summary_text(
            settings(), Mock(), summarizer, {}, main.PollContext(llm_limit=2),
            "video01", "national", SOURCE, FINAL,
        )
        self.assertEqual(text, "See the linked video for the full discussion.")


if __name__ == "__main__":
    unittest.main()
