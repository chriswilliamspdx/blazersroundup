import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from main import (  # noqa: E402
    build_summary_fact_check_input,
    build_summary_fact_check_prompt,
    canonicalize_summary_proper_names,
    safe_fallback_summary,
    summary_fact_lines,
)


class SummaryFactCheckTests(unittest.TestCase):
    def test_prompt_treats_draft_as_untrusted_and_limits_summary(self):
        prompt = build_summary_fact_check_prompt(
            "Exclude generic trailblazer meanings.",
            summary_limit=250,
            facts=["Chauncey Billups is a former Portland Trail Blazers head coach."],
        )

        self.assertIn("Treat the draft summary as untrusted", prompt)
        self.assertIn("stale current-status claim", prompt)
        self.assertIn("current player, coach", prompt)
        self.assertIn("Chauncey Billups is a former Portland Trail Blazers head coach.", prompt)
        self.assertIn("summary (one complete sentence, <=220 characters", prompt)

    def test_fact_check_input_keeps_draft_separate_from_source_material(self):
        text = build_summary_fact_check_input(
            "Episode title: Coaching discussion\nTranscript: Mike D'Antoni was discussed as an old candidate.",
            "Mike D'Antoni is the Portland Trail Blazers head coach.",
        )

        self.assertIn("Draft summary:", text)
        self.assertIn("Source material:", text)
        self.assertIn("old candidate", text)

    def test_safe_fallback_summaries_are_short_and_source_grounded(self):
        national = safe_fallback_summary("national", 250)
        blazers = safe_fallback_summary("blazers", 250)

        self.assertLessEqual(len(national), 250)
        self.assertLessEqual(len(blazers), 250)
        self.assertIn("segment discusses", national)
        self.assertIn("episode discusses", blazers)

    def test_summary_fact_lines_normalizes_optional_config(self):
        facts = summary_fact_lines({"summary_fact_context": ["  One   fact.  ", "", "Two fact."]})

        self.assertEqual(facts, ["One fact.", "Two fact."])

    def test_canonicalizes_mori_in_coaching_context(self):
        text = "The episode notes questions about the team's direction and pressure on head coach Mori."

        self.assertEqual(
            canonicalize_summary_proper_names(text, mode="blazers"),
            "The episode notes questions about the team's direction and pressure on head coach Micah Nori.",
        )

    def test_does_not_canonicalize_standalone_mori_without_context(self):
        text = "The episode briefly mentions Mori in passing."

        self.assertEqual(canonicalize_summary_proper_names(text), text)

    def test_canonicalizes_high_confidence_name_variants(self):
        text = "Shaydon Sharp, Deni Avdia, Toumani Camera, and Donovan Clingen are discussed."

        self.assertEqual(
            canonicalize_summary_proper_names(text, mode="blazers"),
            "Shaedon Sharpe, Deni Avdija, Toumani Camara, and Donovan Clingan are discussed.",
        )


if __name__ == "__main__":
    unittest.main()
