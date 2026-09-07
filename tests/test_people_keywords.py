import json
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
CURRENT_PEOPLE = {
    "Jayson Kent", "Damian Lillard", "Scoot Henderson", "Blake Wesley", "Chris Youngblood", "Jrue Holiday",
    "Deni Avdija", "John Tonje", "Micah Potter", "Ja Morant", "Branden Carlson", "Yang Hansen",
    "Shaedon Sharpe", "Jeremy Sochan", "Donovan Clingan", "Vit Krejci", "Toumani Camara",
    "Robert Williams III", "Sidy Cissoko", "Micah Nori", "James Posey", "Quinton Crawford",
    "Ronnie Burrell", "Nate Bjorkgren", "Joe Cronin", "Andrae Patterson", "Sergi Oliva",
    "Dewayne Hankins", "Joe Loomis", "Galen Davies", "Tom Dundon", "Marc Zahr", "Stan Middleman",
    "Andrew Cherng", "Sheel Tyle", "Richard Chaifetz", "Marc Grandisson", "Jennifer Gates",
    "Nayel Nassar", "Taavet Hinrikus", "Dan Zilberman",
}
BRANDS = {"Portland Trail Blazers", "Trail Blazers", "Blazers", "Rip City", "Rip City Remix", "Moda Center"}
ROSTER = {"Jayson Kent", "Damian Lillard", "Scoot Henderson", "Blake Wesley", "Chris Youngblood", "Jrue Holiday", "Deni Avdija", "John Tonje", "Micah Potter", "Ja Morant", "Branden Carlson", "Yang Hansen", "Shaedon Sharpe", "Jeremy Sochan", "Donovan Clingan", "Vit Krejci", "Toumani Camara", "Robert Williams III", "Sidy Cissoko"}


def config(path):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


class PeopleKeywordTests(unittest.TestCase):
    def test_search_is_canonical_bounded_and_parity(self):
        a = config("config/feeds.yaml")["keywords_search"]
        b = config("config/feeds.youtube.yaml")["keywords_search"]
        self.assertEqual(a, b)
        self.assertLessEqual(len(a), 80)
        self.assertEqual(set(a), CURRENT_PEOPLE | BRANDS | {"Robert Williams"})
        self.assertEqual(len(a), len(set(a)))

    def test_search_has_no_aliases_or_removed_people(self):
        entities = json.loads((ROOT / "worker/summary_entities.json").read_text(encoding="utf-8"))["entities"]
        aliases = {alias.lower() for item in entities for alias in item["aliases"]}
        removed = {"caleb love", "jerami grant", "kris murray", "matisse thybulle", "rayan rupert", "duop reath", "mike schmitz", "jody allen"}
        search = {item.lower() for item in config("config/feeds.yaml")["keywords_search"]}
        aliases -= {item.lower() for item in CURRENT_PEOPLE}
        aliases -= {"robert williams", "rob williams", "robert william", "time lord"}
        self.assertFalse(search & aliases)
        self.assertFalse(search & removed)

    def test_current_aliases_positive_removed_terms_absent_and_lists_unique(self):
        entities = json.loads((ROOT / "worker/summary_entities.json").read_text(encoding="utf-8"))["entities"]
        aliases = {alias.lower() for item in entities if item["name"] in CURRENT_PEOPLE for alias in item["aliases"]}
        removed = {"caleb love", "jerami grant", "kris murray", "matisse thybulle", "rayan rupert", "duop reath", "mike schmitz", "jody allen"}
        for path in ("config/feeds.yaml", "config/feeds.youtube.yaml"):
            values = config(path)["keywords_positive"]
            lowered = {item.lower() for item in values}
            self.assertTrue(aliases <= lowered, path)
            self.assertFalse(lowered & removed, path)
            self.assertEqual(len(values), len(set(values)), path)
        news = config("config/news.yaml")
        self.assertFalse({item.lower() for item in news["keywords_positive"]} & removed)
        self.assertEqual(len(news["keywords_positive"]), len(set(news["keywords_positive"])))
        self.assertEqual(len(news["player_name_keywords"]), len(set(news["player_name_keywords"])))

    def test_context_contains_all_nonplayer_aliases_and_is_unique(self):
        entities = json.loads((ROOT / "worker/summary_entities.json").read_text(encoding="utf-8"))["entities"]
        expected = {value.lower() for item in entities if item["name"] in CURRENT_PEOPLE - ROSTER for value in (item["name"], *item["aliases"])}
        for path in ("config/feeds.yaml", "config/feeds.youtube.yaml"):
            values = config(path)["keywords_context_required"]
            self.assertTrue(expected <= {item.lower() for item in values}, path)
            self.assertEqual(len(values), len(set(values)), path)

    def test_feed_context_gate_has_all_nonplayer_current_people(self):
        expected = {"Micah Nori", "James Posey", "Quinton Crawford", "Ronnie Burrell", "Nate Bjorkgren", "Joe Cronin", "Andrae Patterson", "Sergi Oliva", "Dewayne Hankins", "Joe Loomis", "Galen Davies", "Tom Dundon", "Marc Zahr", "Stan Middleman", "Andrew Cherng", "Sheel Tyle", "Richard Chaifetz", "Marc Grandisson", "Jennifer Gates", "Nayel Nassar", "Taavet Hinrikus", "Dan Zilberman"}
        for path in ("config/feeds.yaml", "config/feeds.youtube.yaml"):
            self.assertTrue(expected <= set(config(path)["keywords_context_required"]), path)

    def test_news_people_gate_contains_positive_people_and_alias_forms(self):
        news = config("config/news.yaml")
        gate = set(news["player_name_keywords"])
        self.assertTrue(set(news["keywords_positive"]) - BRANDS - {"Portland"} <= gate)
        self.assertTrue({"Robert Williams", "Mika Nori", "Micah Nory", "Micha Nori"} <= gate)

    def test_feed_and_news_source_sections_remain_present(self):
        feeds = config("config/feeds.yaml")
        youtube = config("config/feeds.youtube.yaml")
        news = config("config/news.yaml")
        self.assertGreater(len(feeds["national_feeds"]), 0)
        self.assertGreater(len(feeds["blazers_feeds"]), 0)
        self.assertGreater(len(youtube["national_feeds"]), 0)
        self.assertIn("rss_feeds", news)
        self.assertIn("site_searches", news)


if __name__ == "__main__":
    unittest.main()
