"""Source-bound names and final validation for podcast summaries only."""

import json
import re
import unicodedata
from datetime import date
from functools import lru_cache
from pathlib import Path


def normalized(text):
    text = unicodedata.normalize("NFKD", str(text or ""))
    text = "".join(c for c in text if not unicodedata.combining(c))
    return " ".join(re.findall(r"[a-z0-9]+", text.lower()))


def contains(text, phrase):
    return f" {normalized(phrase)} " in f" {normalized(text)} "


@lru_cache(maxsize=1)
def reference():
    return json.loads(Path(__file__).with_name("summary_entities.json").read_text(encoding="utf-8"))


def reference_is_fresh(today=None):
    data = reference()
    age = ((today or date.today()) - date.fromisoformat(data["verified_on"])).days
    return 0 <= age <= data["status_max_age_days"]


def supported_entities(source, mode="", show_name=""):
    team_context = mode == "blazers" or any(
        contains(source, phrase)
        for phrase in ("portland trail blazers", "trail blazers", "rip city", "nba", "basketball")
    )
    supported = []
    for entity in reference()["entities"]:
        forms = [entity["name"], *entity["aliases"]]
        found = [form for form in forms if contains(source, form)]
        # A surname alone is resolved only with an explicit coaching reference.
        if entity["id"] == "micah_nori" and team_context:
            if contains(source, "coach mori"):
                found.append("Mori")
        if not found:
            continue
        media_context = (
            entity["id"] == "mike_richman" and contains(source + " " + show_name, "locked on blazers")
        ) or (
            entity["id"] == "sean_highkin" and contains(source + " " + show_name, "rose garden report")
        )
        if not (team_context or media_context):
            continue
        if entity["id"] == "robert_williams":
            art_context = any(
                any(contains(sentence, form) for form in found)
                and any(contains(sentence, word) for word in ("artist", "painter", "sculptor", "paintings", "artwork"))
                for sentence in re.split(r"[.!?\n]", source)
            )
            if art_context:
                continue
        supported.append({**entity, "observed_forms": found})
    return supported


def canonicalize_summary_proper_names(text, source_text=None, mode="", show_name=""):
    source = text if source_text is None else source_text
    result = str(text or "")
    replacements = []
    for entity in supported_entities(source, mode, show_name):
        for form in [entity["name"], *entity["observed_forms"]]:
            replacements.append((form, entity["name"]))
    # One substitution pass prevents cascading aliases or an extra "III" suffix.
    mapping = {form.lower(): name for form, name in replacements}
    if not mapping:
        return result
    pattern = r"(?<!\w)(?:" + "|".join(re.escape(f) for f in sorted(mapping, key=len, reverse=True)) + r")(?!\w)"
    return re.sub(pattern, lambda m: mapping[m.group().lower()], result, flags=re.IGNORECASE)


def reference_context(source, mode="", show_name="", today=None):
    rows = supported_entities(source, mode, show_name)
    data = reference()
    fresh = reference_is_fresh(today)
    lines = [
        "Spelling references identify people already mentioned in the source; they are not episode evidence.",
        f"Reference snapshot: {data['verified_on']}. Role status fresh: {str(fresh).lower()}.",
        "Never infer an episode topic from a reference entry. Historical discussion keeps its historical tense.",
    ]
    if not fresh:
        lines.append("Roles have expired. Use names only; omit current affiliations and current-status claims.")
    for row in rows:
        role = row["role"] if fresh else "role unavailable (expired)"
        lines.append(
            f"{row['id']}: {row['name']}; observed: {', '.join(row['observed_forms'])}; "
            f"role as of snapshot: {role}."
        )
    return "\n".join(lines)


def validate_review(review, source, mode="", show_name="", limit=250):
    """Return a supported final summary or a reason to use the neutral fallback."""
    if not isinstance(review, dict) or review.get("fact_check_passed") is not True:
        return "", "review_not_passed"
    if review.get("blazers_context_confirmed") is not True:
        return "", "context_not_confirmed"
    if review.get("current_status_claims") is not False:
        # Current claims require information newer than a static reference snapshot.
        return "", "current_status_claim"
    text = review.get("summary")
    if not isinstance(text, str) or not text.strip():
        return "", "empty_summary"
    text = " ".join(text.split())
    evidence = review.get("source_evidence")
    evidence_source = re.sub(
        r"(?m)^(?:Feed type|YouTube video ID|Direct keyword hit in transcript|Show name):.*$", "", source
    )
    if not isinstance(evidence, list) or not evidence or not all(
        isinstance(quote, str) and len(normalized(quote)) >= 12 and contains(evidence_source, quote)
        for quote in evidence
    ):
        return "", "missing_source_evidence"
    ids = review.get("entity_ids")
    if not isinstance(ids, list) or not all(isinstance(item, str) for item in ids):
        return "", "invalid_entity_ids"
    supported = {row["id"]: row for row in supported_entities(source, mode, show_name)}
    if any(item not in supported for item in ids):
        return "", "unsupported_entity"
    # Normalize only identities evidenced by the source, then check the text that will post.
    text = canonicalize_summary_proper_names(text, source, mode, show_name)
    for entity in reference()["entities"]:
        if any(contains(text, form) for form in [entity["name"], *entity["aliases"]]):
            if entity["id"] not in ids:
                return "", "undeclared_entity"
            if not contains(text, entity["name"]):
                return "", "noncanonical_entity"
    if any(not contains(text, supported[item]["name"]) for item in ids):
        return "", "unused_entity"
    # Unknown multiword proper names must be removed by the reviewer, not guessed.
    allowed_names = [supported[item]["name"] for item in ids]
    allowed_names += ["Portland Trail Blazers", "Trail Blazers", "Rip City", "Locked On Blazers", "Rose Garden Report", "NBA"]
    remaining = text
    for name in sorted(allowed_names, key=len, reverse=True):
        remaining = re.sub(r"(?<!\w)" + re.escape(name) + r"(?!\w)", "", remaining, flags=re.IGNORECASE)
    if re.search(r"\b[A-Z][A-Za-z]*(?:['\u2019-][A-Za-z]+)*\s+[A-Z][A-Za-z]*(?:['\u2019-][A-Za-z]+)*\b", remaining):
        return "", "unresolved_proper_name"
    if len(text) > min(limit, 250) or "..." in text or "\u2026" in text:
        return "", "length_or_truncation"
    if not text.endswith((".", "!", "?")):
        return "", "incomplete_sentence"
    return text, ""
