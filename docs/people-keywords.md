# People Keywords

Audited Sep. 6, 2026 against the Sep. 5, 2026 verification snapshot.

## Current team people

The 19 current roster names are taken from the official NBA team page: [Portland Trail Blazers team page](https://www.nba.com/team/1610612757/blazers). Blake Wesley is retained because he is listed there; the entity note deliberately does not make an unsupported signed-contract claim. Robert Williams III is canonical in summaries, while `Robert Williams` is also a search form because posts often omit the suffix.

The official team page lists Micah Nori, James Posey, Quinton Crawford, Ronnie Burrell, and Nate Bjorkgren. Pat St. Andrews is omitted from current configuration because the live team page did not list him on verification day; the older summer-league release is not treated as current staff proof.

## Basketball and ownership people

Joe Cronin is supported by the team's 2025 contract-extension announcement and Andrae Patterson by his current NBA profile. The NBA front-office listing supports Tom Dundon, Marc Zahr, Stan Middleman, Andrew Cherng, Sheel Tyle, Richard Chaifetz, Marc Grandisson, Jennifer Gates, Nayel Nassar, Taavet Hinrikus, and Dan Zilberman as the bounded ownership set.

Mike Schmitz remains in `summary_entities.json` as a historical Blazers identity, but is excluded from current search because NBA.com identifies him as the Dallas Mavericks general manager. Sergi Oliva remains context-gated: NBA.com references him as a Portland assistant GM in a recent scouting-rules article and a 2025 team release, but the current front-office listing was not independently confirmed here. His current status is an explicit follow-up item, not a departure claim. Dewayne Hankins, Joe Loomis, and Galen Davies are included from current official NBA/Blazers executive profiles or the front-office listing. Jody Allen remains as a former chair and historical owner reference. Other non-basketball front-office employees are not added.

## Keyword policy

`keywords_positive` in the feed configs contains current canonical names plus conservative full-name ASR spellings, `Robert Williams`, `Time Lord`, `Portland`, and the existing stable team brands for transcript detection. The shared `keywords_search` lists are canonical-only, with the bounded common `Robert Williams` form. `keywords_context_required` keeps current non-player names and aliases plus the ambiguous Robert Williams forms for the later context gate. Former-player names and aliases for Grant, Murray, Thybulle, Love, Rupert, and Reath remain available for historical summary fact-checking but are removed from standalone keyword lists.

The `verified_on` value remains `2026-09-05`: the existing freshness snapshot was not globally bumped because every underlying historical and media identity was not reverified for current roles.

## Sources

- [NBA team roster, coaches, and team background](https://www.nba.com/team/1610612757/blazers)
- [Joe Cronin contract extension](https://www.nba.com/blazers/news/portland-trail-blazers-sign-general-manager-joe-cronin-to-contract-extension)
- [Andrae Patterson profile](https://www.nba.com/blazers/andrae-patterson)
- [NBA front-office listing](https://www.nba.com/blazers/frontoffice)
- [Mike Schmitz Dallas Mavericks appointment](https://www.nba.com/news/dallas-mavericks-name-mike-schimitz-general-manager)
- [2022 Schmitz/Oliva hiring release](https://www.nba.com/blazers/trail-blazers-hire-mike-schmitz-and-sergi-oliva-assistant-general-managers-kevin-kinghorn-chief)
- [NBA report naming Sergi Oliva](https://www.nba.com/news/trail-blazers-fined-scouting-rules)
- [Rip City Remix release referencing Sergi Oliva](https://www.nba.com/blazers/news/rip-city-remix-name-jonah-herscu-head-coach)
