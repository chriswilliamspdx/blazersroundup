# Podcast summary validation

This applies to summary replies for Blazers, national and high-volume YouTube feeds.
The worker still makes at most the existing draft and review Gemini calls for a
successful summary. No extra model call or external lookup was added.

## References and evidence

The bundled worker/summary_entities.json contains canonical names, transcript
aliases, source URLs and a verification date. It is a summary reference only:
it does not change podcast search keywords, news matching or Bluesky repost rules.
Only identities found in the original source are sent to the model.

The initial snapshot was verified on September 5, 2026 during the audit. Roles
expire after 14 days. Once expired, the prompt receives spellings but no role
facts. The snapshot is not automatically refreshed. To update it, verify the
listed sources, reconcile transactions and revise the data and verification date
together. Do not update the date without checking the underlying facts.

Aliases require basketball/team or show context. Full names are matched at word
boundaries; broad edit-distance replacement is deliberately not used for output.
The artist Robert Williams does not receive the basketball identity. A standalone
Mori requires a coaching reference and team context. Missing identities are
omitted from the rewritten summary instead of guessed.

The reviewer must return a verdict for the final rewritten summary, confirmed
Blazers context, all named entity IDs, and IDs selecting supporting excerpts from
the original title/transcript. The response schema restricts both lists to supplied
values. Excerpts are numbered locally and are not retyped by the model, preventing
quote drift caused by omitted filler words. The validator checks that evidence
IDs exist, person IDs refer to people
present in the source, known names are canonical, and unresolved multiword proper
names do not pass. References and the draft do not count as episode evidence.
NBA team names are handled separately from people when the team or its nickname
is present in the source. Team names follow the [NBA team directory](https://www.nba.com/teams),
including the Los Angeles Clippers spelling used in summaries.

Replies describe source discussion without asserting independently verified
current-status claims about roles, affiliations, contracts, injuries or trades.
Dates and reference facts must not turn a historical discussion into a current
announcement.

## Publication behavior

Validation occurs after name correction and before posting, with a hard maximum
of 250 characters (or the lower configured summary limit). Overlong or incomplete
review output uses the neutral fallback rather than getting cut mid-sentence.
An unsuccessful review keeps the existing video posting workflow and uses a
neutral reply. If review explicitly rejects Blazers context, that reply does not
assert a Blazers topic. Initial video selection and first-post text are unchanged.

Logs report "Gemini summary validation fallback" with a reason. Debug logs report
"Gemini summary validated" with character count or the review's correction note.
There are no new Railway variables, database migrations or web-service changes.

## Limits and verification

This is source-grounded review with a dated identity reference, not independent
live-web verification of every claim. Evidence IDs select actual source excerpts;
the model still judges whether they support the summary. The
proper-name heuristic is intentionally conservative and can fall back for a
legitimate unknown name. A live dry run is needed to measure that rate and Gemini
schema compliance.

Regression tests cover the reported name variants, unrelated people, apostrophized
unknown names, fabricated evidence, failed/malformed verdicts, expired roles,
post-normalization length and unchanged video posting across all three feed modes.
