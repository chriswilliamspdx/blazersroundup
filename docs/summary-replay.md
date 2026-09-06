# Local summary replay

Run `.\.venv\Scripts\python.exe tools/replay_summaries.py` from the repository
to cache public YouTube captions.
Run `.\.venv\Scripts\python.exe tools/replay_summaries.py --run` to execute the
five selected cases with `GOOGLE_API_KEY` or `GEMINI_API_KEY` in the environment.
The model defaults to gemini-3.1-flash-lite and accepts the existing GEMINI_MODEL
and GEMINI_THINKING_LEVEL variables. No key belongs in a command argument or file.

The local command can inherit existing worker variables with:

```powershell
railway.cmd run --service worker --environment production --no-local -- .\.venv\Scripts\python.exe -B tools/replay_summaries.py --run
```

The runner invokes the actual worker handler with an in-memory database substitute,
cached transcripts, and a replacement publishing function that saves posts locally.
It does not start the worker loop. It does not open PostgreSQL, invoke the news or
repost scanners, or contact Bluesky. Captions are fetched directly without account
cookies, rotating proxies, or audio/video downloads. Caption retrieval has a
90-second overall timeout per video. Gemini has a 60-second request timeout,
no automatic request retries, and a maximum of ten requests per invocation.

Four real videos supply five cases. The fifth reuses a Blazers episode as an
explicitly labeled high-volume path test. The normal transcript window and
keyword gates still apply; a name elsewhere in a cached full transcript is not
necessarily supplied to Gemini. These cases do not cover every reported spelling.

`replay-output/captions` caches transcripts. `results.json` includes model usage,
drafts, reviews, validation reasons, captured posts and original input excerpts.
`report.md` presents those results for inspection. The output directory is ignored
by Git. Subsequent runs reuse captions but replace the reports and make new model
requests; use `--output` with another directory to preserve a separate run.
Use `--cache replay-output/captions` to reuse captions with another output directory,
and repeat `--case CASE-ID` to rerun only selected cases. Results include the selected
evidence excerpts alongside the IDs returned by Gemini.

A pass verifies compliance with the current checks, not independent factual truth.
Review the evidence and the final wording before treating a case as successful.
