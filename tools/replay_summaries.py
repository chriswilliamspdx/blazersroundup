"""Run the worker's summary pipeline with cached captions and no production writes."""

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

import requests
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))
import main as worker
from summary_accuracy import evidence_catalog, supported_entities, validate_review
from transcript_providers import TranscriptResult, TranscriptSettings, fetch_transcript

CASES = [
    {"id": "locked-overview", "video_id": "roVYMiAmqzk", "mode": "blazers"},
    {"id": "locked-avdija", "video_id": "4bsrg115Aa8", "mode": "blazers"},
    {"id": "no-dunks", "video_id": "Y9V9HQw2RXs", "mode": "national"},
    {"id": "locked-on-nba", "video_id": "onCYbqVnEEw", "mode": "national"},
    {"id": "high-volume-path", "video_id": "roVYMiAmqzk", "mode": "high_volume",
     "note": "Locked On Blazers episode replayed as high-volume; this is a path test, not a high-volume feed discovery."},
]


def save(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True), encoding="utf-8")


class MemoryDatabase:
    """Ephemeral responses only; unexpected database calls raise AttributeError."""

    def already_seen(self, *args):
        return False

    def llm_cooldown_active(self):
        return None

    def summary_retry_ready(self, *args):
        return True

    def transcript_retry_ready(self, *args):
        return True

    def record_summary_success(self, *args):
        pass

    def record_summary_failure(self, *args):
        return 1, None

    def set_llm_cooldown(self, until, *args):
        return until


class Recorder:
    def __init__(self, summarizer):
        self.summarizer = summarizer
        self.draft = None
        self.review = None
        self.source = ""

    def summarize_json(self, prompt, source):
        self.source = source.split("\n\nIdentity references (not source evidence):\n", 1)[0]
        self.draft = self.summarizer.summarize_json(prompt, source)
        return self.draft

    def fact_check_summary_json(self, prompt, text, **kwargs):
        self.review = self.summarizer.fact_check_summary_json(prompt, text, **kwargs)
        return self.review


def replay(case, cached, config, summarizer):
    transcript = TranscriptResult(cached["full_text"], cached["segments"], cached["provider"])
    settings = SimpleNamespace(
        dry_run=True, dry_run_record_transcript_retries=False, debug=True,
        force_transcript_retry=False, llm_max_calls_per_poll=2, llm_max_attempts=1,
        transcript_max_attempts=1, summary_post_char_limit=250, llm_retry_minutes=60,
    )
    recorder = Recorder(summarizer)
    posts = []

    def capture_post(_settings, first, second, **embed):
        posts.append({"first": first, "summary": second, "characters": len(second), "embed": embed})
        return True

    output = io.StringIO()
    # Replace both external boundaries before invoking the production handler.
    with patch.object(worker, "fetch_transcript", return_value=transcript), patch.object(
        worker, "create_thread", side_effect=capture_post,
    ), contextlib.redirect_stdout(output):
        outcome = worker.handle_video(
            settings, MemoryDatabase(), recorder, config, None,
            worker.PollContext(llm_limit=2), "replay-only", cached["show_name"],
            case["mode"], {"title": cached["title"], "id": case["video_id"]},
            case["video_id"], {"title": cached["title"], "description": ""},
        )
    checked, reason = validate_review(recorder.review, recorder.source, case["mode"])
    if recorder.review is None:
        reason = "review_not_reached"
    return {
        **case, "title": cached["title"], "outcome": outcome,
        "source_excerpt": recorder.source, "draft": recorder.draft, "review": recorder.review,
        "validated_summary": checked, "validation_reason": reason, "captured_posts": posts,
        "selected_evidence": {k: v for k, v in evidence_catalog(recorder.source).items()
                              if k in (recorder.review or {}).get("source_evidence_ids", [])},
        "source_entities": [e["name"] for e in supported_entities(recorder.source, case["mode"])],
        "pipeline_log": output.getvalue(),
    }


def prepare_video(video_id, folder):
    response = requests.get(
        "https://www.youtube.com/oembed",
        params={"url": "https://www.youtube.com/watch?v=" + video_id, "format": "json"}, timeout=20,
    )
    response.raise_for_status()
    info = response.json()
    # Direct public captions only: no cookies, rotating proxies, audio or video downloads.
    result = fetch_transcript(video_id, TranscriptSettings(proxy_enabled=False), log=lambda *args: None)
    save(folder / (video_id + ".json"), {
        "video_id": video_id, "title": info["title"], "show_name": info["author_name"],
        "provider": result.provider, "full_text": result.full_text, "segments": result.segments,
    })


def write_report(folder, report):
    save(folder / "results.json", report)
    lines = ["# Summary replay", "", "No posts sent; no production database accessed.", "",
             f"Model: {report['model']}", f"Gemini requests: {report['requests']}", "",
             "Model verdicts require human review; a validation pass is not a guarantee of factual accuracy.", ""]
    for result in report["cases"]:
        lines.extend(["## " + result["id"], "", "Video: https://www.youtube.com/watch?v=" + result["video_id"],
                      "Mode: " + result["mode"], result.get("note", ""), ""])
        if "error" in result:
            lines.extend(["Blocked: " + result["error"], ""])
            continue
        lines.extend(["Title: " + result.get("title", ""),
                      "Outcome: " + result.get("outcome", "captions cached; Gemini pending"),
                      "Validation: " + (result.get("validation_reason") or "passed"), ""])
        for label in ("draft", "review"):
            if result.get(label):
                lines.extend([label.capitalize() + ":", "```json", json.dumps(result[label], indent=2), "```", ""])
        for post in result.get("captured_posts", []):
            lines.extend([f"Final reply ({post['characters']} characters): {post['summary']}", ""])
        if result.get("source_excerpt"):
            lines.extend(["Source supplied to Gemini:", "```text", result["source_excerpt"], "```", ""])
    (folder / "report.md").write_text("\n".join(lines), encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / "replay-output")
    parser.add_argument("--cache", type=Path, help="Reuse an existing caption cache")
    parser.add_argument("--case", action="append", choices=[c["id"] for c in CASES], help="Select cases to rerun")
    parser.add_argument("--run", action="store_true", help="Make at most ten Gemini requests; otherwise only cache captions")
    args = parser.parse_args()
    folder = args.output.resolve()
    folder.mkdir(parents=True, exist_ok=True)
    cache = args.cache.resolve() if args.cache else folder / "captions"
    cache.mkdir(exist_ok=True)
    config = yaml.safe_load((ROOT / "config/feeds.youtube.yaml").read_text(encoding="utf-8"))
    cached, failures = {}, {}
    cases = [c for c in CASES if not args.case or c["id"] in args.case]
    for video_id in dict.fromkeys(c["video_id"] for c in cases):
        print("Preparing captions:", video_id, flush=True)
        path = cache / (video_id + ".json")
        if not path.exists():
            try:
                child = subprocess.run(
                    [sys.executable, str(Path(__file__).resolve()), "--caption-child", video_id, str(cache)],
                    capture_output=True, text=True, timeout=90,
                )
                if child.returncode:
                    failures[video_id] = "caption_fetch_failed"
            except subprocess.TimeoutExpired:
                failures[video_id] = "caption_fetch_timeout"
        if path.exists():
            cached[video_id] = json.loads(path.read_text(encoding="utf-8"))
        else:
            failures.setdefault(video_id, "caption_cache_missing")
    model = os.getenv("GEMINI_MODEL", "gemini-3.1-flash-lite")
    report = {"model": model, "requests": 0, "usage": [], "request_errors": [], "cases": []}
    key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
    if not args.run or not key:
        report["cases"] = [{**c, "error": failures.get(c["video_id"], "Gemini pending" if not args.run else "Gemini credentials unavailable")}
                           for c in cases]
        write_report(folder, report)
        print("Captions cached:", len(cached), "of", len(cached) + len(failures), "; Gemini requests: 0", flush=True)
        return
    summarizer = worker.GeminiSummarizer(key, model, os.getenv("GEMINI_THINKING_LEVEL", "low"), 60)
    # Same generation code with a bounded transport and no automatic request retries.
    summarizer.client.close()
    summarizer.client = worker.genai.Client(api_key=key, http_options=worker.gtypes.HttpOptions(
        timeout=60000, retry_options=worker.gtypes.HttpRetryOptions(attempts=1),
    ))
    original_generate = summarizer.client.models.generate_content
    last_call = [0.0]

    def bounded_generate(**kwargs):
        if report["requests"] >= 10:
            raise RuntimeError("Replay request limit reached")
        time.sleep(max(0.0, 4.1 - (time.monotonic() - last_call[0])))
        last_call[0] = time.monotonic()
        report["requests"] += 1
        try:
            response = original_generate(**kwargs)
        except Exception as exc:
            report["request_errors"].append({
                "request": report["requests"], "type": type(exc).__name__,
                "status_code": getattr(exc, "status_code", None),
                "elapsed_seconds": round(time.monotonic() - last_call[0], 2),
            })
            raise
        usage = getattr(response, "usage_metadata", None)
        if usage:
            report["usage"].append(usage.model_dump(mode="json"))
        return response

    try:
        with patch.object(summarizer.client.models, "generate_content", side_effect=bounded_generate):
            for case in cases:
                print("Replaying:", case["id"], flush=True)
                if case["video_id"] in failures:
                    result = {**case, "error": failures[case["video_id"]]}
                else:
                    try:
                        result = replay(case, cached[case["video_id"]], config, summarizer)
                    except Exception as exc:
                        result = {**case, "error": type(exc).__name__}
                report["cases"].append(result)
                write_report(folder, report)
    finally:
        summarizer.client.close()
    print("Done. Gemini requests:", report["requests"], "Report:", folder / "report.md")


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--caption-child":
        try:
            if not re.fullmatch(r"[A-Za-z0-9_-]{11}", sys.argv[2]):
                raise ValueError("Invalid video ID")
            prepare_video(sys.argv[2], Path(sys.argv[3]))
        except Exception as exc:
            print(type(exc).__name__, file=sys.stderr)
            sys.exit(1)
    else:
        main()
