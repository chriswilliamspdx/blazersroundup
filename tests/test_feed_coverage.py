import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

import main  # noqa: E402


class FakeDb:
    def __init__(self):
        self.baseline = None
        self.stream_scan_state = {}

    def get_feed_baseline(self, _feed_url):
        return self.baseline

    def has_due_transcript_retry(self, _video_id, _max_attempts):
        return True

    def set_feed_baseline(self, _feed_url, published_at):
        self.baseline = published_at

    def get_state(self, key):
        return self.stream_scan_state.get(key)

    def set_state(self, key, value):
        self.stream_scan_state[key] = value


def settings(**overrides):
    base = {
        "debug": False,
        "dry_run": True,
        "max_feed_candidate_fallbacks": 5,
        "max_transient_failures_per_feed": 2,
        "max_videos_per_feed": 1,
        "transcript_max_attempts": 5,
        "youtube_completed_streams_enabled": False,
        "youtube_metadata_check_enabled": False,
        "youtube_api_key": None,
        "youtube_stream_search_min_minutes": 60,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def entry(video_id, published, title=None):
    return {
        "id": f"yt:video:{video_id}",
        "yt_videoid": video_id,
        "link": main.youtube_link(video_id),
        "title": title or video_id,
        "published": published,
    }


class FeedCoverageTests(unittest.TestCase):
    def test_retry_not_due_candidate_does_not_block_next_archived_video(self):
        calls = []
        entries = [
            entry("newest1", "2026-06-04T12:00:00Z"),
            entry("second2", "2026-06-04T11:00:00Z"),
        ]

        def fake_handle(*args, **kwargs):
            video_id = args[-1]
            calls.append(video_id)
            return main.VIDEO_NOT_DUE if video_id == "newest1" else main.VIDEO_OK

        with patch.object(main, "fetch_youtube_feed", return_value=(SimpleNamespace(entries=entries), {})), patch.object(
            main, "fetch_youtube_api_entries", return_value=([], {})
        ), patch.object(main, "fetch_youtube_video_statuses", return_value={}), patch.object(
            main, "handle_video", side_effect=fake_handle
        ):
            processed = main.process_channel(
                settings(),
                FakeDb(),
                summarizer=None,
                config={},
                transcript_settings=None,
                poll_context=main.PollContext(llm_limit=5),
                feed={"youtube_channel_id": "UCtest"},
                mode="blazers",
            )

        self.assertEqual(calls, ["newest1", "second2"])
        self.assertEqual(processed, 1)

    def test_first_run_retry_not_due_then_success_sets_baseline(self):
        db = FakeDb()
        calls = []
        entries = [
            entry("newest1", "2026-06-04T12:00:00Z"),
            entry("second2", "2026-06-04T11:00:00Z"),
            entry("oldest3", "2026-06-04T10:00:00Z"),
        ]

        def fake_handle(*args, **kwargs):
            video_id = args[-1]
            calls.append(video_id)
            return main.VIDEO_NOT_DUE if video_id == "newest1" else main.VIDEO_OK

        with patch.object(main, "fetch_youtube_feed", return_value=(SimpleNamespace(entries=entries), {})), patch.object(
            main, "fetch_youtube_api_entries", return_value=([], {})
        ), patch.object(main, "fetch_youtube_video_statuses", return_value={}), patch.object(
            main, "handle_video", side_effect=fake_handle
        ):
            processed = main.process_channel(
                settings(dry_run=False),
                db,
                summarizer=None,
                config={},
                transcript_settings=None,
                poll_context=main.PollContext(llm_limit=5),
                feed={"youtube_channel_id": "UCtest"},
                mode="blazers",
            )

        self.assertEqual(calls, ["newest1", "second2"])
        self.assertEqual(processed, 1)
        self.assertEqual(db.baseline.isoformat(), "2026-06-04T11:00:00+00:00")

    def test_first_run_already_seen_sets_baseline_without_backfill(self):
        db = FakeDb()
        calls = []
        entries = [
            entry("newest1", "2026-06-04T12:00:00Z"),
            entry("second2", "2026-06-04T11:00:00Z"),
        ]

        def fake_handle(*args, **kwargs):
            video_id = args[-1]
            calls.append(video_id)
            return main.VIDEO_ALREADY_SEEN

        with patch.object(main, "fetch_youtube_feed", return_value=(SimpleNamespace(entries=entries), {})), patch.object(
            main, "fetch_youtube_api_entries", return_value=([], {})
        ), patch.object(main, "fetch_youtube_video_statuses", return_value={}), patch.object(
            main, "handle_video", side_effect=fake_handle
        ):
            processed = main.process_channel(
                settings(dry_run=False),
                db,
                summarizer=None,
                config={},
                transcript_settings=None,
                poll_context=main.PollContext(llm_limit=5),
                feed={"youtube_channel_id": "UCtest"},
                mode="blazers",
            )

        self.assertEqual(calls, ["newest1"])
        self.assertEqual(processed, 0)
        self.assertEqual(db.baseline.isoformat(), "2026-06-04T12:00:00+00:00")

    def test_completed_stream_entries_merge_with_upload_entries(self):
        upload = entry("upload1", "2026-06-04T10:00:00Z")
        duplicate = entry("upload1", "2026-06-04T10:00:00Z", title="duplicate")
        stream = entry("stream2", "2026-06-04T12:00:00Z")

        merged = main.merge_youtube_entries([upload], [duplicate, stream])

        self.assertEqual([main.parse_youtube_video_id(item) for item in merged], ["stream2", "upload1"])

    def test_live_metadata_skips_before_transcript_attempt(self):
        outcome = main.handle_video(
            settings(),
            db=None,
            summarizer=None,
            config={},
            transcript_settings=None,
            poll_context=main.PollContext(llm_limit=5),
            feed_url="feed",
            show_name="show",
            mode="blazers",
            entry=entry("live01", "2026-06-04T12:00:00Z"),
            video_id="live01",
            video_status={"live_broadcast_content": "live", "actual_end_time": None},
        )

        self.assertEqual(outcome, main.VIDEO_SKIP_CANDIDATE)


if __name__ == "__main__":
    unittest.main()
