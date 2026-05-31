from datetime import datetime, timedelta


def next_retry_at_for_attempt(
    now: datetime,
    attempt_count: int,
    retry_minutes: int,
    max_attempts: int,
) -> datetime | None:
    if attempt_count >= max_attempts:
        return None
    backoff = min(24, 2 ** max(0, attempt_count - 1))
    return now + timedelta(minutes=retry_minutes * backoff)


def transcript_retry_due(attempt: dict | None, max_attempts: int, now: datetime) -> bool:
    if not attempt:
        return True
    if attempt["attempt_count"] >= max_attempts and attempt["next_retry_at"] is None:
        return False
    retry_at = attempt["next_retry_at"]
    return retry_at is None or retry_at <= now
