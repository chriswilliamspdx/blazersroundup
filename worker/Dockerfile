# Smaller, no ffmpeg needed
FROM python:3.11-slim

# System deps (just CA certs + curl handy)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy worker code and config
COPY worker/requirements.txt /app/worker/requirements.txt
RUN pip install --no-cache-dir -r /app/worker/requirements.txt

COPY worker/ /app/worker/
COPY config/ /app/config/

ENV PYTHONUNBUFFERED=1

# FEEDS_PATH lets us point main.py at the YouTube-only config
ENV FEEDS_PATH=/app/config/feeds.youtube.yaml

CMD ["python", "/app/worker/main.py"]
