# worker/Dockerfile
FROM python:3.11-slim

# ffmpeg for faster-whisper
RUN apt-get update && apt-get install -y ffmpeg && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python deps first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY main.py ./main.py

# ✅ Copy feeds config from inside the worker/ context
#   (we moved the file to worker/config/feeds.yaml)
COPY config/feeds.yaml /app/config/feeds.yaml

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
