FROM python:3.11-slim

# System deps for audio & whisper
RUN apt-get update && apt-get install -y ffmpeg && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ./main.py
COPY ../config/feeds.yaml /app/config/feeds.yaml

ENV PYTHONUNBUFFERED=1
CMD ["python","-u","main.py"]
