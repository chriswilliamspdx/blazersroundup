# Dockerfile (repo root)
FROM python:3.11-slim

# Slim basics
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for better layer caching
COPY worker/requirements.txt worker/requirements.txt
RUN pip install --no-cache-dir -r worker/requirements.txt

# Bring in app code (these must exist in context!)
COPY worker/ /app/worker/
COPY config/ /app/config/

ENV PYTHONUNBUFFERED=1

CMD ["python", "-u", "worker/main.py"]
