# syntax=docker/dockerfile:1

FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# System deps (add build tools only if needed)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy app code
COPY app ./app

# Expose port (Cloud Run ignores EXPOSE but it's fine)
EXPOSE 8080

# Cloud Run sets $PORT; default to 8080 for local Docker runs
ENV PORT=8080

# Start with uvicorn
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT}"]
