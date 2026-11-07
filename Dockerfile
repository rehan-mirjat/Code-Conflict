# ==============================================================================
# Code & Conflict - Production Container Image
# Multi-stage lightweight Python container with hardened security practices
# ==============================================================================

FROM python:3.12-slim-bookworm AS base

# Prevent Python from writing pyc files and buffering stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=5000 \
    CC_DB=/app/data/data.db \
    SECRET_KEY=

WORKDIR /app

# Install runtime dependencies and security updates
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy backend requirements and install
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Create an unprivileged user for security isolation
RUN useradd -u 1001 -m -s /bin/bash appuser && \
    mkdir -p /app/data && \
    chown -R appuser:appuser /app

# Copy application code
COPY --chown=appuser:appuser . /app

# Switch to unprivileged user
USER appuser

# Expose HTTP port
EXPOSE 5000

# Container healthcheck against /api/health
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:5000/api/health || exit 1

# Production WSGI startup via Gunicorn
CMD ["gunicorn", "--workers=4", "--threads=2", "--bind=0.0.0.0:5000", "--access-logfile=-", "--error-logfile=-", "backend.wsgi:application"]

