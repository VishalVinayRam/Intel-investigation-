# Multi-stage Dockerfile for Threat Intelligence Worker
# Security Hardening: Non-root user, minimal base image, no secrets

# Stage 1: Builder stage
FROM python:3.11-slim-bookworm AS builder

# Set working directory
WORKDIR /build

# Install dependencies in a virtual environment
COPY app/requirements.txt .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir --upgrade pip && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime stage
FROM python:3.11-slim-bookworm

# Security Build: Upgrade system packages to pull latest security patches
RUN apt-get update && apt-get upgrade -y && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Security: Create non-root user
RUN groupadd -r appuser && \
    useradd -r -g appuser -u 1000 -m -s /sbin/nologin appuser

# Set working directory
WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy application code
COPY app/worker.py .

# Security: Change ownership to non-root user
RUN chown -R appuser:appuser /app

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Security: Switch to non-root user
USER appuser

# Expose metrics port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Run the application
CMD ["python", "worker.py"]
