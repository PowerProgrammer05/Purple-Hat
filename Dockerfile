# PURPLE HAT - Dockerfile
# Comprehensive Security Testing Framework

FROM python:3.11-slim

LABEL maintainer="PURPLE HAT Team"
LABEL description="PURPLE HAT - Modern Security Testing Framework"
LABEL version="2.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    dnsutils \
    net-tools \
    iputils-ping \
    whois \
    nmap \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy application files
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir -r requirements.txt

# Install in development mode
RUN pip install --no-cache-dir -e .

# Create necessary directories
RUN mkdir -p /app/results /app/logs /app/sessions

# Expose port for web interface
EXPOSE 5000

# Volume for results and configs
VOLUME ["/app/results", "/app/sessions", "/app/config"]

# Environment variables
ENV FLASK_APP=ui.webapp_v3
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

# Default command: Start web interface
CMD ["python", "-m", "ui.webapp_v3"]
