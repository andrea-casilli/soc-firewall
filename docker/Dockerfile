# SOC Firewall Dockerfile
# Multi-stage build for production container
# Version: 1.0.0

# Stage 1: Builder
FROM python:3.11-slim-bullseye as builder

# Set build arguments
ARG BUILD_DATE
ARG VERSION=1.0.0
ARG VCS_REF

# Labels
LABEL maintainer="SOC Team <soc@example.com>"
LABEL org.label-schema.build-date=$BUILD_DATE
LABEL org.label-schema.name="soc-firewall"
LABEL org.label-schema.description="Enterprise SOC Firewall System"
LABEL org.label-schema.version=$VERSION
LABEL org.label-schema.vcs-ref=$VCS_REF
LABEL org.label-schema.schema-version="1.0"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=100

# Install system build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    libffi-dev \
    libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements/production.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim-bullseye

# Create non-root user
RUN groupadd -g 1000 socfw && \
    useradd -u 1000 -g socfw -m -s /bin/bash socfw

# Install runtime system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    libcap2-bin \
    iptables \
    tzdata \
    curl \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Grant network capabilities to the binary
RUN setcap 'cap_net_raw,cap_net_admin+eip' /usr/local/bin/python3.11

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONPATH="/app" \
    SOC_FW_CONFIG="/etc/soc-firewall/production.yaml" \
    TZ="UTC"

# Create directory structure
RUN mkdir -p /app \
    /etc/soc-firewall \
    /var/log/soc-firewall \
    /var/lib/soc-firewall \
    /var/run/soc-firewall

# Copy application code
COPY src/ /app/src/
COPY main.py /app/
COPY config/production.yaml /etc/soc-firewall/production.yaml
COPY config/rules/ /etc/soc-firewall/rules/
COPY config/alerting/ /etc/soc-firewall/alerting/

# Set ownership
RUN chown -R socfw:socfw /app \
    /etc/soc-firewall \
    /var/log/soc-firewall \
    /var/lib/soc-firewall \
    /var/run/soc-firewall

# Set permissions
RUN chmod 750 /app \
    && chmod 640 /etc/soc-firewall/production.yaml \
    && chmod 755 /app/main.py

# Switch to non-root user
USER socfw

# Set working directory
WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:5000/api/v1/status || exit 1

# Expose ports
EXPOSE 5000 8765

# Define volumes
VOLUME ["/etc/soc-firewall", "/var/log/soc-firewall", "/var/lib/soc-firewall"]

# Default command
CMD ["python", "main.py", "--config", "/etc/soc-firewall/production.yaml"]

# Stage 3: Development
FROM builder as development

# Install development dependencies
COPY requirements/development.txt /tmp/development.txt
RUN pip install --no-cache-dir -r /tmp/development.txt

# Install debug tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    vim \
    less \
    strace \
    tcpdump \
    net-tools \
    iputils-ping \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy development configuration
COPY config/development.yaml /etc/soc-firewall/development.yaml
COPY config/rules/ /etc/soc-firewall/rules/
COPY config/alerting/ /etc/soc-firewall/alerting/

# Set development environment
ENV SOC_FW_CONFIG="/etc/soc-firewall/development.yaml" \
    FLASK_ENV="development" \
    PYTHONBREAKPOINT="ipdb.set_trace"

# Expose debug port
EXPOSE 5678

# Development command with auto-reload
CMD ["python", "-m", "debugpy", "--listen", "0.0.0.0:5678", "-m", "flask", "run", "--host", "0.0.0.0", "--port", "5000"]

# Stage 4: Test
FROM development as test

# Copy test files
COPY tests/ /app/tests/
COPY pytest.ini /app/
COPY .coveragerc /app/

# Run tests
CMD ["pytest", "tests/", "-v", "--cov=src", "--cov-report=html"]
