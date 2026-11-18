# ==============================================================================
# Stage 1: Fetch & Prepare External Security Scanners (testssl.sh, nuclei, trivy)
# ==============================================================================
FROM debian:bookworm-slim AS security-tools

ARG TARGETARCH
ARG NUCLEI_VERSION=3.3.7
ARG TRIVY_VERSION=0.76.2
ARG TESTSSL_VERSION=3.2rc4

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    unzip \
    tar \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/tools

# 1. Install Nuclei (architecture-aware)
RUN ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "arm64" || echo "amd64") && \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" -o nuclei.zip && \
    unzip -q nuclei.zip nuclei && \
    chmod +x nuclei && \
    rm nuclei.zip

# Pre-fetch Nuclei community templates into /opt/nuclei-templates
ENV NUCLEI_TEMPLATES_DIR=/opt/nuclei-templates
RUN ./nuclei -update-templates -ud /opt/nuclei-templates

# 2. Install Trivy (architecture-aware)
RUN ARCH=$([ "$TARGETARCH" = "arm64" ] && echo "ARM64" || echo "64bit") && \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${ARCH}.tar.gz" -o trivy.tar.gz && \
    tar -xzf trivy.tar.gz trivy && \
    chmod +x trivy && \
    rm trivy.tar.gz

# 3. Install testssl.sh
RUN git clone --depth 1 --branch "${TESTSSL_VERSION}" https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && \
    rm -rf /opt/testssl.sh/.git


# ==============================================================================
# Stage 2: Build TIRweb Python Wheel & Virtual Environment
# ==============================================================================
FROM python:3.12-slim-bookworm AS python-builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml README.md ./
COPY tirweb ./tirweb
COPY rules ./rules

RUN pip install --upgrade pip hatchling && \
    pip install .


# ==============================================================================
# Stage 3: Hardened Minimal Runtime Image with WeasyPrint & Scanners
# ==============================================================================
FROM python:3.12-slim-bookworm AS runtime

LABEL org.opencontainers.image.title="TIRweb" \
      org.opencontainers.image.description="Standalone Web Application & API Security Auditing CLI"

# Install runtime dependencies for:
# - WeasyPrint (Pango, HarfBuzz, GDK-PixBuf, Fontconfig, Liberation fonts)
# - testssl.sh (bash, openssl, bsdmainutils/hexdump, dnsutils, procps, coreutils)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libharfbuzz0b \
    libgdk-pixbuf-2.0-0 \
    libffi8 \
    shared-mime-info \
    fontconfig \
    fonts-liberation \
    bash \
    openssl \
    bsdextrautils \
    dnsutils \
    procps \
    ca-certificates \
    && fc-cache -f \
    && rm -rf /var/lib/apt/lists/*

# Create non-root execution user
RUN groupadd --gid 1000 tirweb && \
    useradd --uid 1000 --gid tirweb --shell /bin/bash --create-home tirweb

# Copy Python virtual environment
COPY --from=python-builder /opt/venv /opt/venv

# Copy security tools and templates
COPY --from=security-tools /opt/tools/nuclei /usr/local/bin/nuclei
COPY --from=security-tools /opt/tools/trivy /usr/local/bin/trivy
COPY --from=security-tools --chown=tirweb:tirweb /opt/nuclei-templates /home/tirweb/nuclei-templates
COPY --from=security-tools /opt/testssl.sh /opt/testssl.sh
RUN ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Copy default ruleset into workspace
WORKDIR /workspace
COPY --chown=tirweb:tirweb rules/ /workspace/rules/

ENV PATH="/opt/venv/bin:/usr/local/bin:$PATH" \
    NUCLEI_TEMPLATES_DIR="/home/tirweb/nuclei-templates" \
    TRIVY_CACHE_DIR="/home/tirweb/.cache/trivy" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

USER tirweb

ENTRYPOINT ["tirweb"]
CMD ["--help"]