# syntax=docker/dockerfile:1.7
#
# Build (from the raas-cli repo root):
#
#   docker build \
#     -f docker/Dockerfile \
#     -t salt-cli-api:latest \
#     .
#
# Run (connects to RaaS and registers the vcf-salt states repo on startup;
# omit the env vars to skip that and just run the API server):
#
#   docker run --rm -p 8000:8000 \
#     -e SCC_SERVER_URL=https://raas.example.com \
#     -e SCC_USERNAME=admin \
#     -e SCC_PASSWORD=secret \
#     salt-cli-api:latest
#
# Trigger a command:
#
#   curl -X POST http://localhost:8000/commands \
#     -H 'Content-Type: application/json' \
#     -d '{"command": "--version"}'

# Broadcom corp networks block direct PyPI access; point pip at the internal
# Artifactory mirror by default (override with --build-arg PIP_INDEX_URL=... elsewhere).
ARG PIP_INDEX_URL=https://packages.vcfd.broadcom.net/artifactory/api/pypi/pypi-virtual/simple

########################
# Stage 1: build the salt-config-cli wheel
########################
FROM python:3.12-slim AS wheel-builder
ARG PIP_INDEX_URL
ENV PIP_INDEX_URL=${PIP_INDEX_URL}

WORKDIR /build

COPY pyproject.toml README.md LICENSE ./
COPY salt_config_cli ./salt_config_cli

RUN pip install --no-cache-dir build && \
    python -m build --wheel --outdir /dist

########################
# Stage 2: runtime image
########################
FROM python:3.12-slim AS runtime
ARG PIP_INDEX_URL
ENV PIP_INDEX_URL=${PIP_INDEX_URL}

# scc shells out to the system git client for repo operations
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 1. Install the salt-config-cli wheel built above
COPY --from=wheel-builder /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -rf /tmp/*.whl

# 2. Sample API server that fronts the scc CLI
COPY docker/api/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY docker/api/app.py /app/app.py

# 3. Startup configuration: connect to RaaS and register the vcf-salt states repo
# (skipped automatically if SCC_SERVER_URL/credentials aren't provided at `docker run`)
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8000
ENTRYPOINT ["/entrypoint.sh"]
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"]
