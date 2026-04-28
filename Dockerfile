# syntax=docker/dockerfile:1.7
ARG PYTHON_VERSION=3.12
ARG COSIGN_VERSION=v2.4.1

FROM ghcr.io/sigstore/cosign/cosign:${COSIGN_VERSION} AS cosign

FROM python:${PYTHON_VERSION}-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign

COPY src ./src

RUN useradd --system --uid 65532 --no-create-home provider
USER 65532

EXPOSE 8443

# TLS cert/key paths the entrypoint reads. Defaults match what
# infra/image-policy-provider/deployment.yaml mounts.
ENV TLS_CERT_FILE=/etc/tls/tls.crt \
    TLS_KEY_FILE=/etc/tls/tls.key

# src.start builds the uvicorn SSLContext explicitly so we can pin
# TLS 1.3 minimum and turn on mTLS when GATEKEEPER_CA_CERT_FILE is
# set (Ratify-equivalent posture).
CMD ["python", "-m", "src.start"]
