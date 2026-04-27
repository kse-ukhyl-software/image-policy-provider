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
CMD ["uvicorn", "src.main:app", \
     "--host", "0.0.0.0", "--port", "8443", \
     "--ssl-keyfile", "/etc/tls/tls.key", \
     "--ssl-certfile", "/etc/tls/tls.crt"]
