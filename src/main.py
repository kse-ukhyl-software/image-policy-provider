"""FastAPI entrypoint for the Gatekeeper external-data provider.

Logging is verbose on purpose -- this service is used in classroom
labs, and seeing the full request/response in `kubectl logs` is part
of how students reason about the External Data flow. Every admission
call produces:

  - a "request" line listing the keys Gatekeeper sent
  - one "key" line per image with verified/error outcome
  - a "response" summary with verified/error counts
"""
from __future__ import annotations

import logging
import os
import time
import uuid

from fastapi import FastAPI, HTTPException

from .models import (
    ProviderRequest,
    ProviderResponse,
    ProviderResponseBody,
    ProviderResponseItem,
)
from .verify import VerificationError, VerifierConfig, verify_image

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("image-policy-provider")

app = FastAPI(title="image-policy-provider", version="0.1.0")
_config = VerifierConfig.from_env()


def _trust_mode(cfg: VerifierConfig) -> str:
    if cfg.cosign_key_path:
        return f"key ({cfg.cosign_key_path})"
    if cfg.cosign_identity and cfg.cosign_oidc_issuer:
        return f"keyless (identity={cfg.cosign_identity}, issuer={cfg.cosign_oidc_issuer})"
    return "unset (every image will fail)"


logger.info(
    "verifier configured: allowed_registries=%s, trust_mode=%s",
    _config.allowed_registries,
    _trust_mode(_config),
)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/validate", response_model=ProviderResponse)
def validate(request: ProviderRequest) -> ProviderResponse:
    if request.kind != "ProviderRequest":
        raise HTTPException(status_code=400, detail=f"unexpected kind {request.kind!r}")

    # Short request id so multi-line entries can be correlated when
    # admission requests overlap.
    rid = uuid.uuid4().hex[:8]
    keys = list(request.request.keys)
    logger.info("[%s] request: %d keys -> %s", rid, len(keys), keys)

    items: list[ProviderResponseItem] = []
    started = time.monotonic()
    for key in keys:
        t0 = time.monotonic()
        try:
            summary = verify_image(key, _config)
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            logger.info("[%s] key OK   (%d ms): %s", rid, elapsed_ms, key)
            items.append(ProviderResponseItem(key=key, value=summary))
        except VerificationError as exc:
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            logger.warning(
                "[%s] key FAIL (%d ms): %s -- %s", rid, elapsed_ms, key, exc
            )
            items.append(ProviderResponseItem(key=key, error=str(exc)))
        except Exception as exc:  # noqa: BLE001 - last-resort guard
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            logger.exception(
                "[%s] key ERROR (%d ms, internal): %s", rid, elapsed_ms, key
            )
            items.append(ProviderResponseItem(key=key, error=f"internal error: {exc}"))

    total_ms = int((time.monotonic() - started) * 1000)
    verified = sum(1 for i in items if i.error is None)
    rejected = len(items) - verified
    logger.info(
        "[%s] response: %d verified, %d rejected, total %d ms",
        rid, verified, rejected, total_ms,
    )

    return ProviderResponse(response=ProviderResponseBody(items=items))
