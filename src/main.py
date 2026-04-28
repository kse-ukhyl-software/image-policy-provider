"""FastAPI entrypoint for the Gatekeeper external-data provider.

Logging is verbose on purpose -- this service is used in classroom
labs, and seeing the full request/response in `kubectl logs` is part
of how students reason about the External Data flow. Every admission
call produces:

  - a "request" line listing the keys Gatekeeper sent
  - one "key" line per image with verified/error outcome
  - a "response" summary with verified/error counts

Set `LOG_BODIES=true` to also dump the full ProviderRequest and
ProviderResponse JSON exchanged with Gatekeeper -- useful for
teaching, noisy in production.
"""
from __future__ import annotations

import asyncio
import json
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

LOG_BODIES = os.getenv("LOG_BODIES", "").lower() in ("1", "true", "yes")

app = FastAPI(title="image-policy-provider", version="0.1.0")
_config = VerifierConfig.from_env()


def _trust_mode(cfg: VerifierConfig) -> str:
    if cfg.cosign_key_path:
        return f"key ({cfg.cosign_key_path})"
    if cfg.cosign_identity and cfg.cosign_oidc_issuer:
        return f"keyless (identity={cfg.cosign_identity}, issuer={cfg.cosign_oidc_issuer})"
    return "unset (every image will fail)"


logger.info(
    "verifier configured: allowed_registries=%s, trust_mode=%s, log_bodies=%s",
    _config.allowed_registries,
    _trust_mode(_config),
    LOG_BODIES,
)


def _dump_json(label: str, rid: str, payload) -> None:
    """Pretty-print the full request/response body to logs."""
    if hasattr(payload, "model_dump"):  # pydantic v2
        body = payload.model_dump(mode="json")
    elif hasattr(payload, "dict"):  # pydantic v1 fallback
        body = payload.dict()
    else:
        body = payload
    text = json.dumps(body, indent=2, default=str)
    # Each line gets the rid prefix so grep [<rid>] picks the whole entry.
    for line in (f"[{rid}] {label}:\n" + text).splitlines():
        logger.info(line)


@app.get("/healthz")
def healthz() -> dict:
    """Liveness: process is up and the HTTP server is responding."""
    return {"status": "ok"}


@app.get("/readyz")
def readyz():
    """Readiness: the verifier is actually configured to do its job.

    We refuse traffic until cosign is on the PATH and at least one
    trust mode (key path OR keyless identity+issuer) is set. This
    prevents the noisy 'no cosign trust material configured' error
    on every key during boot, and matches Ratify's split between
    /healthz (liveness) and /readyz (readiness) on its manager port.
    """
    import shutil

    problems = []
    if shutil.which(_config.cosign_binary) is None:
        problems.append(f"cosign binary {_config.cosign_binary!r} not on PATH")
    if not _config.cosign_key_path and not (
        _config.cosign_identity and _config.cosign_oidc_issuer
    ):
        problems.append(
            "no cosign trust material (set COSIGN_KEY_PATH, or "
            "COSIGN_IDENTITY + COSIGN_OIDC_ISSUER)"
        )
    if problems:
        raise HTTPException(status_code=503, detail={"problems": problems})
    return {"status": "ready"}


# Hard upper bound on a single cosign verify call. Gatekeeper's
# external-data webhook timeout (Provider.spec.timeout) is what
# matters in practice, but if Gatekeeper has already given up,
# leaving this thread blocked on a stalled registry would tie up
# a Uvicorn worker for ages. Match Ratify's middlewareWithTimeout
# default for the verify path.
PER_KEY_TIMEOUT_S = float(os.getenv("PER_KEY_TIMEOUT_S", "5"))


@app.post("/validate", response_model=ProviderResponse)
async def validate(request: ProviderRequest) -> ProviderResponse:
    if request.kind != "ProviderRequest":
        raise HTTPException(status_code=400, detail=f"unexpected kind {request.kind!r}")

    # Short request id so multi-line entries can be correlated when
    # admission requests overlap.
    rid = uuid.uuid4().hex[:8]
    keys = list(request.request.keys)
    logger.info("[%s] request: %d keys -> %s", rid, len(keys), keys)
    if LOG_BODIES:
        _dump_json("ProviderRequest body", rid, request)

    items: list[ProviderResponseItem] = []
    started = time.monotonic()
    for key in keys:
        t0 = time.monotonic()
        try:
            # Run the blocking cosign call on the default executor so
            # the event loop can serve other requests, with a hard
            # per-key deadline. Gatekeeper's webhook timeout is upstream
            # of this; ours is a defence-in-depth bound on stalls.
            summary = await asyncio.wait_for(
                asyncio.to_thread(verify_image, key, _config),
                timeout=PER_KEY_TIMEOUT_S,
            )
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            logger.info("[%s] key OK   (%d ms): %s", rid, elapsed_ms, key)
            items.append(ProviderResponseItem(key=key, value=summary))
        except asyncio.TimeoutError:
            elapsed_ms = int((time.monotonic() - t0) * 1000)
            logger.warning(
                "[%s] key TIMEOUT (%d ms): %s", rid, elapsed_ms, key
            )
            items.append(ProviderResponseItem(
                key=key,
                error=f"verifier timed out after {PER_KEY_TIMEOUT_S:.1f}s",
            ))
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

    response = ProviderResponse(response=ProviderResponseBody(items=items))
    if LOG_BODIES:
        _dump_json("ProviderResponse body", rid, response)
    return response
