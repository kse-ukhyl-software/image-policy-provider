"""FastAPI entrypoint for the Gatekeeper external-data provider."""
from __future__ import annotations

import logging
import os

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


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


@app.post("/validate", response_model=ProviderResponse)
def validate(request: ProviderRequest) -> ProviderResponse:
    if request.kind != "ProviderRequest":
        raise HTTPException(status_code=400, detail=f"unexpected kind {request.kind!r}")

    items: list[ProviderResponseItem] = []
    for key in request.request.keys:
        try:
            summary = verify_image(key, _config)
            items.append(ProviderResponseItem(key=key, value=summary))
        except VerificationError as exc:
            logger.warning("rejecting %s: %s", key, exc)
            items.append(ProviderResponseItem(key=key, error=str(exc)))
        except Exception as exc:  # noqa: BLE001 - last-resort guard
            logger.exception("unexpected error verifying %s", key)
            items.append(ProviderResponseItem(key=key, error=f"internal error: {exc}"))

    return ProviderResponse(response=ProviderResponseBody(items=items))
