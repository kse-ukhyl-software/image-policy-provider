"""Pydantic models for the OPA Gatekeeper External Data Provider API.

The schema mirrors the upstream contract described in
https://open-policy-agent.github.io/gatekeeper/website/docs/externaldata
"""
from __future__ import annotations

from typing import Any, List, Optional

from pydantic import BaseModel, Field


class ProviderRequestBody(BaseModel):
    keys: List[str] = Field(
        ...,
        description="Image references (preferably digests) to verify.",
    )


class ProviderRequest(BaseModel):
    apiVersion: str = "externaldata.gatekeeper.sh/v1beta1"
    kind: str = "ProviderRequest"
    request: ProviderRequestBody


class ProviderResponseItem(BaseModel):
    key: str
    value: Any = None
    error: Optional[str] = None


class ProviderResponseBody(BaseModel):
    # Per OPA's externaldata.ProviderResponse contract, `idempotent`
    # is meaningful only for *mutation* providers ("Applies to mutation
    # only and must be true for mutation"). A verification provider
    # like ours should leave it false; Ratify does the same -- it
    # sets idempotent to the mutation flag, never hard-codes true.
    idempotent: bool = False
    items: List[ProviderResponseItem] = Field(default_factory=list)
    systemError: Optional[str] = None


class ProviderResponse(BaseModel):
    apiVersion: str = "externaldata.gatekeeper.sh/v1beta1"
    kind: str = "ProviderResponse"
    response: ProviderResponseBody
