"""Image signature verification.

Two layers:
1. Cheap structural checks (digest pinning, registry allowlist).
2. Cosign signature verification, delegated to the `cosign` CLI which is
   installed inside the container image. We shell out instead of binding
   to a Python library so the verification semantics match the canonical
   Sigstore implementation byte-for-byte.

The verifier is intentionally small. Anything that cannot be answered with
the local trust material is treated as a failure -- Gatekeeper denies by
default when the provider returns an error for a key.
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)

DIGEST_RE = re.compile(r"^(?P<repo>[^@]+)@sha256:[a-f0-9]{64}$")


@dataclass(frozen=True)
class VerifierConfig:
    allowed_registries: List[str]
    cosign_key_path: Optional[str]
    cosign_identity: Optional[str]
    cosign_oidc_issuer: Optional[str]
    cosign_binary: str = "cosign"

    @classmethod
    def from_env(cls) -> "VerifierConfig":
        allowed = os.getenv("ALLOWED_REGISTRIES", "ghcr.io/kse-bd8338bbe006")
        return cls(
            allowed_registries=[r.strip() for r in allowed.split(",") if r.strip()],
            cosign_key_path=os.getenv("COSIGN_KEY_PATH") or None,
            cosign_identity=os.getenv("COSIGN_IDENTITY") or None,
            cosign_oidc_issuer=os.getenv("COSIGN_OIDC_ISSUER") or None,
            cosign_binary=os.getenv("COSIGN_BINARY", "cosign"),
        )


class VerificationError(Exception):
    """Raised when an image fails any verification step."""


def _ensure_digest(image: str) -> str:
    match = DIGEST_RE.match(image)
    if not match:
        raise VerificationError(
            f"image {image!r} is not pinned to a digest (expected repo@sha256:<64hex>)"
        )
    return match.group("repo")


def _ensure_allowed_registry(repo: str, allowed: List[str]) -> None:
    if not any(repo == prefix or repo.startswith(prefix + "/") for prefix in allowed):
        raise VerificationError(
            f"image repository {repo!r} is not in the allowed registry list {allowed}"
        )


def _run_cosign_verify(image: str, cfg: VerifierConfig) -> None:
    if shutil.which(cfg.cosign_binary) is None:
        raise VerificationError(f"cosign binary {cfg.cosign_binary!r} not found in PATH")

    cmd = [cfg.cosign_binary, "verify", "--output", "json"]
    if cfg.cosign_key_path:
        cmd += ["--key", cfg.cosign_key_path]
    elif cfg.cosign_identity and cfg.cosign_oidc_issuer:
        cmd += [
            "--certificate-identity", cfg.cosign_identity,
            "--certificate-oidc-issuer", cfg.cosign_oidc_issuer,
        ]
    else:
        raise VerificationError(
            "no cosign trust material configured (set COSIGN_KEY_PATH or "
            "COSIGN_IDENTITY + COSIGN_OIDC_ISSUER)"
        )
    cmd.append(image)

    # Logged at DEBUG so the per-image INFO line in main.py stays the
    # primary teaching artifact; flip LOG_LEVEL=DEBUG to see the
    # actual cosign command line that ran.
    logger.debug("running: %s", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        raise VerificationError(
            f"cosign verify failed: {proc.stderr.strip() or proc.stdout.strip()}"
        )


def verify_image(image: str, cfg: VerifierConfig) -> str:
    """Verify a single image reference. Returns a short success summary."""
    repo = _ensure_digest(image)
    _ensure_allowed_registry(repo, cfg.allowed_registries)
    _run_cosign_verify(image, cfg)
    return "verified"
