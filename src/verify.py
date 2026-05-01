"""Image signature verification.

The trust gate is the **Cosign signature**, not digest pinning. We
shell out to the `cosign` CLI baked into the container image; an
unsigned image fails with a clear "no matching signatures" message
from cosign itself, which is the security property students are
meant to internalize.

Why shell out to cosign rather than use sigstore-python? cosign is
the canonical Sigstore implementation, identical semantics to what
GitHub Actions's `actions/attest-build-provenance` (and Sigstore's
own tooling) emits. sigstore-python is a great SDK for *artifact*
signatures but does not currently understand OCI container-image
signature discovery on its own; reimplementing that here would just
diverge from cosign without buying us anything.

Two cheap pre-checks run before cosign:
  * Registry allowlist -- repo must start with one of the prefixes in
    `ALLOWED_REGISTRIES`. Refuses to even look up signatures for
    images outside the trust boundary.
  * Digest-pin warning -- tag-only refs are mutable, so we *log*
    when one slips through, but we let cosign run anyway. cosign
    resolves the tag to a digest internally; if no signature is
    attached, cosign returns "no matching signatures" and that
    becomes the rejection reason. This is what students should see
    when they try to deploy a random `nginx:latest`.

Anything cosign cannot prove is treated as a failure; Gatekeeper
denies the admission for any key whose `error` field is non-empty.
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
TAG_RE = re.compile(r"^(?P<repo>[^@:]+)(?::[^@]+)?$")


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


def _split_repo(image: str) -> str:
    """Return the repository portion of an image reference.

    Accepts both digest (`repo@sha256:...`) and tag (`repo:tag` or
    just `repo`) forms. Raises if neither matches.
    """
    m = DIGEST_RE.match(image)
    if m:
        return m.group("repo")
    m = TAG_RE.match(image)
    if m:
        return m.group("repo")
    raise VerificationError(f"image {image!r} is not a valid image reference")


def _ensure_allowed_registry(repo: str, allowed: List[str]) -> None:
    if not any(repo == prefix or repo.startswith(prefix + "/") for prefix in allowed):
        raise VerificationError(
            f"image repository {repo!r} is not in the allowed registry list {allowed}"
        )


def _run_cosign_verify(image: str, cfg: VerifierConfig) -> None:
    if shutil.which(cfg.cosign_binary) is None:
        raise VerificationError(f"cosign binary {cfg.cosign_binary!r} not found in PATH")

    cmd = [cfg.cosign_binary, "verify", "--output", "json"]
    if cfg.cosign_identity and cfg.cosign_oidc_issuer:
        cmd += [
            "--certificate-identity", cfg.cosign_identity,
            "--certificate-oidc-issuer", cfg.cosign_oidc_issuer,
        ]
    elif cfg.cosign_key_path:
        cmd += ["--key", cfg.cosign_key_path]
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
        # cosign's own message ("no matching signatures", "certificate
        # identity does not match expected", ...) is exactly the kind
        # of reason students should see -- pass it through verbatim.
        raise VerificationError(
            f"cosign verify failed: {proc.stderr.strip() or proc.stdout.strip()}"
        )


def verify_image(image: str, cfg: VerifierConfig) -> str:
    """Verify a single image reference. Returns a short success summary."""
    repo = _split_repo(image)
    _ensure_allowed_registry(repo, cfg.allowed_registries)
    if not DIGEST_RE.match(image):
        # Tag-style refs are accepted but flagged. cosign resolves the
        # tag to a digest; the signature lookup happens against the
        # resolved digest either way.
        logger.info("image %s is not pinned to a digest (mutable tag)", image)
    _run_cosign_verify(image, cfg)
    return "verified"
