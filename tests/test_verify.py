import pytest

from src.verify import VerificationError, VerifierConfig, _ensure_allowed_registry, _ensure_digest


VALID = "ghcr.io/kse-bd8338bbe006/image-policy-provider@sha256:" + "a" * 64


def test_ensure_digest_accepts_pinned_image():
    assert _ensure_digest(VALID) == "ghcr.io/kse-bd8338bbe006/image-policy-provider"


def test_ensure_digest_rejects_tag():
    with pytest.raises(VerificationError):
        _ensure_digest("ghcr.io/kse-bd8338bbe006/image-policy-provider:latest")


def test_ensure_digest_rejects_short_hash():
    with pytest.raises(VerificationError):
        _ensure_digest("ghcr.io/x@sha256:abc")


def test_registry_allowlist_match_prefix():
    _ensure_allowed_registry("ghcr.io/kse-bd8338bbe006/foo", ["ghcr.io/kse-bd8338bbe006"])


def test_registry_allowlist_rejects_lookalike():
    with pytest.raises(VerificationError):
        _ensure_allowed_registry(
            "ghcr.io/kse-bd8338bbe006-evil/foo", ["ghcr.io/kse-bd8338bbe006"]
        )


def test_config_from_env(monkeypatch):
    monkeypatch.setenv("ALLOWED_REGISTRIES", "ghcr.io/a, ghcr.io/b")
    monkeypatch.setenv("COSIGN_KEY_PATH", "/etc/cosign/cosign.pub")
    cfg = VerifierConfig.from_env()
    assert cfg.allowed_registries == ["ghcr.io/a", "ghcr.io/b"]
    assert cfg.cosign_key_path == "/etc/cosign/cosign.pub"
