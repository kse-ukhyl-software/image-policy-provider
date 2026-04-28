import pytest

from src.verify import (
    VerificationError,
    VerifierConfig,
    _ensure_allowed_registry,
    _split_repo,
)


VALID_DIGEST = "ghcr.io/kse-bd8338bbe006/image-policy-provider@sha256:" + "a" * 64
VALID_TAG = "ghcr.io/kse-bd8338bbe006/image-policy-provider:v1.0"
BARE_REPO = "ghcr.io/kse-bd8338bbe006/image-policy-provider"


def test_split_repo_digest():
    assert _split_repo(VALID_DIGEST) == "ghcr.io/kse-bd8338bbe006/image-policy-provider"


def test_split_repo_tag():
    assert _split_repo(VALID_TAG) == "ghcr.io/kse-bd8338bbe006/image-policy-provider"


def test_split_repo_bare():
    assert _split_repo(BARE_REPO) == "ghcr.io/kse-bd8338bbe006/image-policy-provider"


def test_split_repo_invalid():
    with pytest.raises(VerificationError):
        _split_repo("@bad@@reference")


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
