from fastapi.testclient import TestClient

from src.main import app


client = TestClient(app)


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_readyz_requires_trust_material(monkeypatch):
    # Default test config has no COSIGN_KEY_PATH or COSIGN_IDENTITY,
    # so the verifier is not actually ready to verify anything.
    r = client.get("/readyz")
    assert r.status_code == 503
    assert "no cosign trust material" in str(r.json())


def test_validate_rejects_image_outside_allowlist():
    payload = {
        "apiVersion": "externaldata.gatekeeper.sh/v1beta1",
        "kind": "ProviderRequest",
        "request": {"keys": ["docker.io/library/nginx:latest"]},
    }
    r = client.post("/validate", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "ProviderResponse"
    # idempotent should be False on a verify provider per OPA's
    # ProviderResponse contract (and Ratify's own implementation).
    assert body["response"]["idempotent"] is False
    item = body["response"]["items"][0]
    assert item["error"]
    # The default test config has no real cosign trust material set up,
    # but the registry allowlist check fires first for non-allowed
    # registries and is the deterministic message we can assert on.
    assert "allowed registry list" in item["error"]


def test_validate_rejects_unknown_kind():
    payload = {
        "apiVersion": "externaldata.gatekeeper.sh/v1beta1",
        "kind": "WeirdRequest",
        "request": {"keys": []},
    }
    r = client.post("/validate", json=payload)
    assert r.status_code == 400
