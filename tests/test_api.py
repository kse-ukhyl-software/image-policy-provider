from fastapi.testclient import TestClient

from src.main import app


client = TestClient(app)


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_validate_returns_provider_response_shape():
    payload = {
        "apiVersion": "externaldata.gatekeeper.sh/v1beta1",
        "kind": "ProviderRequest",
        "request": {"keys": ["docker.io/library/nginx:latest"]},
    }
    r = client.post("/validate", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "ProviderResponse"
    items = body["response"]["items"]
    assert len(items) == 1
    item = items[0]
    assert item["key"] == "docker.io/library/nginx:latest"
    # Default test config has no cosign trust material configured AND
    # an empty allowlist, so the signature path runs and complains
    # about missing trust material -- exactly what we want students
    # to see in the lab if they haven't set up COSIGN_KEY_PATH or
    # COSIGN_IDENTITY/COSIGN_OIDC_ISSUER.
    assert item["error"]
    assert "trust material" in item["error"] or "cosign" in item["error"].lower()
