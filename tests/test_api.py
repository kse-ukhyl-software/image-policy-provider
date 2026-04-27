from fastapi.testclient import TestClient

from src.main import app


client = TestClient(app)


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


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
    item = body["response"]["items"][0]
    assert item["error"]
    # The default test config has no real cosign trust material set up,
    # but the registry allowlist check fires first for non-allowed
    # registries and is the deterministic message we can assert on.
    assert "allowed registry list" in item["error"]
