from fastapi.testclient import TestClient

from src.main import app


client = TestClient(app)


def test_healthz():
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_validate_rejects_tagged_image():
    payload = {
        "apiVersion": "externaldata.gatekeeper.sh/v1beta1",
        "kind": "ProviderRequest",
        "request": {"keys": ["ghcr.io/kse-bd8338bbe006/x:latest"]},
    }
    r = client.post("/validate", json=payload)
    assert r.status_code == 200
    body = r.json()
    assert body["kind"] == "ProviderResponse"
    item = body["response"]["items"][0]
    assert item["error"]
    assert "digest" in item["error"]
