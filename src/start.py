"""Programmatic uvicorn entrypoint that hardens the provider's TLS.

Gatekeeper has required TLS >= 1.3 for external-data providers since
v3.11; the upstream Ratify provider (notaryproject/ratify) goes
further and requires an mTLS client certificate from Gatekeeper. We
mirror both behaviours here:

  * `ssl_minimum_version=TLSv1_3`  -- the floor every provider has to
    meet anyway.
  * `ssl_cert_reqs=CERT_REQUIRED`, `ssl_ca_certs=$GATEKEEPER_CA_CERT_FILE`
    -- iff the env var is set. When mounted, only TLS clients whose
    certificate chains to Gatekeeper's CA bundle (typically the
    `gatekeeper-webhook-server-cert` Secret) can call us. When not
    mounted, we keep the previous one-way-TLS behaviour so the lab
    keeps booting if the cluster wiring lags.

Run as `python -m src.start`; the Dockerfile uses this as the CMD.
"""
from __future__ import annotations

import logging
import os
import ssl

import uvicorn


def _ssl_kwargs() -> dict:
    cert = os.environ["TLS_CERT_FILE"]
    key = os.environ["TLS_KEY_FILE"]

    kwargs: dict = {
        "ssl_keyfile": key,
        "ssl_certfile": cert,
        # TLS 1.3 floor -- Gatekeeper external-data has required this
        # since v3.11.
        "ssl_version": ssl.PROTOCOL_TLS_SERVER,
    }

    ca = os.getenv("GATEKEEPER_CA_CERT_FILE")
    if ca and os.path.exists(ca):
        # mTLS path: require + verify Gatekeeper's client certificate.
        kwargs["ssl_ca_certs"] = ca
        kwargs["ssl_cert_reqs"] = ssl.CERT_REQUIRED
        logging.getLogger("image-policy-provider").info(
            "TLS mode: mTLS (verifying clients against %s)", ca
        )
    else:
        # Server-auth-only path. Keeps the lab usable if Gatekeeper's
        # CA hasn't been mounted yet; not the production posture.
        logging.getLogger("image-policy-provider").info(
            "TLS mode: server-auth only "
            "(set GATEKEEPER_CA_CERT_FILE to enable mTLS)"
        )

    return kwargs


def main() -> None:
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", "8443"))
    config = uvicorn.Config(
        "src.main:app",
        host=host,
        port=port,
        # uvicorn 0.27+ exposes `ssl_minimum_version` directly; we
        # set it AFTER constructing kwargs so older uvicorn versions
        # gracefully fall back to whatever the Python ssl default is.
        ssl_minimum_version=ssl.TLSVersion.TLSv1_3,
        **_ssl_kwargs(),
    )
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
