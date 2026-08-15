"""The "hardened" endpoint's single-pass ../ strip is not a boundary check."""

from __future__ import annotations

from fastapi.testclient import TestClient

from boundless.fixtures import DEMO_SENTINEL
from helpers import auth

SENTINEL_VALUE = DEMO_SENTINEL.split("=", 1)[1]


def test_dotdotdot_slash_collapses_back(vulnerable_client: TestClient) -> None:
    # `....//....//` -> one strip of `../` -> `../../` -> reaches the config directory.
    response = vulnerable_client.get(
        "/documents/hardened?name=....//....//config/integration.key",
        headers=auth("uma-aurora"),
    )
    assert response.status_code == 200
    assert SENTINEL_VALUE in response.text


def test_percent_encoded_slips_past(vulnerable_client: TestClient) -> None:
    # Percent-encoded `../` carries no literal `../`, so the pre-decode strip does nothing.
    response = vulnerable_client.get(
        "/documents/hardened?name=%2e%2e%2f%2e%2e%2fconfig%2fintegration.key",
        headers=auth("uma-aurora"),
    )
    assert response.status_code == 200
    assert SENTINEL_VALUE in response.text


def test_sanitized_value_is_surfaced(vulnerable_client: TestClient) -> None:
    response = vulnerable_client.get(
        "/documents/hardened?name=....//....//config/integration.key",
        headers=auth("uma-aurora"),
    )
    assert response.status_code == 200
    # The strip collapsed `....//....//` back into a working `../../` traversal.
    assert response.headers.get("x-boundless-sanitized") == "../../config/integration.key"


def test_plain_literal_traversal_is_stripped(vulnerable_client: TestClient) -> None:
    # The naive literal `../../` IS removed by the single-pass strip, so this form does
    # not reach the target. That the sanitizer stops the obvious payload is exactly why
    # the `....//` and percent-encoded bypasses above are needed.
    response = vulnerable_client.get(
        "/documents/hardened?name=../../config/integration.key",
        headers=auth("uma-aurora"),
    )
    assert response.status_code == 404
