"""The vulnerable app refuses to start without explicit acknowledgement."""

from __future__ import annotations

import pytest

from boundless.config import Settings
from boundless.vulnerable.app import ACK_ENV, create_vulnerable_app


def test_refuses_without_acknowledgement(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(ACK_ENV, raising=False)
    with pytest.raises(RuntimeError, match=ACK_ENV):
        create_vulnerable_app(settings)


def test_starts_with_env_acknowledgement(
    settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(ACK_ENV, "true")
    assert create_vulnerable_app(settings) is not None


def test_starts_with_explicit_acknowledgement(settings: Settings) -> None:
    assert create_vulnerable_app(settings, acknowledged=True) is not None


def test_explicit_false_overrides_env(settings: Settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(ACK_ENV, "true")
    with pytest.raises(RuntimeError):
        create_vulnerable_app(settings, acknowledged=False)
