from __future__ import annotations

from pathlib import Path

import pytest

from webhook_triage.config import Settings


def test_settings_are_loaded_from_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    database_path = tmp_path / "configured.db"
    monkeypatch.setenv("STRIPE_WEBHOOK_SECRET", "whsec_configured")
    monkeypatch.setenv("TRIAGE_DATABASE_PATH", str(database_path))
    monkeypatch.setenv("TRIAGE_DIAGNOSTIC_TOKEN", "diagnostic-token")
    monkeypatch.setenv("STRIPE_SIGNATURE_TOLERANCE_SECONDS", "120")

    settings = Settings.from_env()

    assert settings.webhook_secret == "whsec_configured"
    assert settings.database_path == database_path
    assert settings.diagnostic_token == "diagnostic-token"
    assert settings.signature_tolerance_seconds == 120


@pytest.mark.parametrize("value", ["zero", "0", "-1"])
def test_signature_tolerance_must_be_a_positive_integer(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setenv("STRIPE_SIGNATURE_TOLERANCE_SECONDS", value)

    with pytest.raises(ValueError, match="must be"):
        Settings.from_env()
