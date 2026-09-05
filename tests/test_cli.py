from __future__ import annotations

import json
import sys
from pathlib import Path

from webhook_triage.cli import main
from webhook_triage.database import Database


def sample_event(event_id: str = "evt_test_123") -> dict[str, object]:
    return {
        "id": event_id,
        "object": "event",
        "api_version": "2025-08-27.basil",
        "created": 1_700_000_000,
        "livemode": False,
        "type": "payment_intent.succeeded",
        "data": {"object": {"id": "pi_test_123", "object": "payment_intent"}},
    }


def run_reset(
    monkeypatch,
    database_path: Path,
    *,
    confirmation: str | None = None,
    assume_yes: bool = False,
) -> None:
    arguments = ["webhook-triage", "--database", str(database_path), "reset"]
    if assume_yes:
        arguments.append("--yes")
    monkeypatch.setattr(sys, "argv", arguments)
    if confirmation is not None:
        monkeypatch.setattr("builtins.input", lambda _: confirmation)
    main()


def test_reset_requires_confirmation(
    monkeypatch, capsys, tmp_path: Path
) -> None:
    database_path = tmp_path / "triage.db"
    database = Database(database_path)
    database.initialize()
    database.record_event(sample_event(), "hash")

    run_reset(monkeypatch, database_path, confirmation="no")

    assert capsys.readouterr().out == "Reset cancelled.\n"
    assert database.summary()["unique_events"] == 1


def test_reset_clears_results_after_confirmation(
    monkeypatch, capsys, tmp_path: Path
) -> None:
    database_path = tmp_path / "triage.db"
    database = Database(database_path)
    database.initialize()
    database.record_event(sample_event(), "hash")

    run_reset(monkeypatch, database_path, confirmation="yes")

    result = json.loads(capsys.readouterr().out)
    assert result == {
        "cleared_attempts": 1,
        "cleared_events": 1,
        "database": str(database_path),
    }
    assert database.summary()["unique_events"] == 0


def test_reset_yes_skips_confirmation(monkeypatch, capsys, tmp_path: Path) -> None:
    database_path = tmp_path / "triage.db"
    database = Database(database_path)
    database.initialize()
    database.record_invalid_attempt("bad-hash", "invalid_signature")

    monkeypatch.setattr(
        "builtins.input",
        lambda _: (_ for _ in ()).throw(AssertionError("unexpected prompt")),
    )
    run_reset(monkeypatch, database_path, assume_yes=True)

    result = json.loads(capsys.readouterr().out)
    assert result["cleared_attempts"] == 1
    assert result["cleared_events"] == 0
