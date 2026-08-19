from __future__ import annotations

from pathlib import Path

from webhook_triage.database import Database
from webhook_triage.triage import event_response, summary_findings


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


def test_duplicate_delivery_is_counted(tmp_path: Path) -> None:
    database = Database(tmp_path / "triage.db")
    database.initialize()

    first = database.record_event(sample_event(), "hash-a")
    second = database.record_event(sample_event(), "hash-a")

    assert first["delivery_count"] == 1
    assert second["delivery_count"] == 2
    assert event_response(second)["duplicate"] is True
    assert database.summary() == {
        "unique_events": 1,
        "valid_deliveries": 2,
        "duplicate_deliveries": 1,
        "invalid_deliveries": 0,
        "payload_mismatches": 0,
    }


def test_changed_payload_for_same_event_is_flagged(tmp_path: Path) -> None:
    database = Database(tmp_path / "triage.db")
    database.initialize()
    database.record_event(sample_event(), "hash-a")

    changed = event_response(database.record_event(sample_event(), "hash-b"))

    assert changed["payload_changed"] is True
    assert {finding["code"] for finding in changed["findings"]} == {
        "duplicate_delivery",
        "payload_hash_mismatch",
    }
    assert summary_findings(database.summary())[-1]["severity"] == "critical"


def test_invalid_attempt_and_event_filtering(tmp_path: Path) -> None:
    database = Database(tmp_path / "triage.db")
    database.initialize()
    database.record_invalid_attempt("bad-hash", "invalid_signature")
    database.record_event(sample_event("evt_payment"), "hash-payment")
    other = sample_event("evt_customer")
    other["type"] = "customer.updated"
    database.record_event(other, "hash-customer")

    filtered = database.list_events(event_type="customer.updated")
    attempts = database.list_attempts()

    assert [record["event_id"] for record in filtered] == ["evt_customer"]
    assert database.summary()["invalid_deliveries"] == 1
    assert any(attempt["error_code"] == "invalid_signature" for attempt in attempts)

