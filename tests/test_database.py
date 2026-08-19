from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
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
        "semantic_duplicates": 0,
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


def test_different_event_ids_for_same_object_are_linked(tmp_path: Path) -> None:
    database = Database(tmp_path / "triage.db")
    database.initialize()
    database.record_event(sample_event("evt_first"), "hash-first")

    related = event_response(
        database.record_event(sample_event("evt_second"), "hash-second")
    )

    assert related["duplicate"] is False
    assert related["semantic_duplicate"] is True
    assert related["related_event_id"] == "evt_first"
    assert {finding["code"] for finding in related["findings"]} == {
        "related_event_duplicate"
    }
    assert database.summary()["semantic_duplicates"] == 1


def test_concurrent_redeliveries_are_recorded_atomically(tmp_path: Path) -> None:
    database = Database(tmp_path / "triage.db")
    database.initialize()
    delivery_count = 12

    def record(_: int) -> None:
        database.record_event(sample_event(), "same-hash")

    with ThreadPoolExecutor(max_workers=6) as executor:
        list(executor.map(record, range(delivery_count)))

    stored = database.get_event("evt_test_123")
    assert stored is not None
    assert stored["delivery_count"] == delivery_count
    assert database.summary()["duplicate_deliveries"] == delivery_count - 1
    assert len(database.list_attempts(limit=delivery_count)) == delivery_count


def test_version_01_database_is_upgraded_without_losing_events(tmp_path: Path) -> None:
    database_path = tmp_path / "triage.db"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE webhook_events (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                api_version TEXT,
                object_type TEXT,
                livemode INTEGER NOT NULL,
                stripe_created INTEGER,
                first_received_at TEXT NOT NULL,
                last_received_at TEXT NOT NULL,
                delivery_count INTEGER NOT NULL,
                first_payload_sha256 TEXT NOT NULL,
                last_payload_sha256 TEXT NOT NULL,
                payload_changed INTEGER NOT NULL DEFAULT 0
            );
            INSERT INTO webhook_events VALUES (
                'evt_legacy',
                'payment_intent.succeeded',
                '2025-08-27.basil',
                'payment_intent',
                0,
                1700000000,
                '2026-01-01T00:00:00+00:00',
                '2026-01-01T00:00:00+00:00',
                1,
                'legacy-hash',
                'legacy-hash',
                0
            );
            """
        )

    database = Database(database_path)
    database.initialize()
    stored = event_response(database.get_event("evt_legacy") or {})

    assert stored["event_id"] == "evt_legacy"
    assert stored["object_id"] is None
    assert stored["semantic_duplicate"] is False
    assert stored["related_event_id"] is None


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
