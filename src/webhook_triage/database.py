"""SQLite persistence for webhook events and delivery attempts."""

from __future__ import annotations

import sqlite3
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _mapping(value: Any) -> Mapping[str, Any]:
    if hasattr(value, "to_dict_recursive"):
        return value.to_dict_recursive()
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, Mapping):
        return value
    return {}


class Database:
    """Thin repository layer that keeps SQL outside the HTTP handlers."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)

    def _connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS webhook_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    api_version TEXT,
                    object_type TEXT,
                    livemode INTEGER NOT NULL CHECK (livemode IN (0, 1)),
                    stripe_created INTEGER,
                    first_received_at TEXT NOT NULL,
                    last_received_at TEXT NOT NULL,
                    delivery_count INTEGER NOT NULL CHECK (delivery_count >= 1),
                    first_payload_sha256 TEXT NOT NULL,
                    last_payload_sha256 TEXT NOT NULL,
                    payload_changed INTEGER NOT NULL DEFAULT 0
                        CHECK (payload_changed IN (0, 1))
                );

                CREATE INDEX IF NOT EXISTS idx_webhook_events_type
                    ON webhook_events(event_type);
                CREATE INDEX IF NOT EXISTS idx_webhook_events_last_received
                    ON webhook_events(last_received_at DESC);

                CREATE TABLE IF NOT EXISTS delivery_attempts (
                    attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT,
                    received_at TEXT NOT NULL,
                    signature_valid INTEGER NOT NULL CHECK (signature_valid IN (0, 1)),
                    outcome TEXT NOT NULL,
                    error_code TEXT,
                    payload_sha256 TEXT NOT NULL,
                    FOREIGN KEY (event_id) REFERENCES webhook_events(event_id)
                );

                CREATE INDEX IF NOT EXISTS idx_delivery_attempts_received
                    ON delivery_attempts(received_at DESC);
                CREATE INDEX IF NOT EXISTS idx_delivery_attempts_event
                    ON delivery_attempts(event_id);
                """
            )

    def record_invalid_attempt(self, payload_sha256: str, error_code: str) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO delivery_attempts (
                    event_id, received_at, signature_valid, outcome, error_code, payload_sha256
                ) VALUES (NULL, ?, 0, 'rejected', ?, ?)
                """,
                (_utc_now(), error_code, payload_sha256),
            )

    def record_event(self, event: Any, payload_sha256: str) -> dict[str, Any]:
        event_data = _mapping(event)
        object_data = _mapping(_mapping(event_data.get("data")).get("object"))
        event_id = str(event_data["id"])
        event_type = str(event_data["type"])
        now = _utc_now()

        with self._connect() as connection:
            existing = connection.execute(
                """
                SELECT delivery_count, first_payload_sha256, payload_changed
                FROM webhook_events
                WHERE event_id = ?
                """,
                (event_id,),
            ).fetchone()

            if existing:
                payload_changed = bool(existing["payload_changed"]) or (
                    existing["first_payload_sha256"] != payload_sha256
                )
                connection.execute(
                    """
                    UPDATE webhook_events
                    SET last_received_at = ?,
                        delivery_count = delivery_count + 1,
                        last_payload_sha256 = ?,
                        payload_changed = ?
                    WHERE event_id = ?
                    """,
                    (now, payload_sha256, int(payload_changed), event_id),
                )
                outcome = "duplicate"
            else:
                connection.execute(
                    """
                    INSERT INTO webhook_events (
                        event_id,
                        event_type,
                        api_version,
                        object_type,
                        livemode,
                        stripe_created,
                        first_received_at,
                        last_received_at,
                        delivery_count,
                        first_payload_sha256,
                        last_payload_sha256,
                        payload_changed
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 0)
                    """,
                    (
                        event_id,
                        event_type,
                        event_data.get("api_version"),
                        object_data.get("object"),
                        int(bool(event_data.get("livemode"))),
                        event_data.get("created"),
                        now,
                        now,
                        payload_sha256,
                        payload_sha256,
                    ),
                )
                outcome = "accepted"

            connection.execute(
                """
                INSERT INTO delivery_attempts (
                    event_id, received_at, signature_valid, outcome, error_code, payload_sha256
                ) VALUES (?, ?, 1, ?, NULL, ?)
                """,
                (event_id, now, outcome, payload_sha256),
            )

            row = connection.execute(
                "SELECT * FROM webhook_events WHERE event_id = ?", (event_id,)
            ).fetchone()

        if row is None:  # Defensive: the INSERT or UPDATE above must create a row.
            raise RuntimeError("Event was not persisted")
        return dict(row)

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM webhook_events WHERE event_id = ?", (event_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_events(
        self, *, limit: int = 50, event_type: str | None = None
    ) -> list[dict[str, Any]]:
        with self._connect() as connection:
            if event_type:
                rows = connection.execute(
                    """
                    SELECT * FROM webhook_events
                    WHERE event_type = ?
                    ORDER BY last_received_at DESC
                    LIMIT ?
                    """,
                    (event_type, limit),
                ).fetchall()
            else:
                rows = connection.execute(
                    """
                    SELECT * FROM webhook_events
                    ORDER BY last_received_at DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        return [dict(row) for row in rows]

    def list_attempts(self, *, limit: int = 50) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM delivery_attempts
                ORDER BY received_at DESC, attempt_id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def summary(self) -> dict[str, int]:
        with self._connect() as connection:
            event_totals = connection.execute(
                """
                SELECT
                    COUNT(*) AS unique_events,
                    COALESCE(SUM(delivery_count), 0) AS valid_deliveries,
                    COALESCE(SUM(delivery_count - 1), 0) AS duplicate_deliveries,
                    COALESCE(SUM(payload_changed), 0) AS payload_mismatches
                FROM webhook_events
                """
            ).fetchone()
            invalid_total = connection.execute(
                """
                SELECT COUNT(*) AS invalid_deliveries
                FROM delivery_attempts
                WHERE signature_valid = 0
                """
            ).fetchone()

        return {
            "unique_events": int(event_totals["unique_events"]),
            "valid_deliveries": int(event_totals["valid_deliveries"]),
            "duplicate_deliveries": int(event_totals["duplicate_deliveries"]),
            "invalid_deliveries": int(invalid_total["invalid_deliveries"]),
            "payload_mismatches": int(event_totals["payload_mismatches"]),
        }
