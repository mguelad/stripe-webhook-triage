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
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS webhook_events (
                    event_id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    api_version TEXT,
                    object_type TEXT,
                    object_id TEXT,
                    livemode INTEGER NOT NULL CHECK (livemode IN (0, 1)),
                    stripe_created INTEGER,
                    first_received_at TEXT NOT NULL,
                    last_received_at TEXT NOT NULL,
                    delivery_count INTEGER NOT NULL CHECK (delivery_count >= 1),
                    first_payload_sha256 TEXT NOT NULL,
                    last_payload_sha256 TEXT NOT NULL,
                    payload_changed INTEGER NOT NULL DEFAULT 0
                        CHECK (payload_changed IN (0, 1)),
                    semantic_duplicate INTEGER NOT NULL DEFAULT 0
                        CHECK (semantic_duplicate IN (0, 1)),
                    related_event_id TEXT
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

            # Upgrade databases created by version 0.1 without discarding their records.
            columns = {
                str(row["name"])
                for row in connection.execute("PRAGMA table_info(webhook_events)")
            }
            if "object_id" not in columns:
                connection.execute("ALTER TABLE webhook_events ADD COLUMN object_id TEXT")
            if "semantic_duplicate" not in columns:
                connection.execute(
                    """
                    ALTER TABLE webhook_events
                    ADD COLUMN semantic_duplicate INTEGER NOT NULL DEFAULT 0
                    CHECK (semantic_duplicate IN (0, 1))
                    """
                )
            if "related_event_id" not in columns:
                connection.execute(
                    "ALTER TABLE webhook_events ADD COLUMN related_event_id TEXT"
                )

            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_webhook_events_object
                ON webhook_events(event_type, object_id)
                """
            )
            connection.execute("PRAGMA user_version = 2")

    def clear(self) -> dict[str, int]:
        """Remove stored triage results while preserving the database schema."""
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            event_count = int(
                connection.execute("SELECT COUNT(*) FROM webhook_events").fetchone()[0]
            )
            attempt_count = int(
                connection.execute("SELECT COUNT(*) FROM delivery_attempts").fetchone()[0]
            )
            connection.execute("DELETE FROM delivery_attempts")
            connection.execute("DELETE FROM webhook_events")
            connection.execute(
                "DELETE FROM sqlite_sequence WHERE name = 'delivery_attempts'"
            )

        return {
            "cleared_events": event_count,
            "cleared_attempts": attempt_count,
        }

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
        object_id_value = object_data.get("id")
        object_id = str(object_id_value) if object_id_value else None
        now = _utc_now()

        with self._connect() as connection:
            # Lock before checking for an existing ID so two concurrent deliveries cannot
            # both try to insert the same event.
            connection.execute("BEGIN IMMEDIATE")
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
                related_event_id = None
                if object_id:
                    related = connection.execute(
                        """
                        SELECT event_id
                        FROM webhook_events
                        WHERE event_type = ? AND object_id = ?
                        ORDER BY first_received_at ASC, event_id ASC
                        LIMIT 1
                        """,
                        (event_type, object_id),
                    ).fetchone()
                    if related:
                        related_event_id = str(related["event_id"])

                connection.execute(
                    """
                    INSERT INTO webhook_events (
                        event_id,
                        event_type,
                        api_version,
                        object_type,
                        object_id,
                        livemode,
                        stripe_created,
                        first_received_at,
                        last_received_at,
                        delivery_count,
                        first_payload_sha256,
                        last_payload_sha256,
                        payload_changed,
                        semantic_duplicate,
                        related_event_id
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, 0, ?, ?)
                    """,
                    (
                        event_id,
                        event_type,
                        event_data.get("api_version"),
                        object_data.get("object"),
                        object_id,
                        int(bool(event_data.get("livemode"))),
                        event_data.get("created"),
                        now,
                        now,
                        payload_sha256,
                        payload_sha256,
                        int(related_event_id is not None),
                        related_event_id,
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
                    COALESCE(SUM(payload_changed), 0) AS payload_mismatches,
                    COALESCE(SUM(semantic_duplicate), 0) AS semantic_duplicates
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
            "semantic_duplicates": int(event_totals["semantic_duplicates"]),
        }
