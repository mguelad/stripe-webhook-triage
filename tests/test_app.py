from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path

from fastapi.testclient import TestClient

from webhook_triage.app import create_app
from webhook_triage.config import Settings

SECRET = "whsec_test_secret"


def stripe_signature(payload: bytes, secret: str = SECRET) -> str:
    timestamp = int(time.time())
    signed_payload = f"{timestamp}.".encode() + payload
    signature = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={signature}"


def event_payload() -> bytes:
    event = {
        "id": "evt_api_test_123",
        "object": "event",
        "api_version": "2025-08-27.basil",
        "created": 1_700_000_000,
        "livemode": False,
        "pending_webhooks": 1,
        "request": {"id": "req_test_123", "idempotency_key": None},
        "type": "payment_intent.succeeded",
        "data": {"object": {"id": "pi_test_123", "object": "payment_intent"}},
    }
    return json.dumps(event, separators=(",", ":")).encode()


def test_valid_and_duplicate_webhook_delivery(tmp_path: Path) -> None:
    settings = Settings(webhook_secret=SECRET, database_path=tmp_path / "triage.db")
    payload = event_payload()
    headers = {
        "content-type": "application/json",
        "stripe-signature": stripe_signature(payload),
    }

    with TestClient(create_app(settings)) as client:
        first = client.post("/webhooks/stripe", content=payload, headers=headers)
        second = client.post("/webhooks/stripe", content=payload, headers=headers)
        summary = client.get("/triage/summary")

    assert first.status_code == 200
    assert first.json()["duplicate"] is False
    assert second.status_code == 200
    assert second.json()["duplicate"] is True
    assert second.json()["delivery_count"] == 2
    assert summary.json()["duplicate_deliveries"] == 1


def test_invalid_signature_is_recorded(tmp_path: Path) -> None:
    settings = Settings(webhook_secret=SECRET, database_path=tmp_path / "triage.db")
    payload = event_payload()

    with TestClient(create_app(settings)) as client:
        response = client.post(
            "/webhooks/stripe",
            content=payload,
            headers={"stripe-signature": stripe_signature(payload, "wrong-secret")},
        )
        attempts = client.get("/attempts")

    assert response.status_code == 400
    assert attempts.json()[0]["error_code"] == "invalid_signature"
    assert attempts.json()[0]["signature_valid"] is False


def test_missing_secret_reports_degraded_health(tmp_path: Path) -> None:
    settings = Settings(webhook_secret="", database_path=tmp_path / "triage.db")

    with TestClient(create_app(settings)) as client:
        response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "degraded"
