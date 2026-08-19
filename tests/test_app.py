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
DIAGNOSTIC_TOKEN = "diagnostic-test-token"
AUTH_HEADERS = {"authorization": f"Bearer {DIAGNOSTIC_TOKEN}"}


def stripe_signature(payload: bytes, secret: str = SECRET) -> str:
    timestamp = int(time.time())
    signed_payload = f"{timestamp}.".encode() + payload
    signature = hmac.new(secret.encode(), signed_payload, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={signature}"


def event_payload(
    *,
    event_id: str = "evt_api_test_123",
    object_id: str = "pi_test_123",
    event_type: str = "payment_intent.succeeded",
) -> bytes:
    event = {
        "id": event_id,
        "object": "event",
        "api_version": "2025-08-27.basil",
        "created": 1_700_000_000,
        "livemode": False,
        "pending_webhooks": 1,
        "request": {"id": "req_test_123", "idempotency_key": None},
        "type": event_type,
        "data": {"object": {"id": object_id, "object": "payment_intent"}},
    }
    return json.dumps(event, separators=(",", ":")).encode()


def settings(tmp_path: Path, *, secret: str = SECRET, token: str = DIAGNOSTIC_TOKEN) -> Settings:
    return Settings(
        webhook_secret=secret,
        database_path=tmp_path / "triage.db",
        diagnostic_token=token,
    )


def test_valid_and_duplicate_webhook_delivery(tmp_path: Path) -> None:
    runtime_settings = settings(tmp_path)
    payload = event_payload()
    headers = {
        "content-type": "application/json",
        "stripe-signature": stripe_signature(payload),
    }

    with TestClient(create_app(runtime_settings)) as client:
        first = client.post("/webhooks/stripe", content=payload, headers=headers)
        second = client.post("/webhooks/stripe", content=payload, headers=headers)
        summary = client.get("/triage/summary", headers=AUTH_HEADERS)

    assert first.status_code == 200
    assert first.json()["duplicate"] is False
    assert second.status_code == 200
    assert second.json()["duplicate"] is True
    assert second.json()["semantic_duplicate"] is False
    assert second.json()["delivery_count"] == 2
    assert summary.json()["duplicate_deliveries"] == 1


def test_different_event_ids_for_same_object_are_linked(tmp_path: Path) -> None:
    runtime_settings = settings(tmp_path)
    first_payload = event_payload(event_id="evt_first")
    second_payload = event_payload(event_id="evt_second")

    with TestClient(create_app(runtime_settings)) as client:
        first = client.post(
            "/webhooks/stripe",
            content=first_payload,
            headers={"stripe-signature": stripe_signature(first_payload)},
        )
        second = client.post(
            "/webhooks/stripe",
            content=second_payload,
            headers={"stripe-signature": stripe_signature(second_payload)},
        )
        summary = client.get("/triage/summary", headers=AUTH_HEADERS)

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["duplicate"] is False
    assert second.json()["semantic_duplicate"] is True
    assert second.json()["related_event_id"] == "evt_first"
    assert second.json()["findings"][0]["code"] == "related_event_duplicate"
    assert summary.json()["semantic_duplicates"] == 1


def test_invalid_signature_is_recorded(tmp_path: Path) -> None:
    runtime_settings = settings(tmp_path)
    payload = event_payload()

    with TestClient(create_app(runtime_settings)) as client:
        response = client.post(
            "/webhooks/stripe",
            content=payload,
            headers={"stripe-signature": stripe_signature(payload, "wrong-secret")},
        )
        attempts = client.get("/attempts", headers=AUTH_HEADERS)

    assert response.status_code == 400
    assert attempts.json()[0]["error_code"] == "invalid_signature"
    assert attempts.json()[0]["signature_valid"] is False


def test_missing_signature_and_invalid_payload_are_recorded(tmp_path: Path) -> None:
    runtime_settings = settings(tmp_path)
    valid_payload = event_payload()
    invalid_payload = b"not-json"

    with TestClient(create_app(runtime_settings)) as client:
        missing_signature = client.post("/webhooks/stripe", content=valid_payload)
        invalid_json = client.post(
            "/webhooks/stripe",
            content=invalid_payload,
            headers={"stripe-signature": stripe_signature(invalid_payload)},
        )
        attempts = client.get("/attempts", headers=AUTH_HEADERS)

    assert missing_signature.status_code == 400
    assert invalid_json.status_code == 400
    assert {attempt["error_code"] for attempt in attempts.json()} == {
        "missing_signature",
        "invalid_payload",
    }


def test_diagnostic_routes_require_bearer_token(tmp_path: Path) -> None:
    runtime_settings = settings(tmp_path)

    with TestClient(create_app(runtime_settings)) as client:
        missing = client.get("/events")
        wrong = client.get("/events", headers={"authorization": "Bearer wrong-token"})
        accepted = client.get("/events", headers=AUTH_HEADERS)
        health = client.get("/health")

    assert missing.status_code == 401
    assert wrong.status_code == 401
    assert accepted.status_code == 200
    assert health.json() == {
        "status": "ok",
        "webhook_secret_configured": True,
        "diagnostic_auth_configured": True,
    }


def test_event_lookup_returns_404(tmp_path: Path) -> None:
    runtime_settings = settings(tmp_path)

    with TestClient(create_app(runtime_settings)) as client:
        response = client.get("/events/evt_missing", headers=AUTH_HEADERS)

    assert response.status_code == 404


def test_missing_secret_reports_degraded_health(tmp_path: Path) -> None:
    runtime_settings = settings(tmp_path, secret="")

    with TestClient(create_app(runtime_settings)) as client:
        health = client.get("/health")
        webhook = client.post("/webhooks/stripe", content=event_payload())

    assert health.status_code == 200
    assert health.json()["status"] == "degraded"
    assert webhook.status_code == 503


def test_missing_diagnostic_token_disables_diagnostic_routes(tmp_path: Path) -> None:
    runtime_settings = settings(tmp_path, token="")

    with TestClient(create_app(runtime_settings)) as client:
        health = client.get("/health")
        events = client.get("/events", headers=AUTH_HEADERS)

    assert health.json()["status"] == "degraded"
    assert health.json()["diagnostic_auth_configured"] is False
    assert events.status_code == 503
