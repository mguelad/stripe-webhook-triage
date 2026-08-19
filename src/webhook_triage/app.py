"""FastAPI application for Stripe webhook triage."""

from __future__ import annotations

import hashlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Query, Request
from stripe import SignatureVerificationError, Webhook

from webhook_triage.config import Settings
from webhook_triage.database import Database
from webhook_triage.models import (
    DeliveryAttempt,
    EventRecord,
    Health,
    Summary,
    WebhookAcknowledgement,
)
from webhook_triage.triage import event_response, summary_findings


def create_app(settings: Settings | None = None) -> FastAPI:
    runtime_settings = settings or Settings.from_env()
    database = Database(runtime_settings.database_path)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        database.initialize()
        yield

    app = FastAPI(
        title="Stripe Webhook Triage Tool",
        version="0.1.0",
        description="Receive, verify, and diagnose Stripe webhook deliveries.",
        lifespan=lifespan,
    )

    @app.get("/health", response_model=Health)
    async def health() -> dict[str, object]:
        configured = bool(runtime_settings.webhook_secret)
        return {
            "status": "ok" if configured else "degraded",
            "webhook_secret_configured": configured,
            "database_path": str(runtime_settings.database_path),
        }

    @app.post("/webhooks/stripe", response_model=WebhookAcknowledgement)
    async def receive_webhook(request: Request) -> dict[str, object]:
        payload = await request.body()
        payload_sha256 = hashlib.sha256(payload).hexdigest()

        if not runtime_settings.webhook_secret:
            database.record_invalid_attempt(payload_sha256, "endpoint_not_configured")
            raise HTTPException(status_code=503, detail="Webhook signing secret is not configured")

        signature = request.headers.get("stripe-signature")
        if not signature:
            database.record_invalid_attempt(payload_sha256, "missing_signature")
            raise HTTPException(status_code=400, detail="Missing Stripe-Signature header")

        try:
            event = Webhook.construct_event(
                payload,
                signature,
                runtime_settings.webhook_secret,
                tolerance=runtime_settings.signature_tolerance_seconds,
            )
        except ValueError as exc:
            database.record_invalid_attempt(payload_sha256, "invalid_payload")
            raise HTTPException(status_code=400, detail="Invalid webhook payload") from exc
        except SignatureVerificationError as exc:
            database.record_invalid_attempt(payload_sha256, "invalid_signature")
            raise HTTPException(status_code=400, detail="Invalid webhook signature") from exc

        record = event_response(database.record_event(event, payload_sha256))
        return {
            "received": True,
            "event_id": record["event_id"],
            "event_type": record["event_type"],
            "duplicate": record["duplicate"],
            "delivery_count": record["delivery_count"],
            "findings": record["findings"],
        }

    @app.get("/events", response_model=list[EventRecord])
    async def list_events(
        limit: int = Query(default=50, ge=1, le=200),
        event_type: str | None = Query(default=None),
    ) -> list[dict[str, object]]:
        return [
            event_response(record)
            for record in database.list_events(limit=limit, event_type=event_type)
        ]

    @app.get("/events/{event_id}", response_model=EventRecord)
    async def get_event(event_id: str) -> dict[str, object]:
        record = database.get_event(event_id)
        if record is None:
            raise HTTPException(status_code=404, detail="Event not found")
        return event_response(record)

    @app.get("/attempts", response_model=list[DeliveryAttempt])
    async def list_attempts(
        limit: int = Query(default=50, ge=1, le=200),
    ) -> list[dict[str, object]]:
        attempts = database.list_attempts(limit=limit)
        for attempt in attempts:
            attempt["signature_valid"] = bool(attempt["signature_valid"])
        return attempts

    @app.get("/triage/summary", response_model=Summary)
    async def triage_summary() -> dict[str, object]:
        totals = database.summary()
        return {**totals, "findings": summary_findings(totals)}

    return app


app = create_app()

