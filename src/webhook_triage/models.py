"""API response models."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Finding(BaseModel):
    severity: Literal["info", "warning", "critical"]
    code: str
    message: str
    action: str


class WebhookAcknowledgement(BaseModel):
    received: Literal[True] = True
    event_id: str
    event_type: str
    duplicate: bool
    delivery_count: int = Field(ge=1)
    findings: list[Finding]


class EventRecord(BaseModel):
    event_id: str
    event_type: str
    api_version: str | None
    object_type: str | None
    livemode: bool
    stripe_created: int | None
    first_received_at: str
    last_received_at: str
    delivery_count: int = Field(ge=1)
    first_payload_sha256: str
    last_payload_sha256: str
    payload_changed: bool
    duplicate: bool
    findings: list[Finding]


class DeliveryAttempt(BaseModel):
    attempt_id: int
    event_id: str | None
    received_at: str
    signature_valid: bool
    outcome: Literal["accepted", "duplicate", "rejected"]
    error_code: str | None
    payload_sha256: str


class Summary(BaseModel):
    unique_events: int = Field(ge=0)
    valid_deliveries: int = Field(ge=0)
    duplicate_deliveries: int = Field(ge=0)
    invalid_deliveries: int = Field(ge=0)
    payload_mismatches: int = Field(ge=0)
    findings: list[Finding]


class Health(BaseModel):
    status: Literal["ok", "degraded"]
    webhook_secret_configured: bool
    database_path: str

