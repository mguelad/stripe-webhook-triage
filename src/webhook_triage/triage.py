"""Deterministic findings that turn delivery records into support signals."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def event_findings(record: Mapping[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    if int(record["delivery_count"]) > 1:
        findings.append(
            {
                "severity": "info",
                "code": "duplicate_delivery",
                "message": "Stripe delivered this event ID more than once.",
                "action": "Keep processing idempotent and acknowledge known event IDs with 2xx.",
            }
        )

    if bool(record["payload_changed"]):
        findings.append(
            {
                "severity": "critical",
                "code": "payload_hash_mismatch",
                "message": "The same event ID arrived with a different payload hash.",
                "action": "Compare the delivery source and verify that the raw body is unmodified.",
            }
        )

    if not record.get("api_version"):
        findings.append(
            {
                "severity": "warning",
                "code": "api_version_missing",
                "message": "The event did not include an API version.",
                "action": "Confirm the event format and source before relying on its schema.",
            }
        )

    return findings


def event_response(record: Mapping[str, Any]) -> dict[str, Any]:
    response = dict(record)
    response["livemode"] = bool(response["livemode"])
    response["payload_changed"] = bool(response["payload_changed"])
    response["duplicate"] = int(response["delivery_count"]) > 1
    response["findings"] = event_findings(response)
    return response


def summary_findings(summary: Mapping[str, int]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []

    if summary["invalid_deliveries"]:
        findings.append(
            {
                "severity": "warning",
                "code": "signature_failures_present",
                "message": "One or more deliveries failed signature validation.",
                "action": (
                    "Check the endpoint secret, raw request body, and Stripe-Signature header."
                ),
            }
        )

    if summary["duplicate_deliveries"]:
        findings.append(
            {
                "severity": "info",
                "code": "duplicates_present",
                "message": "Duplicate deliveries were observed.",
                "action": "Confirm that downstream handlers are idempotent.",
            }
        )

    if summary["payload_mismatches"]:
        findings.append(
            {
                "severity": "critical",
                "code": "payload_mismatches_present",
                "message": "At least one event ID was seen with different payload hashes.",
                "action": "Investigate the sender and any middleware modifying request bodies.",
            }
        )

    return findings
