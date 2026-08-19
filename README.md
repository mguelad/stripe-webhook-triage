# Stripe Webhook Triage Tool

A small support-engineering service that receives Stripe webhook deliveries, verifies their
signatures, records diagnostic metadata in SQLite, detects duplicates, and exposes a concise
triage summary.

The project is designed around a common support problem: a customer says that a webhook was
missed, delivered more than once, or rejected. The tool creates an auditable delivery trail
without storing the full webhook payload by default.

## What it currently does

- Verifies the raw request body with Stripe's official Python library.
- Stores event and delivery-attempt metadata in SQLite.
- Detects repeated event IDs and payload-hash mismatches.
- Records missing or invalid signatures as failed delivery attempts.
- Provides event, attempt, and aggregate triage endpoints.
- Includes a CLI for querying the same SQLite data during an investigation.
- Avoids storing full webhook payloads, API keys, or signing secrets.

## Architecture

```text
Stripe CLI / Stripe
        |
        v
POST /webhooks/stripe
        |
        +-- signature verification
        +-- idempotency and payload-hash checks
        +-- SQLite event + attempt records
        |
        v
/events  /attempts  /triage/summary  CLI
```

## Quick start

Requirements: Python 3.11+ and the Stripe CLI for end-to-end local testing.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"

export STRIPE_WEBHOOK_SECRET=whsec_replace_me
export TRIAGE_DATABASE_PATH=data/triage.db

uvicorn webhook_triage.app:app --reload --port 4242
```

In a second terminal, forward sandbox events to the local endpoint:

```bash
stripe listen --forward-to http://localhost:4242/webhooks/stripe
```

Use the `whsec_...` secret printed by `stripe listen` as `STRIPE_WEBHOOK_SECRET`, restart the
application, and trigger an event:

```bash
stripe trigger payment_intent.succeeded
```

The Stripe CLI signing secret is different from the secret of a Dashboard-managed webhook
endpoint. Use the secret belonging to the source that sends the event.

## API

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Check service and signing-secret configuration. |
| `POST` | `/webhooks/stripe` | Verify and record a Stripe webhook delivery. |
| `GET` | `/events` | List unique events and duplicate indicators. |
| `GET` | `/events/{event_id}` | Inspect one event's delivery history. |
| `GET` | `/attempts` | Inspect recent valid and rejected attempts. |
| `GET` | `/triage/summary` | View aggregate failures and duplicate signals. |
| `GET` | `/docs` | Open FastAPI's interactive API documentation. |

Examples:

```bash
curl http://localhost:4242/triage/summary
curl "http://localhost:4242/events?event_type=payment_intent.succeeded"
webhook-triage summary
webhook-triage events --limit 20
```

## Tests and quality checks

```bash
pytest
ruff check .
```

The API tests generate Stripe-compatible signatures locally. They do not need a Stripe account,
API key, or network connection.

## Data and security choices

- Signature verification uses the unmodified request body.
- The signing secret comes only from an environment variable.
- Raw payloads are not persisted; only operational metadata and SHA-256 hashes are stored.
- Duplicate event IDs are acknowledged with `200` and recorded, supporting idempotent handling.
- This is a learning and diagnostic project, not a production payment processor.

## Roadmap

- Add filters for time windows, event types, and failure codes.
- Add retry-gap and delivery-latency diagnostics.
- Export a redacted investigation report for customer escalations.
- Add PostgreSQL support and database migrations.
- Add authentication before any hosted deployment.

