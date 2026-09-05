# Stripe Webhook Triage Tool

A local diagnostic receiver for reproducing Stripe webhook problems. It verifies incoming
signatures, records delivery metadata in SQLite, and turns common failure patterns into short,
actionable findings.

## Why I built it

Webhook cases often begin with a broad report such as “the event was missed” or “the customer was
charged twice.” I wanted a small tool that gives support engineers a reliable timeline before they
start guessing: was the request signed correctly, did the same event arrive again, or did two
different Stripe events refer to the same underlying object?

The tool stores hashes and operational metadata instead of full webhook payloads. This keeps the
investigation useful while reducing the amount of customer data kept locally.

## What it detects

| Signal | Meaning | Suggested next step |
| --- | --- | --- |
| Invalid or missing signature | The delivery could not be verified. | Check the endpoint secret, raw request body, and `Stripe-Signature` header. |
| Repeated Event ID | Stripe delivered the same Event object more than once. | Return `2xx` and make the handler idempotent. |
| Related-event duplicate | Different Event IDs have the same event type and `data.object.id`. | Compare the events and protect downstream work with the event type and object ID. |
| Payload hash mismatch | The same Event ID arrived with different raw bytes. | Check middleware or any component that changes the request body. |

Stripe recommends logging processed Event IDs and notes that, in some cases, separate Event
objects can represent the same underlying event. See Stripe's guidance on
[handling duplicate events](https://docs.stripe.com/webhooks#handle-duplicate-events).

## Scope

This is a local reproduction and triage tool. It does not inspect a customer's existing endpoint,
query Stripe Workbench, retry Stripe deliveries, or proxy production traffic. It should not
replace a production webhook handler. Use Stripe
[Workbench](https://docs.stripe.com/workbench) for the delivery history of a real endpoint and this
tool when you want a controlled receiver for testing and investigation.

## Quick start

Requirements: Python 3.11+. The Stripe CLI is only needed for the end-to-end example.

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"

export STRIPE_WEBHOOK_SECRET=whsec_replace_me
export TRIAGE_DATABASE_PATH=data/triage.db
export TRIAGE_DIAGNOSTIC_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"

uvicorn webhook_triage.app:app --reload --host 127.0.0.1 --port 4242
```

In a second terminal, forward Stripe sandbox events to the receiver:

```bash
stripe listen --forward-to http://127.0.0.1:4242/webhooks/stripe
```

Copy the `whsec_...` secret printed by `stripe listen` into `STRIPE_WEBHOOK_SECRET`, restart the
application, and send an event:

```bash
stripe trigger payment_intent.succeeded
```

The Stripe CLI signing secret is different from the secret of a Workbench-managed endpoint. Always
use the secret belonging to the source sending the event. Stripe also requires the unmodified raw
request body for [signature verification](https://docs.stripe.com/webhooks/signature).

## Inspect the result

The webhook receiver remains open to Stripe deliveries. The diagnostic endpoints require the
bearer token configured above:

```bash
curl -H "Authorization: Bearer $TRIAGE_DIAGNOSTIC_TOKEN" \
  http://127.0.0.1:4242/triage/summary

curl -H "Authorization: Bearer $TRIAGE_DIAGNOSTIC_TOKEN" \
  "http://127.0.0.1:4242/events?event_type=payment_intent.succeeded"
```

The same data is available locally through the CLI:

```bash
webhook-triage summary
webhook-triage events --limit 20
webhook-triage show evt_example
webhook-triage attempts --limit 20
```

To start a fresh diagnostic session, stop incoming deliveries and clear the stored results:

```bash
webhook-triage reset
```

The command shows the configured SQLite path and asks for confirmation before deleting event and
delivery-attempt rows. It preserves the database file and schema. For deliberate automation, use
`webhook-triage reset --yes`.

An investigation with one Event ID redelivery and one related-event duplicate produces a summary
like this:

```json
{
  "unique_events": 2,
  "valid_deliveries": 3,
  "duplicate_deliveries": 1,
  "semantic_duplicates": 1,
  "invalid_deliveries": 0,
  "payload_mismatches": 0,
  "findings": [
    {
      "severity": "info",
      "code": "duplicates_present",
      "message": "Duplicate deliveries were observed.",
      "action": "Confirm that downstream handlers are idempotent."
    },
    {
      "severity": "warning",
      "code": "related_event_duplicates_present",
      "message": "Different event IDs were observed for the same event type and object ID.",
      "action": "Review the related events and deduplicate downstream processing using the event type and object ID."
    }
  ]
}
```

## API

| Method | Path | Access | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | Public | Report whether signing and diagnostic authentication are configured. |
| `POST` | `/webhooks/stripe` | Stripe signature | Verify and record a delivery. |
| `GET` | `/events` | Bearer token | List events and duplicate indicators. |
| `GET` | `/events/{event_id}` | Bearer token | Inspect one event. |
| `GET` | `/attempts` | Bearer token | Inspect accepted and rejected delivery attempts. |
| `GET` | `/triage/summary` | Bearer token | View aggregate findings. |
| `GET` | `/docs` | Public | Open FastAPI's interactive API documentation. |

## Data and security choices

- Signature verification uses the unmodified request body and Stripe's official Python library.
- Signing secrets and diagnostic tokens come from environment variables and are never persisted.
- Raw webhook payloads are not stored; only diagnostic metadata and SHA-256 hashes are kept.
- Diagnostic HTTP routes require a bearer token and are disabled when no token is configured.
- `/health` exposes configuration booleans, not secrets or local filesystem paths.
- SQLite writes use a transaction lock so concurrent redeliveries are counted atomically.
- Duplicate deliveries receive a quick `200` acknowledgement, following Stripe's
  [webhook best practices](https://docs.stripe.com/webhooks#best-practices-for-using-webhooks).

Keep the service bound to `127.0.0.1` unless you add the network controls, TLS, monitoring, and
operational safeguards required for a hosted environment.

## Tests and quality checks

```bash
pytest
ruff check .
```

The test suite covers valid deliveries, signature failures, malformed requests, both duplicate
patterns, concurrent redeliveries, diagnostic authentication, configuration errors, and event
filtering. It generates Stripe-compatible signatures locally, so tests do not need a Stripe
account, API key, or network connection.
