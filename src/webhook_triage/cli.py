"""Command-line access to stored triage data."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from webhook_triage.config import Settings
from webhook_triage.database import Database
from webhook_triage.triage import event_response, summary_findings


def _print_json(value: Any) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect Stripe webhook triage data")
    parser.add_argument(
        "--database",
        type=Path,
        default=None,
        help="SQLite database path; defaults to TRIAGE_DATABASE_PATH",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("summary", help="Show aggregate delivery signals")

    events = subparsers.add_parser("events", help="List recent unique events")
    events.add_argument("--limit", type=int, default=20)
    events.add_argument("--type", dest="event_type", default=None)

    show = subparsers.add_parser("show", help="Show one event")
    show.add_argument("event_id")

    attempts = subparsers.add_parser("attempts", help="List recent delivery attempts")
    attempts.add_argument("--limit", type=int, default=20)
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    settings = Settings.from_env()
    database = Database(args.database or settings.database_path)
    database.initialize()

    if args.command == "summary":
        totals = database.summary()
        _print_json({**totals, "findings": summary_findings(totals)})
        return

    if args.command == "events":
        if not 1 <= args.limit <= 200:
            parser.error("--limit must be between 1 and 200")
        _print_json(
            [
                event_response(record)
                for record in database.list_events(
                    limit=args.limit, event_type=args.event_type
                )
            ]
        )
        return

    if args.command == "show":
        record = database.get_event(args.event_id)
        if record is None:
            parser.error(f"event not found: {args.event_id}")
        _print_json(event_response(record))
        return

    if not 1 <= args.limit <= 200:
        parser.error("--limit must be between 1 and 200")
    _print_json(database.list_attempts(limit=args.limit))


if __name__ == "__main__":
    main()

