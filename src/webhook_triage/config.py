"""Application configuration loaded from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    """Runtime settings with safe local defaults."""

    webhook_secret: str
    database_path: Path
    signature_tolerance_seconds: int = 300

    @classmethod
    def from_env(cls) -> Settings:
        raw_tolerance = os.getenv("STRIPE_SIGNATURE_TOLERANCE_SECONDS", "300")
        try:
            tolerance = int(raw_tolerance)
        except ValueError as exc:
            raise ValueError(
                "STRIPE_SIGNATURE_TOLERANCE_SECONDS must be an integer"
            ) from exc

        if tolerance <= 0:
            raise ValueError("STRIPE_SIGNATURE_TOLERANCE_SECONDS must be positive")

        return cls(
            webhook_secret=os.getenv("STRIPE_WEBHOOK_SECRET", ""),
            database_path=Path(os.getenv("TRIAGE_DATABASE_PATH", "data/triage.db")),
            signature_tolerance_seconds=tolerance,
        )
