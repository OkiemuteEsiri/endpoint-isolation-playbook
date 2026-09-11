from __future__ import annotations

import json
from pathlib import Path

from .models import EndpointEvent, parse_utc

REQUIRED = {"event_id", "timestamp", "host", "user", "event_type", "severity", "source"}


def load_events(path: str | Path) -> list[EndpointEvent]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("input must be a JSON array")

    events: list[EndpointEvent] = []
    for index, raw in enumerate(payload):
        if not isinstance(raw, dict):
            raise ValueError(f"record {index} must be an object")
        missing = REQUIRED - raw.keys()
        if missing:
            raise ValueError(f"record {index} missing fields: {sorted(missing)}")
        events.append(
            EndpointEvent(
                event_id=str(raw["event_id"]),
                timestamp=parse_utc(str(raw["timestamp"])),
                host=str(raw["host"]),
                user=str(raw["user"]),
                event_type=str(raw["event_type"]),
                severity=str(raw["severity"]).lower(),
                source=str(raw["source"]),
                process=str(raw.get("process", "")),
                destination=str(raw.get("destination", "")),
                privileged=bool(raw.get("privileged", False)),
                evidence=str(raw.get("evidence", "")),
            )
        )
    return events
