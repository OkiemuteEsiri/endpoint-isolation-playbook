from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_STATES = {"connected", "isolated", "released", "pending"}


def parse_utc(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("timestamp must include timezone information")
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class EndpointEvent:
    event_id: str
    timestamp: datetime
    host: str
    user: str
    event_type: str
    severity: str
    source: str
    process: str = ""
    destination: str = ""
    privileged: bool = False
    evidence: str = ""

    def __post_init__(self) -> None:
        if not self.event_id.strip():
            raise ValueError("event_id is required")
        if not self.host.strip():
            raise ValueError("host is required")
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity}")
        if self.timestamp.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")


@dataclass(frozen=True)
class IsolationFinding:
    finding_id: str
    host: str
    score: int
    severity: str
    confidence: int
    reason: str
    evidence_ids: tuple[str, ...]
    attack_techniques: tuple[str, ...]
    action: str
    release_criteria: tuple[str, ...]

    def __post_init__(self) -> None:
        if not 0 <= self.score <= 100:
            raise ValueError("score must be between 0 and 100")
        if not 0 <= self.confidence <= 100:
            raise ValueError("confidence must be between 0 and 100")
        if self.severity not in VALID_SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity}")


def ensure_unique_event_ids(events: Iterable[EndpointEvent]) -> None:
    seen: set[str] = set()
    for event in events:
        if event.event_id in seen:
            raise ValueError(f"duplicate event_id: {event.event_id}")
        seen.add(event.event_id)
