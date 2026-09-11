from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from typing import Iterable

from .models import EndpointEvent, IsolationFinding, ensure_unique_event_ids

SEVERITY_WEIGHT = {"low": 5, "medium": 12, "high": 22, "critical": 30}
TECHNIQUE_BY_EVENT = {
    "credential_theft_signal": "T1003",
    "remote_service": "T1021",
    "control_impairment": "T1562.001",
    "suspicious_powershell": "T1059.001",
    "c2_like_traffic": "T1071",
    "ransomware_behavior": "T1486",
    "persistence_change": "T1547",
}


def _finding_id(host: str, evidence_ids: tuple[str, ...]) -> str:
    material = host + "|" + "|".join(sorted(evidence_ids))
    return sha256(material.encode()).hexdigest()[:16]


def _severity(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    return "low"


def _release_criteria(event_types: set[str]) -> tuple[str, ...]:
    criteria = [
        "Preserve relevant endpoint, identity, and network evidence.",
        "Validate containment scope and confirm no active malicious process or connection remains.",
        "Confirm endpoint protection and required telemetry are healthy.",
    ]
    if "credential_theft_signal" in event_types:
        criteria.append("Reset or revoke impacted credentials/tokens and validate identity telemetry.")
    if "persistence_change" in event_types:
        criteria.append("Remove or validate persistence artifacts and confirm clean startup state.")
    if "ransomware_behavior" in event_types:
        criteria.append("Validate recovery readiness and confirm destructive activity has ceased.")
    criteria.append("Document incident owner approval before network release.")
    return tuple(criteria)


def assess_endpoints(events: Iterable[EndpointEvent]) -> list[IsolationFinding]:
    events = list(events)
    ensure_unique_event_ids(events)
    by_host: dict[str, list[EndpointEvent]] = defaultdict(list)
    for event in events:
        by_host[event.host].append(event)

    findings: list[IsolationFinding] = []
    for host, host_events in sorted(by_host.items()):
        event_types = {e.event_type for e in host_events}
        base = max(SEVERITY_WEIGHT[e.severity] for e in host_events)
        score = base

        # Multi-signal correlation deliberately raises confidence rather than treating one alert as proof.
        score += min(30, 8 * max(0, len(event_types) - 1))
        if any(e.privileged for e in host_events):
            score += 12
        if "control_impairment" in event_types:
            score += 15
        if "credential_theft_signal" in event_types:
            score += 12
        if "c2_like_traffic" in event_types:
            score += 10
        if "ransomware_behavior" in event_types:
            score += 25
        score = min(100, score)

        confidence = min(100, 35 + 12 * len(event_types) + 5 * len(host_events))
        evidence_ids = tuple(sorted(e.event_id for e in host_events))
        techniques = tuple(sorted({TECHNIQUE_BY_EVENT[t] for t in event_types if t in TECHNIQUE_BY_EVENT}))

        if score >= 70:
            action = "isolate_immediately"
        elif score >= 50:
            action = "isolate_after_analyst_validation"
        elif score >= 30:
            action = "increase_monitoring_and_investigate"
        else:
            action = "monitor"

        findings.append(
            IsolationFinding(
                finding_id=_finding_id(host, evidence_ids),
                host=host,
                score=score,
                severity=_severity(score),
                confidence=confidence,
                reason=f"Correlated {len(host_events)} events across {len(event_types)} signal types.",
                evidence_ids=evidence_ids,
                attack_techniques=techniques,
                action=action,
                release_criteria=_release_criteria(event_types),
            )
        )
    return findings


def portfolio_metrics(findings: Iterable[IsolationFinding]) -> dict[str, object]:
    findings = list(findings)
    return {
        "hosts_assessed": len(findings),
        "immediate_isolation": sum(f.action == "isolate_immediately" for f in findings),
        "analyst_validation_required": sum(f.action == "isolate_after_analyst_validation" for f in findings),
        "highest_score": max((f.score for f in findings), default=0),
        "average_confidence": round(sum(f.confidence for f in findings) / len(findings), 1) if findings else 0.0,
        "critical_findings": sum(f.severity == "critical" for f in findings),
    }
