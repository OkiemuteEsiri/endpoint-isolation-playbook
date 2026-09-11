from __future__ import annotations

from .decision_engine import portfolio_metrics
from .models import IsolationFinding


def render_markdown(findings: list[IsolationFinding]) -> str:
    metrics = portfolio_metrics(findings)
    lines = [
        "# Endpoint Isolation Assessment",
        "",
        "> Synthetic defensive lab output. ATT&CK mappings are investigative context, not proof of compromise.",
        "",
        "## Executive Summary",
        "",
        f"- Hosts assessed: **{metrics['hosts_assessed']}**",
        f"- Immediate isolation recommendations: **{metrics['immediate_isolation']}**",
        f"- Analyst-validation recommendations: **{metrics['analyst_validation_required']}**",
        f"- Highest risk score: **{metrics['highest_score']} / 100**",
        f"- Average confidence: **{metrics['average_confidence']}%**",
        f"- Critical findings: **{metrics['critical_findings']}**",
        "",
        "## Findings",
        "",
    ]
    for finding in sorted(findings, key=lambda item: item.score, reverse=True):
        lines.extend(
            [
                f"### {finding.host} — {finding.severity.upper()} ({finding.score}/100)",
                "",
                f"**Decision:** `{finding.action}`  ",
                f"**Confidence:** {finding.confidence}%  ",
                f"**Finding ID:** `{finding.finding_id}`  ",
                f"**Reason:** {finding.reason}  ",
                f"**ATT&CK context:** {', '.join(finding.attack_techniques) or 'None'}  ",
                f"**Evidence IDs:** {', '.join(finding.evidence_ids)}",
                "",
                "**Release criteria**",
            ]
        )
        lines.extend(f"- {criterion}" for criterion in finding.release_criteria)
        lines.append("")
    lines.extend(
        [
            "## Governance Notes",
            "",
            "Isolation is a containment action with business impact. High-confidence destructive or control-impairment signals may justify rapid containment, but ambiguous signals should be analyst-validated. Release requires evidence-based revalidation and documented approval.",
        ]
    )
    return "\n".join(lines)
