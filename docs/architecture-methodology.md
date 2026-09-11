# Architecture and Methodology

## Objective

This project demonstrates a defensive, evidence-driven endpoint isolation decision workflow for incident response. It is designed for synthetic data and recruiter-facing portfolio use. It does not connect to a live EDR platform and does not execute isolation actions.

## Architecture

1. **Telemetry ingestion** — JSON records are validated and normalized into immutable `EndpointEvent` objects.
2. **Correlation** — events are grouped by host and evaluated across independent signal types.
3. **Decision support** — the engine computes bounded risk and confidence values, maps relevant MITRE ATT&CK context, and recommends one of four actions.
4. **Reporting** — findings are rendered into an executive/technical Markdown assessment.
5. **Governance** — release criteria require evidence preservation, control-health validation, remediation, and documented approval.

## Risk model

The score is intentionally explainable. It combines:

- maximum event severity;
- diversity of correlated signal types;
- privileged-account context;
- security-control impairment;
- credential-theft indicators;
- C2-like network behavior;
- destructive/ransomware-like behavior.

Scores are capped at 100. Confidence is calculated separately so a severe but weakly corroborated event is not presented as equivalent to a well-supported incident.

## Decision thresholds

| Score | Recommended action |
|---:|---|
| 70–100 | Isolate immediately |
| 50–69 | Isolate after analyst validation |
| 30–49 | Increase monitoring and investigate |
| 0–29 | Monitor |

The recommendation is decision support, not autonomous enforcement.

## ATT&CK context

The lab uses ATT&CK identifiers to organize investigation context, including T1003, T1021, T1059.001, T1071, T1486, T1547, and T1562.001. A mapping is not evidence that a technique actually occurred.

## Isolation workflow

1. Validate host identity and asset criticality.
2. Preserve relevant endpoint, identity, and network evidence.
3. Correlate telemetry across multiple sources.
4. Determine business and safety impact of isolation.
5. Isolate when the risk of continued connectivity exceeds containment cost.
6. Investigate scope and root cause.
7. Remediate endpoint and identity risks.
8. Validate EDR/telemetry health.
9. Confirm release criteria and obtain approval.
10. Release, monitor closely, and document closure evidence.

## Release standard

A device should not be released solely because alerts stopped. Closure should demonstrate that:

- malicious or unauthorized activity is no longer present;
- compromised credentials/tokens have been addressed when relevant;
- persistence artifacts have been removed or validated;
- required security controls are healthy;
- evidence has been retained;
- incident ownership has approved reconnection.

## Safety and limitations

This repository contains no malware, exploit payloads, credential-stealing code, EDR bypass logic, isolation API credentials, or live targeting. Synthetic telemetry uses documentation-range IP addresses. Production isolation should be performed only through approved organizational procedures and authorized security tooling.
