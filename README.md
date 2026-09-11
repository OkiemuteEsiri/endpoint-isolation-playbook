# Endpoint Isolation Playbook

Defensive incident-response decision-support lab for determining when an endpoint should be isolated, what evidence should drive that decision, and what must be validated before reconnection.

## Why this project exists

Endpoint isolation is one of the highest-impact containment actions available to a security operations team. It can stop lateral movement, credential abuse, command-and-control traffic, and destructive activity, but it can also disrupt business-critical systems when applied without sufficient evidence. This project models a disciplined containment workflow that separates **severity**, **confidence**, and **business-impact-aware decision making**.

The project is intentionally defensive. It does not perform live isolation and contains no EDR credentials, malware, exploit code, credential theft, persistence deployment, or production targeting.

## What it demonstrates

- Evidence-driven incident containment decisions
- Multi-signal endpoint correlation
- Severity and confidence separation
- Explainable 0–100 risk scoring
- Deterministic finding identifiers
- ATT&CK-aligned investigative context
- Endpoint/identity/network evidence preservation
- Release and revalidation criteria
- Executive and technical Markdown reporting
- Fail-closed input validation
- Synthetic telemetry suitable for safe portfolio demonstration
- Unit tests and least-privilege CI

## Architecture

```text
Synthetic endpoint telemetry
        |
        v
Validated immutable models
        |
        v
Host-level signal correlation
        |
        +--> risk score
        +--> confidence
        +--> ATT&CK context
        +--> containment recommendation
        |
        v
Release criteria + governance
        |
        v
Executive / technical Markdown report
```

## Repository structure

```text
.github/workflows/ci.yml       Least-privilege CI
src/models.py                  Immutable validated domain models
src/io.py                      Fail-closed JSON ingestion
src/decision_engine.py         Correlation, scoring, recommendations
src/reporting.py               Markdown executive/technical reporting
src/cli.py                     Offline CLI

data/synthetic_endpoint_events.json
                               Realistic synthetic endpoint telemetry

tests/test_decision_engine.py  Unit tests

docs/architecture-methodology.md
                               Architecture, scoring, release methodology

reports/example-assessment.md  Example investigation and containment output
```

## Containment decision model

The engine groups telemetry by endpoint and evaluates independent signals rather than treating a single alert as proof of compromise.

Risk factors include:

| Signal | Why it matters |
|---|---|
| Event severity | Establishes the initial impact baseline |
| Multiple signal types | Increases corroboration |
| Privileged-account context | Raises potential blast radius |
| Security-control impairment | Reduces defensive visibility/protection |
| Credential-theft signal | Increases identity compromise risk |
| C2-like traffic | Suggests sustained external communication |
| Ransomware/destructive behavior | Can justify rapid containment |

The score is bounded to **0–100**. Confidence is calculated separately.

### Decision thresholds

| Risk score | Recommendation |
|---:|---|
| 70–100 | `isolate_immediately` |
| 50–69 | `isolate_after_analyst_validation` |
| 30–49 | `increase_monitoring_and_investigate` |
| 0–29 | `monitor` |

These recommendations are decision support, not autonomous enforcement.

## ATT&CK context

The synthetic lab can map evidence to relevant MITRE ATT&CK context including:

- **T1003** — OS Credential Dumping
- **T1021** — Remote Services
- **T1059.001** — PowerShell
- **T1071** — Application Layer Protocol
- **T1486** — Data Encrypted for Impact
- **T1547** — Boot or Logon Autostart Execution
- **T1562.001** — Impair Defenses

ATT&CK mappings organize investigation context. They do not prove that an attacker successfully executed a technique.

## Example workflow

A typical analyst workflow represented by this project is:

1. Confirm host identity, ownership, and criticality.
2. Preserve endpoint, identity, and network evidence.
3. Correlate signals across telemetry sources.
4. Assess severity, confidence, and business impact.
5. Decide whether immediate isolation is justified.
6. Investigate scope and root cause.
7. Remediate endpoint and identity exposure.
8. Confirm security controls and telemetry are healthy.
9. Validate formal release criteria.
10. Obtain incident-owner approval and reconnect under increased monitoring.

## Release criteria

The project deliberately treats **release from isolation** as a security control rather than an administrative click.

Common release requirements include:

- no active malicious or unauthorized process/connection remains;
- relevant evidence has been preserved;
- endpoint protection is operational;
- compromised credentials or tokens are remediated where relevant;
- persistence artifacts are removed or validated;
- destructive behavior has ceased;
- recovery readiness has been validated where necessary;
- incident ownership approves reconnection.

No-alert activity alone is not sufficient closure evidence.

## Synthetic dataset

`data/synthetic_endpoint_events.json` contains four deliberately different endpoint scenarios:

- a high-confidence endpoint with defense impairment, credential-access context, and C2-like traffic;
- a server with service/persistence activity that may have legitimate administrative explanations;
- a low-risk scripting signal included to demonstrate false-positive tuning;
- a destructive-behavior case correlated with defense impairment.

All names, telemetry, and addresses are synthetic. Documentation-range IP space is used where applicable.

## Run locally

Python 3.12 is sufficient; no external packages are required.

```bash
python -m unittest discover -s tests -v
python -m src.cli data/synthetic_endpoint_events.json --output reports/generated-assessment.md
```

The CLI parses the synthetic telemetry, evaluates endpoints, and generates a Markdown assessment.

## Testing strategy

The unit suite validates important security-engineering properties including:

- low-confidence signals do not automatically trigger isolation;
- destructive behavior increases risk;
- multi-signal correlation increases risk;
- privileged context affects prioritization;
- duplicate evidence IDs fail closed;
- finding IDs remain deterministic;
- identity-specific release criteria appear when relevant;
- hosts are assessed independently;
- metrics remain bounded;
- invalid severities fail closed.

CI performs compilation, unit-test discovery, and an offline CLI smoke test using least-privilege `contents: read` permissions.

## Example investigation output

See [`reports/example-assessment.md`](reports/example-assessment.md) for a synthetic analyst-facing containment assessment covering immediate isolation, analyst validation, monitoring, ATT&CK context, and release requirements.

## Design decisions

### Severity is not confidence

A critical alert can still require corroboration. Conversely, several medium-severity events can become significant when they form a coherent sequence.

### Isolation is not remediation

Containment limits exposure. It does not by itself remove persistence, reset credentials, restore controls, or establish root cause.

### Reconnection is a security decision

Release requires explicit evidence and ownership because premature reconnection can reintroduce risk.

### Data quality fails closed

Malformed records, missing required fields, duplicate evidence identifiers, invalid timestamps, and unsupported severities are rejected rather than silently normalized into misleading results.

## Skills demonstrated

This repository is intended to demonstrate practical ability in:

- Detection Engineering
- Incident Response
- Endpoint Security
- SOC Engineering
- Security Automation
- Python
- Risk-based decision support
- Evidence handling
- MITRE ATT&CK mapping
- Containment governance
- Remediation validation
- Executive security reporting
- CI/CD security hygiene

## Limitations

This is a synthetic decision-support lab, not a replacement for an enterprise EDR, SIEM, SOAR platform, or formal incident-response program. It does not retrieve live telemetry, perform endpoint isolation, execute malware, alter hosts, or make production changes.

A production implementation would additionally integrate asset criticality, CMDB ownership, EDR APIs, identity telemetry, network controls, change management, approval workflows, legal/regulatory requirements, and organization-specific severity thresholds.

## Roadmap

Future safe enhancements may include:

- asset criticality and business-service dependencies;
- isolation SLA metrics;
- case state transitions;
- evidence-chain validation;
- approved exception handling for critical systems;
- pluggable synthetic EDR/SIEM adapters;
- JSON report export;
- ATT&CK coverage summaries;
- containment-to-recovery KPI reporting.

## Safety statement

This project is for defensive security engineering, authorized training, and portfolio demonstration. It contains no malicious payloads, credential extraction, EDR bypass logic, persistence deployment, live targeting, or confidential client data.
