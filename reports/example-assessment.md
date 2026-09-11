# Example Endpoint Isolation Assessment

> Synthetic example for portfolio demonstration only.

## Executive summary

The synthetic dataset contains four endpoints with different containment profiles. `LAB-WS-017` and `LAB-WS-031` represent the strongest containment candidates because multiple high-impact signals are correlated. `LAB-SRV-004` requires analyst validation because the observed service and remote-administration activity could be legitimate. `LAB-WS-022` is retained as a low-risk tuning case.

## Priority decisions

### LAB-WS-017

**Recommended action:** isolate immediately after identity/asset confirmation.  
**Context:** correlated endpoint-protection impairment, credential-access signal, privileged context, and C2-like traffic.  
**ATT&CK:** T1003, T1071, T1562.001.

Release should require credential/token remediation, restored security controls, preserved evidence, validation of active network connections, and incident-owner approval.

### LAB-WS-031

**Recommended action:** isolate immediately.  
**Context:** destructive-file-behavior signal correlated with defense impairment and privileged context.  
**ATT&CK:** T1486, T1562.001.

Release should require confirmation that destructive activity has ceased, endpoint protection is healthy, recovery readiness is validated, evidence is retained, and reconnection is approved.

### LAB-SRV-004

**Recommended action:** isolate only after analyst validation unless additional evidence increases risk.  
**Context:** service modification plus remote-service administration can be legitimate operational behavior.  
**ATT&CK:** T1021, T1547.

This case demonstrates why severity and ATT&CK mapping alone are insufficient for containment decisions.

### LAB-WS-022

**Recommended action:** monitor and investigate.  
**Context:** a single low-severity scripting signal with no corroborating high-impact telemetry.  
**ATT&CK:** T1059.001.

## Validation principle

Containment closure is evidence-based. A host is not considered safe simply because no new alerts occur. The investigation must validate remediation, identity exposure where relevant, control health, and approval to reconnect.
