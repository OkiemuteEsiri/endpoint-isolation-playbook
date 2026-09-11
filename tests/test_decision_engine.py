import unittest
from datetime import datetime, timezone

from src.decision_engine import assess_endpoints, portfolio_metrics
from src.models import EndpointEvent, ensure_unique_event_ids


def event(event_id, host="LAB-1", event_type="suspicious_powershell", severity="low", privileged=False):
    return EndpointEvent(
        event_id=event_id,
        timestamp=datetime(2026, 9, 10, tzinfo=timezone.utc),
        host=host,
        user="synthetic",
        event_type=event_type,
        severity=severity,
        source="synthetic",
        privileged=privileged,
    )


class DecisionEngineTests(unittest.TestCase):
    def test_single_low_signal_is_not_immediate_isolation(self):
        finding = assess_endpoints([event("e1")])[0]
        self.assertNotEqual(finding.action, "isolate_immediately")

    def test_ransomware_signal_drives_high_risk(self):
        finding = assess_endpoints([event("e1", event_type="ransomware_behavior", severity="critical")])[0]
        self.assertGreaterEqual(finding.score, 55)
        self.assertIn("T1486", finding.attack_techniques)

    def test_multi_signal_correlation_increases_score(self):
        one = assess_endpoints([event("e1", severity="high")])[0]
        many = assess_endpoints([
            event("e2", severity="high"),
            event("e3", event_type="control_impairment", severity="high"),
            event("e4", event_type="c2_like_traffic", severity="high"),
        ])[0]
        self.assertGreater(many.score, one.score)

    def test_privileged_context_increases_score(self):
        normal = assess_endpoints([event("e1", severity="medium")])[0]
        privileged = assess_endpoints([event("e2", severity="medium", privileged=True)])[0]
        self.assertGreater(privileged.score, normal.score)

    def test_duplicate_evidence_ids_fail_closed(self):
        with self.assertRaises(ValueError):
            ensure_unique_event_ids([event("dup"), event("dup", host="LAB-2")])

    def test_deterministic_finding_ids(self):
        events = [event("e1"), event("e2", event_type="remote_service")]
        first = assess_endpoints(events)[0].finding_id
        second = assess_endpoints(list(reversed(events)))[0].finding_id
        self.assertEqual(first, second)

    def test_release_criteria_include_identity_action_for_credential_signal(self):
        finding = assess_endpoints([event("e1", event_type="credential_theft_signal", severity="critical")])[0]
        self.assertTrue(any("credentials/tokens" in item for item in finding.release_criteria))

    def test_hosts_are_assessed_independently(self):
        findings = assess_endpoints([event("e1", host="LAB-1"), event("e2", host="LAB-2")])
        self.assertEqual(2, len(findings))

    def test_portfolio_metrics_are_bounded_and_consistent(self):
        findings = assess_endpoints([event("e1", host="LAB-1"), event("e2", host="LAB-2", severity="high")])
        metrics = portfolio_metrics(findings)
        self.assertEqual(2, metrics["hosts_assessed"])
        self.assertGreaterEqual(metrics["highest_score"], 0)
        self.assertLessEqual(metrics["highest_score"], 100)

    def test_invalid_severity_fails_closed(self):
        with self.assertRaises(ValueError):
            event("e1", severity="extreme")


if __name__ == "__main__":
    unittest.main()
