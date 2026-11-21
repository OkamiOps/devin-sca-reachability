import unittest

from sca_reachability.errors import InputError
from sca_reachability.models import Component, Vulnerability
from sca_reachability.pipeline import analyze
from sca_reachability.report import build_report


class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.component = Component(
            purl="pkg:pypi/fictional-demo-package@1.0.0",
            version="1.0.0",
        )

    def test_finding_is_retained_with_unknown_reachability(self):
        result = analyze(
            [self.component],
            [[Vulnerability(id="DEMO-0001")]],
        )
        report = build_report(result)

        self.assertEqual(report["assessment"], "findings_present")
        self.assertEqual(report["summary"]["unknown"], 1)
        self.assertEqual(report["findings"][0]["reachability"]["status"], "unknown")
        self.assertIn("do not prove", report["findings"][0]["reachability"]["reason"])

    def test_no_findings_are_not_reported_as_safe(self):
        report = build_report(analyze([self.component], [[]]))

        self.assertEqual(report["assessment"], "no_findings_in_supplied_data")
        self.assertEqual(report["summary"]["total_findings"], 0)
        self.assertNotIn("safe", report)

    def test_rejects_misaligned_component_results(self):
        with self.assertRaisesRegex(InputError, "does not match"):
            analyze([self.component], [])
