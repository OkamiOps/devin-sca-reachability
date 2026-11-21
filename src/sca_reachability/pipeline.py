from collections.abc import Sequence

from sca_reachability.errors import InputError
from sca_reachability.models import (
    AnalysisResult,
    Component,
    Finding,
    Vulnerability,
)
from sca_reachability.reachability import (
    DefaultReachabilityAnalyzer,
    ReachabilityAnalyzer,
)


def analyze(
    components: Sequence[Component],
    vulnerabilities_by_component: Sequence[Sequence[Vulnerability]],
    analyzer: ReachabilityAnalyzer | None = None,
) -> AnalysisResult:
    if len(components) != len(vulnerabilities_by_component):
        raise InputError(
            "vulnerability result count does not match SBOM component count"
        )

    reachability_analyzer = analyzer or DefaultReachabilityAnalyzer()
    findings = []
    for component, vulnerabilities in zip(
        components, vulnerabilities_by_component, strict=True
    ):
        for vulnerability in vulnerabilities:
            findings.append(
                Finding(
                    component=component,
                    vulnerability=vulnerability,
                    reachability=reachability_analyzer.analyze(
                        component, vulnerability
                    ),
                )
            )

    return AnalysisResult(
        components_analyzed=len(components),
        findings=tuple(findings),
    )
