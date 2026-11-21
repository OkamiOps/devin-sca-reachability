from collections import Counter
from typing import Any

from sca_reachability.models import AnalysisResult


def build_report(result: AnalysisResult) -> dict[str, Any]:
    reachability_counts = Counter(
        finding.reachability.status.value for finding in result.findings
    )
    findings = [
        {
            "component": {
                "purl": finding.component.purl,
                "version": finding.component.version,
            },
            "vulnerability": {
                "id": finding.vulnerability.id,
                "aliases": list(finding.vulnerability.aliases),
                "summary": finding.vulnerability.summary,
            },
            "reachability": {
                "status": finding.reachability.status.value,
                "reason": finding.reachability.reason,
                "evidence": [item.to_dict() for item in finding.reachability.evidence],
            },
        }
        for finding in result.findings
    ]

    return {
        "assessment": (
            "findings_present"
            if findings
            else "no_findings_in_supplied_data"
        ),
        "components_analyzed": result.components_analyzed,
        "summary": {
            "total_findings": len(findings),
            "reachable": reachability_counts["reachable"],
            "unreachable": reachability_counts["unreachable"],
            "unknown": reachability_counts["unknown"],
        },
        "findings": findings,
    }
