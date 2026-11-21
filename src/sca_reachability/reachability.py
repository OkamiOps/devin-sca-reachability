from typing import Protocol

from sca_reachability.models import (
    Component,
    ReachabilityResult,
    ReachabilityStatus,
    Vulnerability,
)


class ReachabilityAnalyzer(Protocol):
    def analyze(
        self, component: Component, vulnerability: Vulnerability
    ) -> ReachabilityResult: ...


class DefaultReachabilityAnalyzer:
    def analyze(
        self, component: Component, vulnerability: Vulnerability
    ) -> ReachabilityResult:
        return ReachabilityResult(
            status=ReachabilityStatus.UNKNOWN,
            reason=(
                "No static reachability analyzer is configured; dependency presence "
                "or imports alone do not prove the vulnerable code path is executed."
            ),
        )
