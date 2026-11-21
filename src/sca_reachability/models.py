from dataclasses import dataclass
from enum import Enum


@dataclass(frozen=True)
class Component:
    purl: str
    version: str
    name: str | None = None


@dataclass(frozen=True)
class Vulnerability:
    id: str
    aliases: tuple[str, ...] = ()
    summary: str | None = None


class ReachabilityStatus(str, Enum):
    REACHABLE = "reachable"
    UNREACHABLE = "unreachable"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ReachabilityResult:
    status: ReachabilityStatus
    reason: str


@dataclass(frozen=True)
class Finding:
    component: Component
    vulnerability: Vulnerability
    reachability: ReachabilityResult


@dataclass(frozen=True)
class AnalysisResult:
    components_analyzed: int
    findings: tuple[Finding, ...]
