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
class ReachabilityEvidence:
    path: str
    line: int
    kind: str
    detail: str
    snippet: str = ""

    def to_dict(self) -> dict:
        return {"path": self.path, "line": self.line, "kind": self.kind,
                "detail": self.detail, "snippet": self.snippet}


@dataclass(frozen=True)
class ReachabilityResult:
    status: ReachabilityStatus
    reason: str
    evidence: tuple[ReachabilityEvidence, ...] = ()
    files_scanned: int | None = None
    language: str | None = None
    granularity: str | None = None
    symbols: tuple[str, ...] = ()

    def analysis_dict(self) -> dict:
        return {"files_scanned": self.files_scanned, "language": self.language,
                "granularity": self.granularity, "symbols": list(self.symbols)}


@dataclass(frozen=True)
class Finding:
    component: Component
    vulnerability: Vulnerability
    reachability: ReachabilityResult


@dataclass(frozen=True)
class AnalysisResult:
    components_analyzed: int
    findings: tuple[Finding, ...]
