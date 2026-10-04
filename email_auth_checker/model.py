"""Result types shared by every check."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class Status(str, Enum):
    """Outcome of a single finding, and by extension of a check.

    ERROR is not a verdict about the domain: it means a lookup failed (timeout,
    SERVFAIL) and the answer is unknown. It ranks above WARN so that "could not
    check" is never displayed as "looks fine".
    """

    PASS = "PASS"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    FAIL = "FAIL"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {Status.PASS: 0, Status.INFO: 0, Status.WARN: 1, Status.ERROR: 2, Status.FAIL: 3}


def worst(statuses: Iterable[Status]) -> Status:
    """Most severe status; INFO counts as PASS at check level."""
    result = Status.PASS
    for status in statuses:
        if status.rank > result.rank:
            result = status
    return result


@dataclass
class Finding:
    status: Status
    message: str
    why: str = ""

    def to_dict(self) -> dict[str, str]:
        data = {"status": self.status.value, "message": self.message}
        if self.why:
            data["why"] = self.why
        return data


@dataclass
class CheckResult:
    name: str
    summary: str = ""
    findings: list[Finding] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def add(self, status: Status, message: str, why: str = "") -> Finding:
        finding = Finding(status, message, why)
        self.findings.append(finding)
        return finding

    @property
    def status(self) -> Status:
        return worst(f.status for f in self.findings)

    def has(self, status: Status) -> bool:
        return any(f.status is status for f in self.findings)

    def sorted_findings(self) -> list[Finding]:
        """Most severe first; discovery order is kept within a severity."""
        return sorted(self.findings, key=lambda f: -f.status.rank)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "details": self.details,
        }
