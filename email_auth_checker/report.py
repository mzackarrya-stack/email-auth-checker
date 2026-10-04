"""Run the four checks for a domain and render the results as text or JSON."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Callable, Optional, Sequence

from . import __version__
from .dkim import check_dkim
from .dmarc import check_dmarc
from .model import CheckResult, Status, worst
from .mx import check_mx
from .resolver import Resolver
from .spf import LOOKUP_LIMIT, check_spf

EXIT_OK = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_INCOMPLETE = 3  # no FAIL, but at least one lookup failed: the result is unknown, not clean


@dataclass
class DomainReport:
    domain: str
    checks: list[CheckResult]

    @property
    def status(self) -> Status:
        return worst(c.status for c in self.checks)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "status": self.status.value,
            "checks": {c.name.lower(): c.to_dict() for c in self.checks},
        }


def check_domain(domain: str, resolver: Resolver, selectors: Sequence[str] = ()) -> DomainReport:
    runs: list[tuple[str, Callable[[], CheckResult]]] = [
        ("SPF", lambda: check_spf(domain, resolver)),
        ("DMARC", lambda: check_dmarc(domain, resolver)),
        ("DKIM", lambda: check_dkim(domain, resolver, selectors)),
        ("MX", lambda: check_mx(domain, resolver)),
    ]
    checks = []
    for name, run in runs:
        try:
            checks.append(run())
        except Exception as exc:  # noqa: BLE001 - a bug in one check must not hide the other three
            failed = CheckResult(name, summary="internal error")
            failed.add(Status.ERROR, f"internal error: {type(exc).__name__}: {exc}",
                       "this is a bug in email-auth-checker, not necessarily in your DNS; please report it")
            checks.append(failed)
    return DomainReport(domain, checks)


def exit_code(reports: Sequence[DomainReport]) -> int:
    statuses = [r.status for r in reports]
    if Status.FAIL in statuses:
        return EXIT_FAIL
    if Status.ERROR in statuses:
        return EXIT_INCOMPLETE
    return EXIT_OK


# --- text ----------------------------------------------------------------------

_COLORS = {
    Status.PASS: "32", Status.INFO: "36", Status.WARN: "33", Status.ERROR: "35", Status.FAIL: "31",
}


def _label(status: Status, color: bool) -> str:
    text = f"{status.value:<5}"
    return f"\033[1;{_COLORS[status]}m{text}\033[0m" if color else text


def _spf_tree_lines(node: Optional[dict[str, Any]], depth: int = 0, via: str = "") -> list[str]:
    if node is None:
        return []
    count = "no record" if node.get("record") is None else f"{node['lookups']}"
    lines = [f"{'  ' * depth}{via}{node['domain']}  {count}"]
    for child in node.get("includes", []):
        lines.extend(_spf_tree_lines(child, depth + 1, "include:"))
    if node.get("redirect"):
        lines.extend(_spf_tree_lines(node["redirect"], depth + 1, "redirect="))
    return lines


def render_text(reports: Sequence[DomainReport], color: bool = False, verbose: bool = False) -> str:
    out: list[str] = []
    pad = " " * 9
    for report in reports:
        out.append(f"{report.domain}  {_label(report.status, color)}")
        for check in report.checks:
            out.append(f"  {check.name:<6} {_label(check.status, color)}  {check.summary}")
            record = check.details.get("record") or next(iter(check.details.get("records") or []), None)
            if record and (verbose or check.status is not Status.PASS):
                out.append(f"{pad}record: {record}")
            for finding in check.sorted_findings():
                if not verbose and finding.status in (Status.PASS, Status.INFO):
                    continue
                out.append(f"{pad}{_label(finding.status, color)}  {finding.message}")
                if finding.why and finding.status not in (Status.PASS, Status.INFO):
                    out.append(f"{pad}       why: {finding.why}")
            lookups = check.details.get("lookups")
            if check.name == "SPF" and lookups is not None and (verbose or lookups >= LOOKUP_LIMIT - 1):
                out.append(f"{pad}lookups per record:")
                out.extend(f"{pad}  {line}" for line in _spf_tree_lines(check.details.get("tree")))
        counts = {s: sum(1 for c in report.checks if c.status is s) for s in Status}
        parts = [f"{counts[Status.FAIL]} fail", f"{counts[Status.WARN]} warn"]
        if counts[Status.ERROR]:
            parts.append(f"{counts[Status.ERROR]} could not be checked")
        out.append(f"  -> {', '.join(parts)}")
        out.append("")
    return "\n".join(line.rstrip() for line in out).rstrip() + "\n"


# --- JSON ----------------------------------------------------------------------

def render_json(reports: Sequence[DomainReport]) -> str:
    payload = {
        "tool": "email-auth-checker",
        "version": __version__,
        "exit_code": exit_code(reports),
        "domains": [r.to_dict() for r in reports],
    }
    return json.dumps(payload, indent=2) + "\n"
