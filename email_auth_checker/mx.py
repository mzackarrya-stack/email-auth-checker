"""MX: where mail for the domain is delivered (RFC 5321 5.1, RFC 7505).

A sending domain needs to receive mail too: bounces and replies go there, and many
receivers refuse mail from a domain that cannot accept any.
"""

from __future__ import annotations

import ipaddress
from typing import Optional

from .model import CheckResult, Status
from .resolver import LookupFailed, NXDomain, Resolver, normalize_name

WHY_LOOKUP_FAILED = "the answer is unknown, not necessarily wrong; retry or try --nameserver 1.1.1.1"


def _parse_mx(value: str) -> tuple[int, str]:
    preference, _, host = value.strip().partition(" ")
    host = host.strip()
    return int(preference), "." if host in (".", "") else normalize_name(host)


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _has_address(resolver: Resolver, host: str) -> Optional[bool]:
    """True/False if the host has an A or AAAA record; None if that can't be determined."""
    unknown = False
    for rdtype in ("A", "AAAA"):
        try:
            if resolver(host, rdtype):
                return True
        except NXDomain:
            return False
        except LookupFailed:
            unknown = True
    return None if unknown else False


def check_mx(domain: str, resolver: Resolver) -> CheckResult:
    result = CheckResult("MX")
    domain = normalize_name(domain)
    try:
        raw = resolver(domain, "MX")
    except NXDomain:
        result.summary = "domain does not exist"
        result.add(Status.FAIL, f"{domain} does not exist (NXDOMAIN)",
                   "mail from a domain that does not resolve is refused nearly everywhere")
        return result
    except LookupFailed as exc:
        result.summary = "lookup failed"
        result.add(Status.ERROR, f"could not fetch MX records: {exc.reason}", WHY_LOOKUP_FAILED)
        return result

    try:
        records = sorted(_parse_mx(v) for v in raw)
    except ValueError:
        result.summary = "unreadable MX answer"
        result.add(Status.ERROR, f"could not parse MX answer {raw!r}", "the resolver returned unexpected data")
        return result
    result.details["hosts"] = [{"preference": pref, "host": host} for pref, host in records]

    if not records:
        implicit = _has_address(resolver, domain)
        if implicit:
            result.summary = "no MX, falls back to the A/AAAA record"
            result.add(Status.WARN, "no MX record; mail is delivered to the domain's A/AAAA address",
                       "this implicit MX works, but bounces land on whatever web server answers there")
        elif implicit is None:
            result.summary = "no MX record"
            result.add(Status.ERROR, "no MX record, and the A/AAAA fallback could not be checked", WHY_LOOKUP_FAILED)
        else:
            result.summary = "no MX record"
            result.add(Status.FAIL, "no MX record and no A/AAAA fallback: the domain cannot receive mail",
                       "bounces and replies are lost, and many receivers refuse mail from domains that can't "
                       "receive any")
        return result

    null_mx = [r for r in records if r[1] == "."]
    if null_mx:
        if len(records) == 1 and null_mx[0][0] == 0:
            result.summary = "null MX: the domain accepts no mail"
            result.add(Status.WARN, "null MX (RFC 7505): the domain declares it accepts no mail",
                       "right for a domain that never sends; if you send from it, receivers may refuse your "
                       "mail because bounces can't come back")
        else:
            result.summary = "malformed null MX"
            result.add(Status.FAIL, "null MX ('.') mixed with other MX records or with a non-zero preference",
                       "RFC 7505 3: a null MX must be the only MX record, with preference 0; senders behave "
                       "unpredictably otherwise")
        return result

    hosts = [host for _, host in records]
    literals = [h for h in hosts if _is_ip_literal(h)]
    for host in literals:
        result.add(Status.FAIL, f"MX points to an IP address ({host})",
                   "an MX must name a host; many senders refuse to deliver to an address")
    unresolved, unknown = [], []
    for host in hosts:
        if host in literals:
            continue
        state = _has_address(resolver, host)
        if state is False:
            unresolved.append(host)
        elif state is None:
            unknown.append(host)
    named = [h for h in hosts if h not in literals]
    if named and len(unresolved) == len(named):
        result.add(Status.FAIL, f"no MX host has an address ({', '.join(unresolved)})",
                   "mail to the domain cannot be delivered anywhere")
    else:
        for host in unresolved:
            result.add(Status.WARN, f"MX host {host} has no A/AAAA record",
                       "senders that try it first lose time before falling back to the next host")
    for host in unknown:
        result.add(Status.INFO, f"could not resolve MX host {host}")

    listing = Status.INFO if result.has(Status.FAIL) else Status.PASS
    result.add(listing, f"{len(records)} MX host{'s' if len(records) > 1 else ''}: "
               + ", ".join(f"{pref} {host}" for pref, host in records))
    result.summary = f"{len(records)} host{'s' if len(records) > 1 else ''}, primary {records[0][1]}"
    return result
