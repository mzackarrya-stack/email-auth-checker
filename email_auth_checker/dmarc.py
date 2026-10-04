"""DMARC: what receivers do with mail that fails SPF and DKIM alignment (RFC 7489).

Discovery: ``_dmarc.<domain>`` first; if there is no record and the domain is a
subdomain, parent domains are tried in turn, and the subdomain gets the parent's
``sp=`` (or ``p=``). Without the Public Suffix List this is an approximation of the
organizational-domain lookup, close to the DNS tree walk of DMARCbis.
"""

from __future__ import annotations

import re
from typing import Optional

from .model import CheckResult, Status
from .resolver import LookupFailed, NXDomain, Resolver, normalize_name
from .taglist import parse_tag_list

POLICIES = ("none", "quarantine", "reject")
KNOWN_TAGS = frozenset({
    "v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "rf", "ri",  # RFC 7489
    "np", "psd", "t",  # DMARCbis
})
WEAKER = {"reject": "quarantine", "quarantine": "none"}
MODES = {"r": "relaxed", "s": "strict"}

_PREFIX = re.compile(r"^\s*v\s*=\s*dmarc1\b", re.IGNORECASE)
_AUTH = re.compile(r"^\s*v\s*=\s*DMARC1\s*(;|$)", re.IGNORECASE)

WHY_SYNTAX = "receivers may ignore the whole record, leaving the domain without DMARC"
WHY_LOOKUP_FAILED = "the answer is unknown, not necessarily wrong; retry or try --nameserver 1.1.1.1"


def _candidates(domain: str) -> list[str]:
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(max(len(labels) - 1, 1))]


def _same_org(a: str, b: str) -> bool:
    """Heuristic organizational-domain match (last two labels). No Public Suffix List."""
    return a.split(".")[-2:] == b.split(".")[-2:]


def _report_destinations(result: CheckResult, rua: str) -> tuple[list[str], list[str]]:
    """Validate rua URIs; return (addresses, destination domains)."""
    addresses, domains = [], []
    for uri in (u.strip() for u in rua.split(",")):
        if not uri:
            continue
        base = uri.split("!", 1)[0]  # optional "!10m" size limit
        lower = base.lower()
        if lower.startswith("mailto:"):
            address = base[len("mailto:"):]
            local, _, host = address.rpartition("@")
            if not local or "." not in host:
                result.add(Status.WARN, f"rua entry '{uri}' is not a valid mailto: address",
                           "receivers can't send reports to it")
                continue
            addresses.append(address)
            if normalize_name(host) not in domains:
                domains.append(normalize_name(host))
        elif "@" in base and ":" not in base:
            result.add(Status.WARN, f"rua entry '{uri}' is missing 'mailto:'",
                       "receivers skip it, so no aggregate reports arrive")
        else:
            result.add(Status.WARN, f"rua entry '{uri}' is not a mailto: URI",
                       "receivers only have to support mailto:, most send nothing anywhere else")
    return addresses, domains


def _check_report_authorization(result: CheckResult, resolver: Resolver, policy_domain: str,
                                destinations: list[str]) -> None:
    for dest in destinations:
        if _same_org(dest, policy_domain):
            continue
        name = f"{policy_domain}._report._dmarc.{dest}"
        try:
            txts = resolver(name, "TXT")
        except NXDomain:
            txts = []
        except LookupFailed as exc:
            result.add(Status.INFO, f"could not verify that {dest} accepts reports for {policy_domain} ({exc.reason})")
            continue
        if any(_AUTH.match(t) for t in txts):
            result.add(Status.INFO, f"external report destination {dest} has authorized reports for {policy_domain}")
        else:
            result.add(Status.WARN, f"reports go to {dest}, which has not published {name}",
                       "RFC 7489 7.1: receivers drop reports to another domain unless it opts in with that record")


def _validate_policy(result: CheckResult, tags: dict[str, str], tag: str, status: Status) -> Optional[str]:
    raw = tags.get(tag)
    if raw is None:
        return None
    if raw.lower() in POLICIES:
        return raw.lower()
    result.add(status, f"{tag}={raw} is not none, quarantine or reject", WHY_SYNTAX)
    return None


def check_dmarc(domain: str, resolver: Resolver) -> CheckResult:
    result = CheckResult("DMARC")
    domain = normalize_name(domain)
    found_at: Optional[str] = None
    records: list[str] = []
    strays: list[tuple[str, str]] = []

    for candidate in _candidates(domain):
        name = f"_dmarc.{candidate}"
        try:
            txts = resolver(name, "TXT")
        except NXDomain:
            txts = []
        except LookupFailed as exc:
            result.summary = "lookup failed"
            result.add(Status.ERROR, f"could not fetch {name}: {exc.reason}", WHY_LOOKUP_FAILED)
            return result
        records = [t for t in txts if _PREFIX.match(t)]
        if records:
            found_at = candidate
            break
        strays.extend((name, t) for t in txts)

    for name, txt in strays:
        result.add(Status.WARN if found_at else Status.FAIL,
                   f"TXT record at {name} is not a DMARC record: {txt[:80]!r}",
                   "a DMARC record must start with v=DMARC1; receivers discard anything else")

    if found_at is None:
        result.summary = "no DMARC record"
        where = f"_dmarc.{domain}" + (" or any parent domain" if domain.count(".") > 1 else "")
        result.add(Status.FAIL, f"no DMARC record at {where}",
                   "nothing tells receivers what to do with mail that fails SPF and DKIM, so spoofing your "
                   "domain costs nothing; Gmail and Yahoo require DMARC from bulk senders")
        return result

    location = f"_dmarc.{found_at}"
    result.details.update({"found_at": location, "records": records})
    if len(records) > 1:
        result.summary = f"{len(records)} DMARC records"
        result.add(Status.FAIL, f"{len(records)} DMARC records at {location}",
                   "RFC 7489 6.6.3: with more than one record receivers apply no DMARC at all")
        return result

    record = records[0]
    inherited = found_at != domain
    if inherited:
        result.add(Status.INFO, f"no record at _dmarc.{domain}; the one at {location} applies")

    parsed = parse_tag_list(record)
    for error in parsed.errors:
        result.add(Status.FAIL, f"invalid syntax: {error}", WHY_SYNTAX)
    tags = parsed.tags

    version = tags.get("v", "")
    if version != "DMARC1":
        if version.lower() == "dmarc1":
            result.add(Status.WARN, f"'v={version}' should be written 'v=DMARC1'",
                       "RFC 7489 defines the version in upper case; a strict receiver may ignore the record")
        else:
            hint = ": tags are separated by semicolons, not commas" if "," in version else ""
            result.add(Status.FAIL, f"version tag reads 'v={version}'{hint}",
                       "receivers ignore a record whose first tag is not exactly v=DMARC1")

    p = _validate_policy(result, tags, "p", Status.FAIL)
    if "p" not in tags:
        result.add(Status.FAIL, "no p= tag (the policy)",
                   "p is required; receivers ignore the record, or treat it as p=none when rua is set")
    sp = _validate_policy(result, tags, "sp", Status.FAIL)
    _validate_policy(result, tags, "np", Status.WARN)

    if inherited:
        policy = sp or p
        policy_label = (f"sp={sp}" if sp else f"p={p}") + f" from {location}"
    else:
        policy = p
        policy_label = f"p={p}"
    if policy == "none":
        result.add(Status.WARN, f"{policy_label}: monitoring only",
                   "failing mail is still delivered; DMARC protects nothing until p=quarantine or p=reject")
    elif policy == "quarantine":
        result.add(Status.PASS, f"{policy_label}: failing mail goes to spam")
    elif policy == "reject":
        result.add(Status.PASS, f"{policy_label}: failing mail is refused")

    pct: Optional[int] = None
    if "pct" in tags:
        raw = tags["pct"]
        if not raw.isdigit() or int(raw) > 100:
            result.add(Status.WARN, f"pct={raw} is not a whole number from 0 to 100", WHY_SYNTAX)
        else:
            pct = int(raw)
            if pct < 100 and policy in WEAKER:
                result.add(Status.WARN, f"pct={pct}: the policy applies to only {pct}% of failing mail",
                           f"the other {100 - pct}% gets the next weaker policy ({policy} -> {WEAKER[policy]}); "
                           "pct is a rollout step, not an end state")

    if not inherited:
        if sp is not None:
            if sp == "none" and p in WEAKER:
                result.add(Status.WARN, f"sp=none while p={p}: subdomains are not protected",
                           f"anyone can send as anything.{domain}; sp applies to every subdomain without "
                           "its own record")
            else:
                result.add(Status.INFO, f"subdomain policy: sp={sp}")
        elif p is not None:
            result.add(Status.INFO, f"subdomains inherit p={p} (no sp=)")

    modes = {}
    for tag in ("adkim", "aspf"):
        raw = tags.get(tag, "r")
        if raw.lower() not in MODES:
            result.add(Status.WARN, f"{tag}={raw} is not r or s", WHY_SYNTAX)
            modes[tag] = None
        else:
            modes[tag] = raw.lower()
    result.add(Status.INFO, "alignment: " + ", ".join(
        f"{'DKIM' if tag == 'adkim' else 'SPF'} {MODES.get(mode or '', 'invalid')}"
        f"{'' if tag in tags else ' (default)'}" for tag, mode in modes.items()))

    addresses: list[str] = []
    if not tags.get("rua"):
        result.add(Status.WARN, "no rua= (aggregate reports)",
                   "without reports you can't see who sends as your domain, so you can't safely move to "
                   "quarantine or reject")
    else:
        addresses, destinations = _report_destinations(result, tags["rua"])
        _check_report_authorization(result, resolver, found_at, destinations)

    for name in parsed.order:
        if name not in KNOWN_TAGS:
            result.add(Status.WARN, f"unknown tag '{name}' is ignored",
                       "receivers skip tags they don't know; check for a typo")

    parts = [f"inherited from {location}"] if inherited else []
    if p:
        parts.append(f"p={p}")
    if sp:
        parts.append(f"sp={sp}")
    if pct is not None and pct < 100:
        parts.append(f"pct={pct}")
    parts.append(f"reports to {', '.join(addresses)}" if addresses else "no reports")
    result.summary = ", ".join(parts)
    result.details.update({
        "record": record,
        "inherited": inherited,
        "tags": tags,
        "policy": policy,
        "subdomain_policy": sp or p,
        "pct": pct,
        "adkim": modes["adkim"],
        "aspf": modes["aspf"],
        "rua": addresses,
    })
    return result
