"""SPF: which servers may send mail for a domain (RFC 7208).

The part most checkers get wrong is the 10-lookup limit. It applies to the whole
evaluation, nested includes and redirects included, and only to the terms that
cost a DNS query: include, a, mx, ptr, exists and redirect. ip4, ip6, all and exp
are free. Terms after ``all`` are never evaluated, so they are not counted, and a
``redirect`` is ignored entirely when the record has an ``all``.

The count is the worst case: a receiver stops at the first matching mechanism, so
a server listed early may still pass a record that is over the limit. The servers
that fail are the ones matched late -- typically the most recently added provider.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any, Optional

from .model import CheckResult, Status
from .resolver import LookupFailed, NXDomain, Resolver, normalize_name

LOOKUP_LIMIT = 10
MAX_RECORDS = 100  # safety net against pathological include trees
MX_ADDRESS_LIMIT = 10
MECHANISMS = frozenset({"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"})
DNS_TERMS = frozenset({"include", "a", "mx", "ptr", "exists", "redirect"})

_VERSION = re.compile(r"^v=spf1(?:\s|$)", re.IGNORECASE)
_MODIFIER = re.compile(r"^([A-Za-z][A-Za-z0-9_.-]*)=(.*)$")
_MECHANISM = re.compile(r"^([+\-~?]?)([A-Za-z][A-Za-z0-9_.-]*)(.*)$")
_DUAL_CIDR = re.compile(r"^(?:/(\d{1,2}))?(?://(\d{1,3}))?$")
_TOP_LABEL = re.compile(r"^[A-Za-z0-9-]*[A-Za-z][A-Za-z0-9-]*$")

WHY_PERMERROR = "a syntax error anywhere makes receivers return permerror: SPF fails for every message"
WHY_LOOKUP_FAILED = "the answer is unknown, not necessarily wrong; retry or try --nameserver 1.1.1.1"


@dataclass
class Term:
    raw: str
    kind: str  # "mechanism" or "modifier"
    name: str
    qualifier: str = ""  # mechanisms only; "+" when omitted
    explicit_qualifier: bool = False
    domain: str = ""  # domain-spec of include/exists/a/mx/ptr/redirect/exp, "" if none
    error: str = ""  # makes the record a permerror
    ignored: str = ""  # silently ignored by receivers, but almost certainly not what was meant

    @property
    def has_macro(self) -> bool:
        return "%" in self.domain

    @property
    def is_valid_mechanism(self) -> bool:
        return self.kind == "mechanism" and not self.error


def is_spf_record(txt: str) -> bool:
    return bool(_VERSION.match(txt))


def spf_records(resolver: Resolver, domain: str) -> list[str]:
    """TXT records of ``domain`` that are SPF records. Raises NXDomain / LookupFailed."""
    return [txt for txt in resolver(domain, "TXT") if is_spf_record(txt)]


def _split_cidr(spec: str) -> tuple[str, str]:
    """Split ``domain/24//64`` at the first ``/`` that is not inside a ``%{...}`` macro."""
    depth = 0
    for i, ch in enumerate(spec):
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(depth - 1, 0)
        elif ch == "/" and depth == 0:
            return spec[:i], spec[i:]
    return spec, ""


def _domain_spec_error(spec: str) -> str:
    if not spec:
        return "missing domain"
    if "%" in spec:
        return ""  # macro: expanded per message, can't be validated statically
    labels = spec.rstrip(".").split(".")
    if len(labels) < 2 or any(not label for label in labels):
        return f"'{spec}' is not a valid domain"
    if any(len(label) > 63 for label in labels):
        return f"'{spec}' has a label longer than 63 characters"
    if not _TOP_LABEL.match(labels[-1]):
        return f"'{spec}' is not a domain (an IP address belongs in ip4:/ip6:)"
    return ""


def _cidr_error(cidr: str) -> str:
    m = _DUAL_CIDR.match(cidr)
    if not m:
        return f"invalid prefix length '{cidr}'"
    v4, v6 = m.group(1), m.group(2)
    if v4 is not None and int(v4) > 32:
        return f"IPv4 prefix /{v4} is larger than 32"
    if v6 is not None and int(v6) > 128:
        return f"IPv6 prefix //{v6} is larger than 128"
    return ""


def _ip_error(name: str, value: str) -> str:
    address, _, prefix = value.partition("/")
    if prefix and not prefix.isdigit():
        return f"invalid prefix length in '{value}'"
    try:
        if name == "ip4":
            ipaddress.IPv4Network(value, strict=False)
        else:
            ipaddress.IPv6Network(value, strict=False)
    except ValueError:
        family = "IPv4" if name == "ip4" else "IPv6"
        return f"'{value}' is not a valid {family} address or network"
    return ""


def parse_term(raw: str) -> Term:
    """Parse one whitespace-separated SPF term (after ``v=spf1``)."""
    m = _MODIFIER.match(raw)
    if m:
        name, value = m.group(1).lower(), m.group(2)
        term = Term(raw, "modifier", name)
        if name in ("redirect", "exp"):
            term.domain = value
            term.error = _domain_spec_error(value)
        elif name in MECHANISMS:
            term.ignored = (
                f"'{name}=' is not the {name} mechanism, it is read as an unknown modifier "
                f"and ignored; write '{name}:'"
            )
        return term

    m = _MECHANISM.match(raw)
    if not m:
        return Term(raw, "mechanism", "", error="not a valid mechanism or modifier")
    name, rest = m.group(2).lower(), m.group(3)
    term = Term(raw, "mechanism", name, qualifier=m.group(1) or "+", explicit_qualifier=bool(m.group(1)))
    if name not in MECHANISMS:
        term.error = f"unknown mechanism '{name}'"
    elif name == "all":
        if rest:
            term.error = "'all' takes no argument"
    elif name in ("ip4", "ip6"):
        if not rest.startswith(":") or len(rest) == 1:
            term.error = f"{name} needs an address, e.g. {name}:{'192.0.2.0/24' if name == 'ip4' else '2001:db8::/32'}"
        else:
            term.error = _ip_error(name, rest[1:])
    elif name in ("include", "exists"):
        if not rest.startswith(":") or len(rest) == 1:
            term.error = f"{name} needs a domain, e.g. {name}:_spf.example.com"
        else:
            term.domain = rest[1:]
            term.error = _domain_spec_error(term.domain)
    elif name == "ptr":
        if rest.startswith(":"):
            term.domain = rest[1:]
            term.error = _domain_spec_error(term.domain)
        elif rest:
            term.error = f"unexpected '{rest}' after ptr"
    else:  # a, mx: [":" domain-spec] [dual-cidr-length]
        if rest.startswith(":"):
            term.domain, cidr = _split_cidr(rest[1:])
            term.error = _domain_spec_error(term.domain)
        elif rest.startswith("/") or not rest:
            cidr = rest
        else:
            cidr = ""
            term.error = f"unexpected '{rest}' after {name}"
        if not term.error and cidr:
            term.error = _cidr_error(cidr)
    return term


def effective_all(node: Optional[dict[str, Any]]) -> Optional[dict[str, str]]:
    """The ``all`` that ends evaluation: the record's own, else its redirect target's."""
    while node is not None:
        if node.get("all"):
            return node["all"]
        node = node.get("redirect")
    return None


class _Walker:
    def __init__(self, resolver: Resolver, result: CheckResult) -> None:
        self.resolver = resolver
        self.result = result
        self.lookups = 0
        self.records_seen = 0
        self.truncated = False
        self._seen_messages: set[tuple[Status, str]] = set()

    def add(self, status: Status, message: str, why: str = "") -> None:
        # The same nested record can be reached through several includes.
        if (status, message) not in self._seen_messages:
            self._seen_messages.add((status, message))
            self.result.add(status, message, why)

    def visit_record(self, domain: str, record: str, chain: list[str], label: str) -> dict[str, Any]:
        self.records_seen += 1
        terms = [parse_term(raw) for raw in record.split()[1:]]
        node: dict[str, Any] = {
            "domain": domain, "record": record, "lookups": 0, "all": None, "includes": [], "redirect": None,
        }

        for term in terms:
            if term.error:
                self.add(Status.FAIL, f"{label}invalid term '{term.raw}': {term.error}", WHY_PERMERROR)
            elif term.ignored:
                self.add(Status.FAIL, f"{label}{term.ignored}",
                         "the servers it was meant to authorize are not authorized, so their mail fails SPF")
        for modifier in ("redirect", "exp"):
            if sum(1 for t in terms if t.kind == "modifier" and t.name == modifier) > 1:
                self.add(Status.FAIL, f"{label}'{modifier}=' appears more than once", WHY_PERMERROR)

        all_index = next((i for i, t in enumerate(terms) if t.is_valid_mechanism and t.name == "all"), None)
        live = terms if all_index is None else terms[: all_index + 1]
        dead = [] if all_index is None else [t.raw for t in terms[all_index + 1:] if t.kind == "mechanism"]
        if dead:
            self.add(Status.WARN, f"{label}terms after 'all' are never evaluated: {' '.join(dead)}",
                     "evaluation stops at 'all', which matches every server; move them before it")
        if all_index is not None:
            all_term = terms[all_index]
            node["all"] = {"qualifier": all_term.qualifier, "term": all_term.raw, "domain": domain,
                           "explicit": all_term.explicit_qualifier}

        if any(t.is_valid_mechanism and t.name == "ptr" for t in live):
            self.add(Status.WARN, f"{label}uses the 'ptr' mechanism",
                     "RFC 7208 5.5 says not to publish it: slow, unreliable, and some receivers skip it")

        redirect = next((t for t in terms if t.kind == "modifier" and t.name == "redirect" and not t.error), None)
        if redirect is not None and all_index is not None:
            self.add(Status.WARN, f"{label}redirect={redirect.domain} is ignored because the record has an 'all'",
                     "RFC 7208 6.1: with 'all' present the redirect is never followed")
            redirect = None

        counted = [t for t in live if t.is_valid_mechanism and t.name in DNS_TERMS]
        node["lookups"] = len(counted) + (1 if redirect is not None else 0)
        self.lookups += node["lookups"]

        for term in counted:
            if term.has_macro:
                self.add(Status.INFO, f"{label}'{term.raw}' uses macros: counted as one lookup, not followed")
            elif term.name == "include":
                child = self.descend(term, "include", chain, label)
                if child is not None:
                    node["includes"].append(child)
                    included_all = effective_all(child)
                    if included_all and included_all["qualifier"] == "+" and term.qualifier == "+":
                        self.add(Status.FAIL, f"{label}include:{child['domain']} ends in '{included_all['term']}', "
                                              "so the include matches every server",
                                 "an include passes when the included record passes; with +all inside, "
                                 "any server on the internet passes your SPF")
            elif term.name == "mx":
                self.check_mx_count(term, domain, label)

        if redirect is not None:
            if redirect.has_macro:
                self.add(Status.INFO, f"{label}'{redirect.raw}' uses macros: counted as one lookup, not followed")
            else:
                node["redirect"] = self.descend(redirect, "redirect", chain, label)
        return node

    def descend(self, term: Term, via: str, chain: list[str], label: str) -> Optional[dict[str, Any]]:
        target = normalize_name(term.domain)
        if target in chain:
            path = " -> ".join(chain + [target])
            self.add(Status.FAIL, f"{label}{via}:{target} loops back into the chain ({path})",
                     "the evaluation never ends; receivers hit the lookup limit and return permerror")
            return None
        if len(chain) > LOOKUP_LIMIT or self.records_seen >= MAX_RECORDS:
            self.truncated = True  # already past the limit; stop following
            return None
        error_node = {"domain": target, "record": None, "lookups": 0, "all": None, "includes": [], "redirect": None}
        try:
            records = spf_records(self.resolver, target)
        except NXDomain:
            self.add(Status.FAIL, f"{label}{via}:{target} does not exist",
                     "an include or redirect to a missing domain is a permanent error: SPF fails for every "
                     "message (common after leaving a provider)")
            return error_node
        except LookupFailed as exc:
            self.add(Status.ERROR, f"{label}could not fetch {via}:{target} ({exc.reason})",
                     "that branch was not counted, so the lookup total is a lower bound")
            return error_node
        if not records:
            self.add(Status.FAIL, f"{label}{via}:{target} has no SPF record",
                     "RFC 7208 5.2/6.1: an include or redirect that finds no SPF record is a permanent error, "
                     "not a no-op")
            return error_node
        if len(records) > 1:
            self.add(Status.FAIL, f"{label}{via}:{target} publishes {len(records)} SPF records",
                     "more than one SPF record is a permanent error, and it propagates to your record")
            return error_node
        return self.visit_record(target, records[0], chain + [target], f"[{via}:{target}] ")

    def check_mx_count(self, term: Term, domain: str, label: str) -> None:
        target = normalize_name(term.domain) if term.domain else domain
        try:
            hosts = self.resolver(target, "MX")
        except (NXDomain, LookupFailed):
            return
        if len(hosts) > MX_ADDRESS_LIMIT:
            self.add(Status.FAIL, f"{label}'{term.raw}': {target} has {len(hosts)} MX hosts, more than the "
                                  f"{MX_ADDRESS_LIMIT} the mx mechanism may resolve",
                     "RFC 7208 4.6.4: past 10 address lookups the mx mechanism returns permerror")


def check_spf(domain: str, resolver: Resolver) -> CheckResult:
    result = CheckResult("SPF")
    try:
        txts = resolver(domain, "TXT")
    except NXDomain:
        result.summary = "domain does not exist"
        result.add(Status.FAIL, f"{domain} does not exist (NXDOMAIN)",
                   "nothing can be authenticated for a domain that does not resolve")
        return result
    except LookupFailed as exc:
        result.summary = "lookup failed"
        result.add(Status.ERROR, f"could not fetch TXT records of {domain}: {exc.reason}", WHY_LOOKUP_FAILED)
        return result

    records = [t for t in txts if is_spf_record(t)]
    near_misses = [t for t in txts if not is_spf_record(t) and "v=spf1" in t.lower()]
    result.details["records"] = records
    for txt in near_misses:
        result.add(Status.WARN if records else Status.FAIL,
                   f"TXT record mentions v=spf1 but does not start with 'v=spf1 ': {txt[:80]!r}",
                   "receivers only read records that begin exactly with v=spf1 (stray quotes or spaces?); "
                   "this one is ignored")

    if not records:
        result.summary = "no SPF record"
        result.add(Status.FAIL, "no SPF record",
                   "receivers can't tell which servers may send as you; Gmail and Yahoo require SPF or DKIM "
                   "from every sender")
        return result
    if len(records) > 1:
        result.add(Status.FAIL, f"{len(records)} SPF records published; there must be exactly one",
                   "RFC 7208 4.5: several SPF records is a permanent error, SPF fails for every message; "
                   "merge them into one (analysis below uses the first)")

    walker = _Walker(resolver, result)
    tree = walker.visit_record(normalize_name(domain), records[0], [normalize_name(domain)], "")
    total = walker.lookups
    lower_bound = walker.truncated or result.has(Status.ERROR)
    shown = f"{total}{'+' if lower_bound else ''}"

    if total > LOOKUP_LIMIT:
        result.add(Status.FAIL, f"{shown} DNS lookups; RFC 7208 allows {LOOKUP_LIMIT}",
                   "receivers return permerror as soon as an 11th lookup is needed: every server not matched "
                   "before that point fails SPF, usually the provider listed last")
    elif total >= LOOKUP_LIMIT - 1:
        result.add(Status.WARN, f"{shown}/{LOOKUP_LIMIT} DNS lookups, at the edge of the limit",
                   "nested includes belong to your providers and change without notice; one more and SPF breaks")
    else:
        result.add(Status.PASS, f"{shown}/{LOOKUP_LIMIT} DNS lookups")
    if walker.truncated:
        result.add(Status.INFO, "stopped following includes once the limit was clearly exceeded")

    final = effective_all(tree)
    via = f" via redirect={final['domain']}" if final and final["domain"] != tree["domain"] else ""
    if final is None:
        result.add(Status.WARN, "no 'all' at the end and no redirect",
                   "servers you did not list get 'neutral', which receivers treat like having no SPF")
        ending = "no all"
    else:
        ending = final["term"]
        qualifier = final["qualifier"]
        ends = f"ends in '{final['term']}'{via}"
        if qualifier == "+":
            bare = "" if final["explicit"] else " ('all' without a qualifier means +all)"
            result.add(Status.FAIL, f"{ends}{bare}",
                       "+all authorizes every server on the internet to send as your domain")
        elif qualifier == "?":
            result.add(Status.WARN, f"{ends} (neutral)",
                       "unlisted servers are neither allowed nor refused, so SPF protects nothing")
        elif qualifier == "~":
            result.add(Status.PASS, f"{ends} (softfail): unlisted servers are flagged")
        else:
            result.add(Status.PASS, f"{ends} (fail): unlisted servers are refused")

    count = f"{shown} lookups (limit {LOOKUP_LIMIT})" if total > LOOKUP_LIMIT else f"{shown}/{LOOKUP_LIMIT} lookups"
    result.summary = f"{count}, ends in {ending}{via}"
    result.details.update({
        "lookups": total,
        "lookups_is_lower_bound": lower_bound,
        "limit": LOOKUP_LIMIT,
        "all": final["term"] if final else None,
        "tree": tree,
    })
    return result
