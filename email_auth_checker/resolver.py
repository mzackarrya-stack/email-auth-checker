"""The only module that talks to the network.

Every check receives a *resolver function* ``(name, rdtype) -> list[str]`` instead
of calling dnspython directly, so tests can pass a dictionary-backed fake and
never touch the network.

Contract of a resolver function:

* returns a list of strings, one per record:
  - TXT: the record's character-strings joined with no separator (RFC 7208 3.3,
    RFC 6376 3.6.2.2 -- a 2048-bit DKIM key never fits in one 255-byte string)
  - MX: ``"<preference> <exchange>"``, e.g. ``"10 mx1.example.com"``; a null MX
    (RFC 7505) is ``"0 ."``
  - A / AAAA: the address
* returns ``[]`` when the name exists but has no record of that type
* raises :class:`NXDomain` when the name does not exist
* raises :class:`LookupFailed` when the answer is unknown (timeout, SERVFAIL...)
"""

from __future__ import annotations

import threading
from typing import Callable, Sequence

Resolver = Callable[[str, str], list]


class DNSError(Exception):
    def __init__(self, name: str, rdtype: str, reason: str = "") -> None:
        self.name = name
        self.rdtype = rdtype
        self.reason = reason
        super().__init__(f"{name} {rdtype}: {reason}" if reason else f"{name} {rdtype}")


class NXDomain(DNSError):
    """The name does not exist."""


class LookupFailed(DNSError):
    """The lookup did not produce an answer, so the result is unknown."""


def normalize_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


def txt_to_str(strings: Sequence[bytes]) -> str:
    """Join the character-strings of one TXT record the way SPF/DKIM/DMARC require."""
    return b"".join(strings).decode("utf-8", errors="replace")


def cached(resolver: Resolver) -> Resolver:
    """Memoize answers (and NXDOMAIN/failures) for the duration of one run.

    SPF trees often include the same provider record from several branches;
    without a cache each branch would query it again.
    """
    cache: dict[tuple[str, str], object] = {}
    lock = threading.Lock()

    def resolve(name: str, rdtype: str) -> list:
        key = (normalize_name(name), rdtype.upper())
        with lock:
            hit = cache.get(key)
        if hit is None:
            try:
                hit = list(resolver(*key))
            except DNSError as exc:
                hit = exc
            with lock:
                cache[key] = hit
        if isinstance(hit, DNSError):
            raise hit
        return list(hit)

    return resolve


def system_resolver(timeout: float = 5.0, nameservers: Sequence[str] | None = None) -> Resolver:
    """Resolver function backed by dnspython and the system (or given) nameservers.

    Raises :class:`RuntimeError` if no nameserver configuration can be found.
    """
    import dns.exception
    import dns.resolver

    try:
        if nameservers:
            res = dns.resolver.Resolver(configure=False)
            res.nameservers = list(nameservers)
        else:
            res = dns.resolver.Resolver()
    except dns.resolver.NoResolverConfiguration as exc:  # pragma: no cover - environment specific
        raise RuntimeError("no DNS resolver configuration found; pass --nameserver") from exc
    res.lifetime = timeout
    res.timeout = min(timeout, 2.0)

    def resolve(name: str, rdtype: str) -> list:
        name = normalize_name(name)
        try:
            answer = res.resolve(name + ".", rdtype, search=False)
        except dns.resolver.NXDOMAIN:
            raise NXDomain(name, rdtype, "does not exist") from None
        except dns.resolver.NoAnswer:
            return []
        except dns.resolver.NoNameservers:
            raise LookupFailed(name, rdtype, "no nameserver answered (SERVFAIL or refused)") from None
        except dns.exception.Timeout:
            raise LookupFailed(name, rdtype, f"timed out after {timeout:g}s") from None
        except (dns.exception.DNSException, OSError, ValueError) as exc:
            raise LookupFailed(name, rdtype, f"{type(exc).__name__}: {exc}") from None
        if rdtype == "TXT":
            return [txt_to_str(rr.strings) for rr in answer]
        if rdtype == "MX":
            return [f"{rr.preference} {rr.exchange.to_text(omit_final_dot=True) or '.'}" for rr in answer]
        return [rr.to_text() for rr in answer]

    return resolve
