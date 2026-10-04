"""The dnspython adapter, exercised with a patched Resolver.resolve (no network)."""

import dns.exception
import dns.rdata
import dns.resolver
import pytest

from email_auth_checker.resolver import LookupFailed, NXDomain, cached, system_resolver, txt_to_str


def patched(monkeypatch, behaviour):
    def fake_resolve(self, qname, rdtype, *args, **kwargs):
        return behaviour(str(qname), rdtype)

    monkeypatch.setattr(dns.resolver.Resolver, "resolve", fake_resolve)
    return system_resolver(timeout=1.0, nameservers=["192.0.2.53"])


def test_txt_character_strings_are_joined_without_separator():
    assert txt_to_str([b"v=spf1 include:_spf.goo", b"gle.com ~all"]) == "v=spf1 include:_spf.google.com ~all"


def test_txt_answer(monkeypatch):
    rdata = dns.rdata.from_text("IN", "TXT", '"v=DKIM1; k=rsa; p=MIIBIjAN" "BgkqhkiG9w0BAQEFAAOCAQ8A"')
    resolve = patched(monkeypatch, lambda name, rdtype: [rdata])
    assert resolve("example.com", "TXT") == ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"]


def test_mx_answer_including_null_mx(monkeypatch):
    answers = [dns.rdata.from_text("IN", "MX", "10 mx.example.com."), dns.rdata.from_text("IN", "MX", "0 .")]
    resolve = patched(monkeypatch, lambda name, rdtype: answers)
    assert resolve("example.com", "MX") == ["10 mx.example.com", "0 ."]


def test_query_name_is_absolute(monkeypatch):
    seen = []
    resolve = patched(monkeypatch, lambda name, rdtype: seen.append(name) or [])
    resolve("Example.COM.", "TXT")
    assert seen == ["example.com."]


@pytest.mark.parametrize("exc, expected", [
    (dns.resolver.NXDOMAIN(), NXDomain),
    (dns.resolver.NoNameservers(), LookupFailed),
    (dns.exception.Timeout(), LookupFailed),
    (dns.resolver.LifetimeTimeout(timeout=1.0, errors=[]), LookupFailed),
    (OSError("network unreachable"), LookupFailed),
])
def test_errors_are_mapped(monkeypatch, exc, expected):
    def boom(name, rdtype):
        raise exc

    resolve = patched(monkeypatch, boom)
    with pytest.raises(expected):
        resolve("example.com", "TXT")


def test_no_answer_is_an_empty_list(monkeypatch):
    def no_answer(name, rdtype):
        raise dns.resolver.NoAnswer()

    assert patched(monkeypatch, no_answer)("example.com", "TXT") == []


def test_cache_memoizes_answers_and_errors():
    calls = []

    def base(name, rdtype):
        calls.append((name, rdtype))
        if name == "missing.example":
            raise NXDomain(name, rdtype)
        return ["v=spf1 -all"]

    resolve = cached(base)
    assert resolve("Example.com.", "TXT") == resolve("example.com", "txt") == ["v=spf1 -all"]
    for _ in range(2):
        with pytest.raises(NXDomain):
            resolve("missing.example", "TXT")
    assert calls == [("example.com", "TXT"), ("missing.example", "TXT")]
