import io
import json

import pytest

from email_auth_checker.cli import main, normalize_domain
from email_auth_checker.report import check_domain, render_text
from fakes import RSA_2048, FakeResolver, timeout

HEALTHY = {
    "example.com": {
        "TXT": ["v=spf1 include:_spf.mailhost.example -all"],
        "MX": ["10 mx.example.com"],
    },
    "_spf.mailhost.example": {"TXT": ["v=spf1 ip4:192.0.2.0/24 ~all"]},
    "_dmarc.example.com": {"TXT": ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"]},
    "google._domainkey.example.com": {"TXT": [f"v=DKIM1; k=rsa; p={RSA_2048}"]},
    "mx.example.com": {"A": ["192.0.2.25"]},
}

BROKEN = {
    "broken.example": {"TXT": ["v=spf1 +all"], "MX": ["0 ."]},
}


def run(*args, zone=None, resolver=None):
    out, err = io.StringIO(), io.StringIO()
    code = main(list(args), resolver=resolver or FakeResolver(zone if zone is not None else HEALTHY),
                stdout=out, stderr=err)
    return code, out.getvalue(), err.getvalue()


# --- exit codes ------------------------------------------------------------------

def test_healthy_domain_exits_zero():
    code, out, _ = run("example.com")
    assert code == 0
    assert "example.com  PASS" in out


def test_any_fail_exits_one():
    code, out, _ = run("broken.example", zone=BROKEN)
    assert code == 1
    assert "FAIL" in out and "why:" in out


def test_one_failing_domain_among_several_exits_one():
    code, out, _ = run("example.com", "broken.example", zone={**HEALTHY, **BROKEN})
    assert code == 1
    assert "example.com  PASS" in out and "broken.example  FAIL" in out


def test_usage_errors_exit_two(capsys):
    assert run("not a domain")[0] == 2
    assert run("192.0.2.1")[0] == 2
    assert run("example.com", "--selector", "bad selector!")[0] == 2
    assert run("example.com", "--nameserver", "dns.google")[0] == 2
    assert run("example.com", "--timeout", "0")[0] == 2
    assert run()[0] == 2  # argparse: DOMAIN is required
    capsys.readouterr()


def test_help_exits_zero(capsys):
    assert run("--help")[0] == 0
    assert "exit codes" in capsys.readouterr().out


def test_dns_failures_without_fail_exit_three():
    class Down:
        def __call__(self, name, rdtype):
            raise timeout(name, rdtype)

    code, out, _ = run("example.com", resolver=Down())
    assert code == 3
    assert "ERROR" in out and "could not be checked" in out


def test_unexpected_exception_in_a_check_never_crashes():
    class Buggy(FakeResolver):
        def __call__(self, name, rdtype):
            if rdtype == "MX":
                raise RuntimeError("boom")
            return super().__call__(name, rdtype)

    code, out, _ = run("example.com", resolver=Buggy(HEALTHY))
    assert code == 3
    assert "internal error: RuntimeError: boom" in out
    assert "SPF    PASS" in out  # the other checks still ran


# --- output ----------------------------------------------------------------------

def test_json_output():
    code, out, _ = run("example.com", "broken.example", "--json", zone={**HEALTHY, **BROKEN})
    data = json.loads(out)
    assert code == data["exit_code"] == 1
    assert [d["domain"] for d in data["domains"]] == ["example.com", "broken.example"]
    healthy, broken = data["domains"]
    assert set(healthy["checks"]) == {"spf", "dmarc", "dkim", "mx"}
    assert healthy["checks"]["spf"]["details"]["lookups"] == 1
    assert healthy["checks"]["dkim"]["details"]["keys"][0]["bits"] == 2048
    assert broken["checks"]["spf"]["status"] == "FAIL"
    first = broken["checks"]["spf"]["findings"][0]
    assert first["status"] == "FAIL" and first["why"]


def test_selector_option_accepts_commas_and_repeats():
    zone = {**HEALTHY, "acme._domainkey.example.com": {"TXT": [f"p={RSA_2048}"]}}
    code, out, _ = run("example.com", "-s", "acme,other", "-s", "third", "--json", zone=zone)
    checked = json.loads(out)["domains"][0]["checks"]["dkim"]["details"]["selectors_checked"]
    assert checked[:3] == ["acme", "other", "third"]
    assert code == 1  # "other" and "third" were requested but have no key


def test_verbose_shows_passes_and_spf_tree():
    _, out, _ = run("example.com", "-v")
    assert "PASS   1/10 DNS lookups" in out
    assert "include:_spf.mailhost.example  0" in out


def test_no_ansi_codes_when_not_a_tty():
    _, out, _ = run("example.com")
    assert "\033[" not in out


def test_render_text_with_color():
    report = check_domain("broken.example", FakeResolver(BROKEN))
    assert "\033[1;31mFAIL \033[0m" in render_text([report], color=True)


def test_duplicate_domains_checked_once():
    _, out, _ = run("example.com", "EXAMPLE.com.", "--json")
    assert len(json.loads(out)["domains"]) == 1


# --- domain normalization -------------------------------------------------------------

@pytest.mark.parametrize("raw, expected", [
    ("Example.COM.", "example.com"),
    ("https://www.example.com/contact?x=1", "www.example.com"),
    ("postmaster@example.com", "example.com"),
    ("example.com/path", "example.com"),
    ("  example.com  ", "example.com"),
    ("bücher.example", "xn--bcher-kva.example"),
])
def test_normalize_domain(raw, expected):
    assert normalize_domain(raw) == expected


@pytest.mark.parametrize("raw", ["", "localhost", "exa mple.com", "-bad.example.com", "a..b.com", "192.0.2.1",
                                 "x" * 64 + ".com"])
def test_normalize_domain_rejects(raw):
    with pytest.raises(ValueError):
        normalize_domain(raw)
