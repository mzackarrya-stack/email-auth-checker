from email_auth_checker.model import Status
from email_auth_checker.mx import check_mx
from fakes import FakeResolver, has_message, timeout


def test_hosts_sorted_by_preference():
    resolver = FakeResolver({
        "example.com": {"MX": ["20 mx2.example.com", "10 mx1.example.com"]},
        "mx1.example.com": {"A": ["192.0.2.10"]},
        "mx2.example.com": {"AAAA": ["2001:db8::25"]},
    })
    result = check_mx("example.com", resolver)
    assert result.status is Status.PASS
    assert [h["host"] for h in result.details["hosts"]] == ["mx1.example.com", "mx2.example.com"]
    assert result.summary == "2 hosts, primary mx1.example.com"


def test_null_mx():
    result = check_mx("example.com", FakeResolver({"example.com": {"MX": ["0 ."]}}))
    assert result.status is Status.WARN
    assert has_message(result, Status.WARN, "null MX")


def test_null_mx_mixed_with_real_hosts_is_malformed():
    resolver = FakeResolver({"example.com": {"MX": ["0 .", "10 mx.example.com"]}, "mx.example.com": {"A": ["192.0.2.1"]}})
    assert has_message(check_mx("example.com", resolver), Status.FAIL, "null MX")


def test_no_mx_with_address_falls_back():
    result = check_mx("example.com", FakeResolver({"example.com": {"A": ["192.0.2.1"]}}))
    assert result.status is Status.WARN
    assert has_message(result, Status.WARN, "no MX record")


def test_no_mx_and_no_address_fails():
    result = check_mx("example.com", FakeResolver({"example.com": {"TXT": ["v=spf1 -all"]}}))
    assert result.status is Status.FAIL
    assert has_message(result, Status.FAIL, "cannot receive mail")


def test_nxdomain_fails():
    assert check_mx("nope.example", FakeResolver({})).status is Status.FAIL


def test_dangling_host_is_warned():
    resolver = FakeResolver({
        "example.com": {"MX": ["10 mx1.example.com", "20 gone.example.com"]},
        "mx1.example.com": {"A": ["192.0.2.10"]},
    })
    result = check_mx("example.com", resolver)
    assert result.status is Status.WARN
    assert has_message(result, Status.WARN, "gone.example.com has no A/AAAA")


def test_all_hosts_dangling_fails():
    resolver = FakeResolver({"example.com": {"MX": ["10 gone.example.com"]}})
    assert has_message(check_mx("example.com", resolver), Status.FAIL, "no MX host has an address")


def test_mx_pointing_to_ip_address():
    resolver = FakeResolver({"example.com": {"MX": ["10 192.0.2.25"]}})
    assert has_message(check_mx("example.com", resolver), Status.FAIL, "points to an IP address")


def test_timeout_is_an_error():
    result = check_mx("example.com", FakeResolver({"example.com": {"MX": timeout("example.com", "MX")}}))
    assert result.status is Status.ERROR


def test_host_address_timeout_is_not_a_failure():
    resolver = FakeResolver({
        "example.com": {"MX": ["10 mx.example.com"]},
        "mx.example.com": {"A": timeout(), "AAAA": timeout()},
    })
    result = check_mx("example.com", resolver)
    assert result.status is Status.PASS
    assert has_message(result, Status.INFO, "could not resolve MX host mx.example.com")
