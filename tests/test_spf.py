import pytest

from email_auth_checker.model import Status
from email_auth_checker.spf import check_spf, parse_term
from fakes import FakeResolver, has_message, messages, timeout


def spf(record, **extra):
    """Zone with example.com publishing ``record`` plus any extra names."""
    zone = {"example.com": {"TXT": [record] if isinstance(record, str) else record}}
    zone.update(extra)
    return FakeResolver(zone)


def txt(*records):
    return {"TXT": list(records)}


# --- term parsing ----------------------------------------------------------------

@pytest.mark.parametrize("raw, name, qualifier, domain", [
    ("-all", "all", "-", ""),
    ("all", "all", "+", ""),
    ("~ALL", "all", "~", ""),
    ("include:_spf.google.com", "include", "+", "_spf.google.com"),
    ("?include:spf.example.net", "include", "?", "spf.example.net"),
    ("a", "a", "+", ""),
    ("a/24", "a", "+", ""),
    ("mx:mail.example.com/24//64", "mx", "+", "mail.example.com"),
    ("ip4:192.0.2.0/24", "ip4", "+", ""),
    ("ip6:2001:db8::/32", "ip6", "+", ""),
    ("exists:%{i}._spf.example.com", "exists", "+", "%{i}._spf.example.com"),
    ("ptr", "ptr", "+", ""),
])
def test_parse_valid_mechanisms(raw, name, qualifier, domain):
    term = parse_term(raw)
    assert (term.kind, term.name, term.qualifier, term.domain, term.error) == ("mechanism", name, qualifier, domain, "")


@pytest.mark.parametrize("raw, fragment", [
    ("ipv4:192.0.2.1", "unknown mechanism"),
    ("ip4:192.0.2.0/33", "not a valid IPv4"),
    ("ip4:2001:db8::1", "not a valid IPv4"),
    ("ip6:192.0.2.1", "not a valid IPv6"),
    ("ip4", "needs an address"),
    ("include", "needs a domain"),
    ("include:", "needs a domain"),
    ("include:192.0.2.1", "IP address belongs in ip4"),
    ("include:localhost", "not a valid domain"),
    ("all:example.com", "takes no argument"),
    ("a/40", "larger than 32"),
    ("mx//200", "larger than 128"),
    ("redirect=", "missing domain"),
])
def test_parse_invalid_terms(raw, fragment):
    assert fragment in parse_term(raw).error


def test_macro_slash_is_not_a_cidr():
    term = parse_term("a:%{ir/}.example.com/24")
    assert term.domain == "%{ir/}.example.com" and term.error == ""


def test_modifier_named_like_a_mechanism_is_flagged():
    term = parse_term("include=_spf.google.com")
    assert term.kind == "modifier" and term.error == "" and "ignored" in term.ignored


# --- presence --------------------------------------------------------------------

def test_no_spf_record_fails():
    result = check_spf("example.com", spf(["google-site-verification=abc"]))
    assert result.status is Status.FAIL
    assert "no SPF record" in messages(result, Status.FAIL)


def test_domain_does_not_exist():
    result = check_spf("nope.example", FakeResolver({}))
    assert result.status is Status.FAIL
    assert has_message(result, Status.FAIL, "does not exist")


def test_multiple_spf_records_is_a_permerror():
    result = check_spf("example.com", spf(["v=spf1 -all", "v=spf1 include:_spf.google.com ~all"]))
    assert result.status is Status.FAIL
    assert has_message(result, Status.FAIL, "2 SPF records")


def test_version_must_be_followed_by_space():
    result = check_spf("example.com", spf(["v=spf10 -all"]))
    assert "no SPF record" in messages(result, Status.FAIL)


def test_record_with_stray_quotes_is_called_out():
    result = check_spf("example.com", spf(['"v=spf1 -all"']))
    assert has_message(result, Status.FAIL, "does not start with 'v=spf1 '")


def test_txt_lookup_timeout_is_an_error_not_a_fail():
    result = check_spf("example.com", FakeResolver({"example.com": {"TXT": timeout()}}))
    assert result.status is Status.ERROR


# --- lookup counting -------------------------------------------------------------

def test_counts_only_dns_terms():
    resolver = spf(
        "v=spf1 a mx ip4:192.0.2.0/24 ip6:2001:db8::/32 include:spf.provider.net exp=explain.example.com -all",
        **{"spf.provider.net": txt("v=spf1 ip4:198.51.100.0/24 ~all")},
    )
    result = check_spf("example.com", resolver)
    assert result.details["lookups"] == 3  # a, mx, include; ip4/ip6/all/exp are free
    assert result.status is Status.PASS


def test_nested_includes_are_counted_recursively():
    resolver = spf(
        "v=spf1 include:one.example.net -all",
        **{
            "one.example.net": txt("v=spf1 include:two.example.net a ~all"),
            "two.example.net": txt("v=spf1 include:three.example.net mx ~all"),
            "three.example.net": txt("v=spf1 ip4:192.0.2.1 exists:%{i}.rbl.example.net ~all"),
        },
    )
    result = check_spf("example.com", resolver)
    # include one(1) + include two(1) + a(1) + include three(1) + mx(1) + exists(1)
    assert result.details["lookups"] == 6


def test_exactly_ten_lookups_is_allowed_but_warned():
    record = "v=spf1 " + " ".join(f"a:host{i}.example.com" for i in range(10)) + " -all"
    result = check_spf("example.com", spf(record))
    assert result.details["lookups"] == 10
    assert result.status is Status.WARN


def test_eleven_lookups_fails():
    record = "v=spf1 " + " ".join(f"a:host{i}.example.com" for i in range(11)) + " -all"
    result = check_spf("example.com", spf(record))
    assert result.details["lookups"] == 11
    assert has_message(result, Status.FAIL, "11 DNS lookups")


def test_limit_exceeded_through_nested_includes():
    providers = {f"spf{i}.example.net": txt(f"v=spf1 include:inner{i}.example.net ~all") for i in range(6)}
    providers.update({f"inner{i}.example.net": txt("v=spf1 ip4:192.0.2.1 ~all") for i in range(6)})
    record = "v=spf1 " + " ".join(f"include:spf{i}.example.net" for i in range(6)) + " -all"
    result = check_spf("example.com", spf(record, **providers))
    assert result.details["lookups"] == 12
    assert result.status is Status.FAIL


def test_include_loop_is_detected_and_terminates():
    resolver = spf(
        "v=spf1 include:a.example.net -all",
        **{
            "a.example.net": txt("v=spf1 include:b.example.net ~all"),
            "b.example.net": txt("v=spf1 include:a.example.net ~all"),
        },
    )
    result = check_spf("example.com", resolver)
    assert has_message(result, Status.FAIL, "loops back")
    assert resolver.count("a.example.net", "TXT") == 1


def test_self_include_is_a_loop():
    result = check_spf("example.com", spf("v=spf1 include:example.com -all"))
    assert has_message(result, Status.FAIL, "example.com -> example.com")


def test_same_include_reached_twice_is_counted_twice():
    resolver = spf(
        "v=spf1 include:left.example.net include:right.example.net -all",
        **{
            "left.example.net": txt("v=spf1 include:shared.example.net ~all"),
            "right.example.net": txt("v=spf1 include:shared.example.net ~all"),
            "shared.example.net": txt("v=spf1 a mx ~all"),
        },
    )
    result = check_spf("example.com", resolver)
    # 2 top includes + 2 nested includes + (a + mx) twice
    assert result.details["lookups"] == 8
    assert not has_message(result, Status.FAIL, "loops back")


def test_deep_chain_stops_without_recursing_forever():
    zone = {f"l{i}.example.net": txt(f"v=spf1 include:l{i + 1}.example.net ~all") for i in range(30)}
    result = check_spf("example.com", spf("v=spf1 include:l0.example.net -all", **zone))
    assert result.status is Status.FAIL
    assert result.details["lookups"] > 10
    assert result.details["lookups_is_lower_bound"] is True


def test_redirect_counts_and_supplies_the_final_all():
    resolver = spf("v=spf1 redirect=_spf.example.net",
                   **{"_spf.example.net": txt("v=spf1 ip4:192.0.2.0/24 ~all")})
    result = check_spf("example.com", resolver)
    assert result.details["lookups"] == 1
    assert result.details["all"] == "~all"
    assert result.status is Status.PASS
    assert "via redirect=_spf.example.net" in result.summary


def test_redirect_is_ignored_when_record_has_all():
    resolver = spf("v=spf1 ip4:192.0.2.1 redirect=_spf.example.net -all",
                   **{"_spf.example.net": txt("v=spf1 a mx ~all")})
    result = check_spf("example.com", resolver)
    assert result.details["lookups"] == 0
    assert has_message(result, Status.WARN, "is ignored")
    assert resolver.count("_spf.example.net", "TXT") == 0


def test_terms_after_all_are_not_evaluated_or_counted():
    result = check_spf("example.com", spf("v=spf1 -all include:spf.example.net a"))
    assert result.details["lookups"] == 0
    assert has_message(result, Status.WARN, "never evaluated: include:spf.example.net a")


def test_include_without_spf_record_is_a_permerror():
    resolver = spf("v=spf1 include:old-provider.example.net -all",
                   **{"old-provider.example.net": txt("some unrelated text")})
    result = check_spf("example.com", resolver)
    assert has_message(result, Status.FAIL, "has no SPF record")


def test_include_of_missing_domain_is_a_permerror():
    result = check_spf("example.com", spf("v=spf1 include:gone.example.net -all"))
    assert has_message(result, Status.FAIL, "include:gone.example.net does not exist")


def test_include_timeout_makes_the_count_a_lower_bound():
    resolver = spf("v=spf1 include:slow.example.net a -all", **{"slow.example.net": {"TXT": timeout()}})
    result = check_spf("example.com", resolver)
    assert result.status is Status.ERROR
    assert result.details["lookups_is_lower_bound"] is True
    assert "2+/10" in result.summary


def test_macros_are_counted_but_not_followed():
    resolver = spf("v=spf1 exists:%{i}._spf.example.com include:%{d}.example.net -all")
    result = check_spf("example.com", resolver)
    assert result.details["lookups"] == 2
    assert resolver.queries == [("example.com", "TXT")]


def test_mx_mechanism_with_more_than_ten_hosts():
    hosts = [f"{i} mx{i}.example.com" for i in range(11)]
    resolver = FakeResolver({"example.com": {"TXT": ["v=spf1 mx -all"], "MX": hosts}})
    result = check_spf("example.com", resolver)
    assert has_message(result, Status.FAIL, "11 MX hosts")


# --- the final "all" -------------------------------------------------------------

@pytest.mark.parametrize("record, status, fragment", [
    ("v=spf1 ip4:192.0.2.1 +all", Status.FAIL, "ends in '+all'"),
    ("v=spf1 ip4:192.0.2.1 all", Status.FAIL, "without a qualifier means +all"),
    ("v=spf1 ip4:192.0.2.1 ?all", Status.WARN, "(neutral)"),
    ("v=spf1 ip4:192.0.2.1", Status.WARN, "no 'all'"),
    ("v=spf1 ip4:192.0.2.1 ~all", Status.PASS, "(softfail)"),
    ("v=spf1 ip4:192.0.2.1 -all", Status.PASS, "(fail)"),
])
def test_final_all(record, status, fragment):
    result = check_spf("example.com", spf(record))
    assert result.status is status
    assert has_message(result, status, fragment)


def test_plus_all_inside_an_include_is_critical():
    resolver = spf("v=spf1 include:sloppy.example.net -all",
                   **{"sloppy.example.net": txt("v=spf1 ip4:192.0.2.1 +all")})
    result = check_spf("example.com", resolver)
    assert has_message(result, Status.FAIL, "include matches every server")


def test_softfail_inside_an_include_is_fine():
    resolver = spf("v=spf1 include:ok.example.net -all", **{"ok.example.net": txt("v=spf1 ip4:192.0.2.1 ?all")})
    assert check_spf("example.com", resolver).status is Status.PASS


# --- other problems --------------------------------------------------------------

def test_ptr_is_deprecated_and_counted():
    result = check_spf("example.com", spf("v=spf1 ptr -all"))
    assert has_message(result, Status.WARN, "'ptr'")
    assert result.details["lookups"] == 1


def test_unknown_mechanism_is_a_permerror():
    result = check_spf("example.com", spf("v=spf1 ipv4:192.0.2.1 -all"))
    assert has_message(result, Status.FAIL, "unknown mechanism 'ipv4'")


def test_include_written_with_equals_sign():
    result = check_spf("example.com", spf("v=spf1 include=_spf.google.com -all"))
    assert has_message(result, Status.FAIL, "write 'include:'")
    assert result.details["lookups"] == 0


def test_duplicate_redirect_is_a_permerror():
    result = check_spf("example.com", spf("v=spf1 redirect=a.example.net redirect=b.example.net"))
    assert has_message(result, Status.FAIL, "appears more than once")


def test_errors_in_nested_records_name_their_source():
    resolver = spf("v=spf1 include:bad.example.net -all", **{"bad.example.net": txt("v=spf1 ip4:300.1.1.1 ~all")})
    result = check_spf("example.com", resolver)
    assert has_message(result, Status.FAIL, "[include:bad.example.net] invalid term 'ip4:300.1.1.1'")


def test_tree_is_reported_in_details():
    resolver = spf("v=spf1 include:p.example.net -all", **{"p.example.net": txt("v=spf1 a ~all")})
    tree = check_spf("example.com", resolver).details["tree"]
    assert tree["domain"] == "example.com" and tree["lookups"] == 1
    assert tree["includes"][0]["domain"] == "p.example.net" and tree["includes"][0]["lookups"] == 1
