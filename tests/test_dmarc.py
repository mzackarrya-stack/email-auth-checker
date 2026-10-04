import pytest

from email_auth_checker.dmarc import check_dmarc
from email_auth_checker.model import Status
from email_auth_checker.taglist import parse_tag_list
from fakes import FakeResolver, has_message, messages, timeout


def dmarc(*records, domain="example.com", **extra):
    zone = {f"_dmarc.{domain}": {"TXT": list(records)}}
    zone.update(extra)
    return FakeResolver(zone)


GOOD = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"


# --- tag-value parsing -----------------------------------------------------------

def test_tag_list_tolerates_spaces_and_trailing_semicolon():
    parsed = parse_tag_list(" v = DMARC1 ;p=reject;  rua=mailto:a@example.com ; ")
    assert parsed.tags == {"v": "DMARC1", "p": "reject", "rua": "mailto:a@example.com"}
    assert parsed.order == ["v", "p", "rua"] and parsed.errors == []


def test_tag_list_reports_duplicates_and_garbage():
    parsed = parse_tag_list("v=DMARC1; p=none; p=reject; garbage; 1x=2")
    assert any("appears more than once" in e for e in parsed.errors)
    assert any("'garbage' is not a tag=value pair" in e for e in parsed.errors)
    assert any("'1x' is not a valid tag name" in e for e in parsed.errors)


# --- discovery -------------------------------------------------------------------

def test_missing_record_fails():
    result = check_dmarc("example.com", FakeResolver({}))
    assert result.status is Status.FAIL
    assert has_message(result, Status.FAIL, "no DMARC record at _dmarc.example.com")


def test_good_record_passes():
    result = check_dmarc("example.com", dmarc(GOOD))
    assert result.status is Status.PASS
    assert result.details["policy"] == "reject"
    assert result.details["rua"] == ["dmarc@example.com"]
    assert result.summary == "p=reject, reports to dmarc@example.com"


def test_multiple_records_disable_dmarc():
    result = check_dmarc("example.com", dmarc(GOOD, "v=DMARC1; p=none"))
    assert has_message(result, Status.FAIL, "2 DMARC records")


def test_non_dmarc_txt_at_dmarc_name():
    result = check_dmarc("example.com", dmarc("p=reject; v=DMARC1"))
    assert result.status is Status.FAIL
    assert has_message(result, Status.FAIL, "is not a DMARC record")


def test_subdomain_inherits_parent_record_and_its_sp():
    resolver = dmarc("v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.com")
    result = check_dmarc("news.example.com", resolver)
    assert result.details["found_at"] == "_dmarc.example.com"
    assert result.details["inherited"] is True
    assert result.details["policy"] == "quarantine"
    assert has_message(result, Status.INFO, "no record at _dmarc.news.example.com")


def test_subdomain_without_sp_gets_p():
    result = check_dmarc("a.b.example.com", dmarc("v=DMARC1; p=none; rua=mailto:d@example.com"))
    assert result.details["policy"] == "none"
    assert result.status is Status.WARN


def test_lookup_timeout_is_an_error():
    result = check_dmarc("example.com", FakeResolver({"_dmarc.example.com": {"TXT": timeout()}}))
    assert result.status is Status.ERROR


# --- policy ----------------------------------------------------------------------

@pytest.mark.parametrize("policy, status", [("none", Status.WARN), ("quarantine", Status.PASS),
                                            ("reject", Status.PASS), ("REJECT", Status.PASS)])
def test_policy_levels(policy, status):
    result = check_dmarc("example.com", dmarc(f"v=DMARC1; p={policy}; rua=mailto:d@example.com"))
    assert result.status is status


def test_p_none_is_monitoring_only():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=none; rua=mailto:d@example.com"))
    assert has_message(result, Status.WARN, "monitoring only")


def test_missing_p_fails():
    result = check_dmarc("example.com", dmarc("v=DMARC1; rua=mailto:d@example.com"))
    assert has_message(result, Status.FAIL, "no p= tag")


def test_invalid_p_fails():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=block; rua=mailto:d@example.com"))
    assert has_message(result, Status.FAIL, "p=block is not none, quarantine or reject")


def test_commas_instead_of_semicolons():
    result = check_dmarc("example.com", dmarc("v=DMARC1, p=reject, rua=mailto:d@example.com"))
    assert has_message(result, Status.FAIL, "separated by semicolons, not commas")


def test_lowercase_version_is_warned():
    result = check_dmarc("example.com", dmarc("v=dmarc1; p=reject; rua=mailto:d@example.com"))
    assert has_message(result, Status.WARN, "should be written 'v=DMARC1'")


def test_duplicate_tag_is_invalid_syntax():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=reject; p=none; rua=mailto:d@example.com"))
    assert has_message(result, Status.FAIL, "appears more than once")


# --- pct -------------------------------------------------------------------------

def test_pct_below_100_is_warned_with_its_effect():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=reject; pct=25; rua=mailto:d@example.com"))
    warning = next(f for f in result.findings if "pct=25" in f.message)
    assert warning.status is Status.WARN
    assert "reject -> quarantine" in warning.why
    assert result.details["pct"] == 25


@pytest.mark.parametrize("pct", [0, 99])
def test_pct_boundaries(pct):
    result = check_dmarc("example.com", dmarc(f"v=DMARC1; p=quarantine; pct={pct}; rua=mailto:d@example.com"))
    assert has_message(result, Status.WARN, f"pct={pct}: the policy applies to only {pct}%")


def test_pct_100_is_silent():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=reject; pct=100; rua=mailto:d@example.com"))
    assert result.status is Status.PASS


@pytest.mark.parametrize("pct", ["150", "abc", "-5", "50.5"])
def test_invalid_pct(pct):
    result = check_dmarc("example.com", dmarc(f"v=DMARC1; p=reject; pct={pct}; rua=mailto:d@example.com"))
    assert has_message(result, Status.WARN, f"pct={pct} is not a whole number")


def test_pct_is_irrelevant_with_p_none():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=none; pct=10; rua=mailto:d@example.com"))
    assert not has_message(result, Status.WARN, "pct=10")


# --- reports ---------------------------------------------------------------------

def test_missing_rua_is_warned():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=reject"))
    assert has_message(result, Status.WARN, "no rua=")
    assert result.summary.endswith("no reports")


def test_rua_without_mailto():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=reject; rua=dmarc@example.com"))
    assert has_message(result, Status.WARN, "missing 'mailto:'")


def test_rua_size_suffix_and_multiple_uris():
    record = "v=DMARC1; p=reject; rua=mailto:a@example.com!10m, mailto:b@example.com"
    result = check_dmarc("example.com", dmarc(record))
    assert result.details["rua"] == ["a@example.com", "b@example.com"]


def test_external_rua_without_authorization_is_warned():
    resolver = dmarc("v=DMARC1; p=reject; rua=mailto:reports@dmarc-vendor.example")
    result = check_dmarc("example.com", resolver)
    assert has_message(result, Status.WARN, "example.com._report._dmarc.dmarc-vendor.example")


def test_external_rua_with_authorization_is_accepted():
    resolver = dmarc("v=DMARC1; p=reject; rua=mailto:reports@dmarc-vendor.example",
                     **{"example.com._report._dmarc.dmarc-vendor.example": {"TXT": ["v=DMARC1"]}})
    result = check_dmarc("example.com", resolver)
    assert result.status is Status.PASS
    assert has_message(result, Status.INFO, "has authorized reports")


def test_same_organization_rua_needs_no_authorization():
    resolver = dmarc("v=DMARC1; p=reject; rua=mailto:dmarc@reports.example.com")
    result = check_dmarc("example.com", resolver)
    assert result.status is Status.PASS
    assert not any("_report._dmarc" in name for name, _ in resolver.queries)


# --- alignment, subdomains, unknown tags ---------------------------------------------

def test_alignment_modes_are_reported():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=reject; adkim=s; rua=mailto:d@example.com"))
    assert result.details["adkim"] == "s" and result.details["aspf"] == "r"
    assert has_message(result, Status.INFO, "DKIM strict, SPF relaxed (default)")


def test_invalid_alignment_mode():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=reject; aspf=x; rua=mailto:d@example.com"))
    assert has_message(result, Status.WARN, "aspf=x is not r or s")


def test_sp_none_leaves_subdomains_open():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com"))
    assert has_message(result, Status.WARN, "subdomains are not protected")


def test_invalid_sp_fails():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=reject; sp=maybe; rua=mailto:d@example.com"))
    assert has_message(result, Status.FAIL, "sp=maybe")


def test_unknown_tag_is_warned():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com; pc=100"))
    assert has_message(result, Status.WARN, "unknown tag 'pc'")


def test_dmarcbis_tags_are_known():
    result = check_dmarc("example.com", dmarc("v=DMARC1; p=reject; np=reject; t=n; rua=mailto:d@example.com"))
    assert not messages(result, Status.WARN)
