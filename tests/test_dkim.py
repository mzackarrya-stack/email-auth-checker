import base64

import pytest

from email_auth_checker.dkim import (
    COMMON_SELECTORS, analyse_key, check_dkim, decode_key, looks_like_dkim, rsa_modulus_bits,
)
from email_auth_checker.model import Status
from fakes import (
    ED25519, RSA_512, RSA_1024, RSA_2048, RSA_2048_PKCS1, FakeResolver, has_message, messages, timeout,
)


def key_zone(selector, *records, domain="example.com"):
    return FakeResolver({f"{selector}._domainkey.{domain}": {"TXT": list(records)}})


# --- key size from p= ----------------------------------------------------------

@pytest.mark.parametrize("p, bits", [(RSA_512, 512), (RSA_1024, 1024), (RSA_2048, 2048), (RSA_2048_PKCS1, 2048)])
def test_rsa_modulus_bits_from_embedded_keys(p, bits):
    assert rsa_modulus_bits(decode_key(p)) == bits


@pytest.mark.parametrize("bits", [1024, 1536, 2048, 3072, 4096])
def test_rsa_modulus_bits_matches_cryptography(bits):
    crypto = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    public = crypto.generate_private_key(public_exponent=65537, key_size=bits).public_key()
    for fmt in (serialization.PublicFormat.SubjectPublicKeyInfo, serialization.PublicFormat.PKCS1):
        der = public.public_bytes(serialization.Encoding.DER, fmt)
        assert rsa_modulus_bits(der) == public.key_size == bits
        key = analyse_key("s", f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}")
        assert key.bits == bits


def test_embedded_keys_agree_with_cryptography():
    serialization = pytest.importorskip("cryptography.hazmat.primitives.serialization")
    for p, bits in [(RSA_1024, 1024), (RSA_2048, 2048)]:
        assert serialization.load_der_public_key(decode_key(p)).key_size == bits


def test_whitespace_inside_p_is_allowed():
    spaced = " ".join(RSA_2048[i:i + 60] for i in range(0, len(RSA_2048), 60))
    assert analyse_key("s", f"v=DKIM1; k=rsa; p={spaced}").bits == 2048


def test_der_parser_rejects_garbage():
    for blob in (b"", b"\x30", b"\x30\x05\x02\x01", b"\x04\x00", b"\x30\x03\x01\x01\x00"):
        with pytest.raises(ValueError):
            rsa_modulus_bits(blob)


def test_non_rsa_spki_is_rejected():
    # SubjectPublicKeyInfo for an Ed25519 key (OID 1.3.101.112)
    spki = bytes.fromhex("302a300506032b6570032100") + base64.b64decode(ED25519)
    with pytest.raises(ValueError, match="not an RSA key"):
        rsa_modulus_bits(spki)


# --- analysing one record ------------------------------------------------------

@pytest.mark.parametrize("p, status", [(RSA_512, Status.FAIL), (RSA_1024, Status.WARN), (RSA_2048, Status.PASS)])
def test_key_size_verdicts(p, status):
    key = analyse_key("sel", f"v=DKIM1; k=rsa; p={p}")
    assert [f.status for f in key.findings] == [status]


def test_k_defaults_to_rsa():
    assert analyse_key("sel", f"p={RSA_2048}").key_type == "rsa"


def test_revoked_key():
    key = analyse_key("old", "v=DKIM1; k=rsa; p=")
    assert key.revoked and not key.usable
    assert [f.status for f in key.findings] == [Status.INFO]


def test_invalid_base64():
    key = analyse_key("sel", 'v=DKIM1; k=rsa; p=MIIBIjANBg" "kqhkiG9w0B')
    assert has_message(key, Status.FAIL, "not valid base64")


def test_valid_base64_that_is_not_a_key():
    key = analyse_key("sel", "v=DKIM1; k=rsa; p=" + base64.b64encode(b"hello world, not a key").decode())
    assert has_message(key, Status.FAIL, "not a valid RSA public key")


def test_testing_mode_flag():
    key = analyse_key("sel", f"v=DKIM1; k=rsa; t=y; p={RSA_2048}")
    assert key.testing and has_message(key, Status.WARN, "t=y")


def test_sha1_only_key_is_unusable():
    key = analyse_key("sel", f"v=DKIM1; k=rsa; h=sha1; p={RSA_2048}")
    assert has_message(key, Status.FAIL, "h=sha1")


def test_service_type_not_email():
    assert has_message(analyse_key("sel", f"v=DKIM1; s=other; p={RSA_2048}"), Status.FAIL, "does not cover email")


def test_ed25519_key():
    key = analyse_key("ed", f"v=DKIM1; k=ed25519; p={ED25519}")
    assert key.key_type == "ed25519" and key.bits == 256 and key.usable


def test_ed25519_wrong_length():
    key = analyse_key("ed", f"v=DKIM1; k=ed25519; p={RSA_1024}")
    assert has_message(key, Status.FAIL, "expected 32")


def test_unknown_key_type():
    assert has_message(analyse_key("sel", f"v=DKIM1; k=dsa; p={RSA_2048}"), Status.FAIL, "unknown key type")


def test_version_must_come_first():
    assert has_message(analyse_key("sel", f"k=rsa; v=DKIM1; p={RSA_2048}"), Status.FAIL, "first tag")


def test_looks_like_dkim():
    assert looks_like_dkim("v=DKIM1; k=rsa; p=")
    assert looks_like_dkim(f"k=rsa; p={RSA_1024}")
    assert not looks_like_dkim("v=spf1 -all")
    assert not looks_like_dkim("google-site-verification=abc")


# --- the check over selectors ----------------------------------------------------

def test_finds_key_at_common_selector():
    result = check_dkim("example.com", key_zone("selector1", f"v=DKIM1; k=rsa; p={RSA_2048}"))
    assert result.status is Status.PASS
    assert result.summary == "1 active key: selector1 (rsa 2048)"
    assert result.details["keys"][0]["bits"] == 2048


def test_nothing_found_is_a_warning_not_a_failure():
    result = check_dkim("example.com", FakeResolver({}))
    assert result.status is Status.WARN
    assert has_message(result, Status.WARN, f"among {len(COMMON_SELECTORS)} common selectors")


def test_only_revoked_keys():
    result = check_dkim("example.com", key_zone("google", "v=DKIM1; k=rsa; p="))
    assert has_message(result, Status.WARN, "only revoked keys")


def test_short_key_fails_even_next_to_a_good_one():
    resolver = FakeResolver({
        "google._domainkey.example.com": {"TXT": [f"v=DKIM1; k=rsa; p={RSA_2048}"]},
        "default._domainkey.example.com": {"TXT": [f"v=DKIM1; k=rsa; p={RSA_512}"]},
    })
    result = check_dkim("example.com", resolver)
    assert result.status is Status.FAIL
    assert has_message(result, Status.FAIL, "default: rsa 512-bit")


def test_requested_selector_is_checked_first():
    resolver = key_zone("acme2024", f"v=DKIM1; p={RSA_2048}")
    result = check_dkim("example.com", resolver, selectors=["acme2024"])
    assert result.details["selectors_checked"][0] == "acme2024"
    assert result.status is Status.PASS


def test_requested_selector_missing_fails():
    result = check_dkim("example.com", FakeResolver({}), selectors=["acme2024"])
    assert has_message(result, Status.FAIL, "no key at acme2024._domainkey.example.com")


def test_unrelated_txt_at_selector_is_ignored():
    result = check_dkim("example.com", key_zone("mail", "v=spf1 -all"))  # e.g. a wildcard TXT
    assert result.details["keys"] == []


def test_two_records_at_one_selector():
    resolver = key_zone("s1", f"v=DKIM1; p={RSA_2048}", f"v=DKIM1; p={RSA_1024}")
    assert has_message(check_dkim("example.com", resolver), Status.WARN, "2 key records")


def test_all_lookups_timing_out_is_an_error():
    class Down:
        def __call__(self, name, rdtype):
            raise timeout(name, rdtype)

    result = check_dkim("example.com", Down())
    assert result.status is Status.ERROR
    assert has_message(result, Status.ERROR, "lookups failed")


def test_custom_common_list():
    resolver = key_zone("x", f"p={RSA_2048}")
    result = check_dkim("example.com", resolver, common=("x",))
    assert result.details["selectors_checked"] == ["x"]
    assert not [m for m in messages(result) if "common" in m]
