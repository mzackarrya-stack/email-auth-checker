"""DKIM: public keys published at ``<selector>._domainkey.<domain>`` (RFC 6376, RFC 8301, RFC 8463).

DNS cannot list the selectors a domain uses; the only authoritative source is the
``s=`` tag of a DKIM-Signature header on a real message. This module therefore
probes a list of common selectors plus any the user supplies, and treats "nothing
found" as a warning, never as a failure.

RSA key sizes are read exactly from the DER structure in ``p=`` (the modulus bit
length), without a crypto library.
"""

from __future__ import annotations

import base64
import binascii
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Iterable, Optional, Sequence

from .model import CheckResult, Finding, Status
from .resolver import LookupFailed, NXDomain, Resolver, normalize_name
from .taglist import parse_tag_list

COMMON_SELECTORS: tuple[str, ...] = (
    "google",  # Google Workspace
    "selector1", "selector2",  # Microsoft 365
    "default", "dkim", "mail", "email", "smtp", "key1", "key2",
    "k1", "k2", "k3",  # Mailchimp
    "s1", "s2",  # SendGrid
    "mandrill",
    "zoho", "zmail",  # Zoho Mail
    "mxvault",
    "fm1", "fm2", "fm3",  # Fastmail
    "protonmail", "protonmail2", "protonmail3",  # Proton Mail
    "sig1",  # iCloud custom domains
    "mailjet", "cm", "everlytickey1", "everlytickey2",
    "20230601", "20210112", "20161025",  # date-style selectors seen in Gmail signatures
)

MIN_RSA_BITS = 1024  # RFC 8301: verifiers must not accept smaller keys
RECOMMENDED_RSA_BITS = 2048  # RFC 8301: signers should use at least this
_RSA_OID = bytes.fromhex("2a864886f70d010101")  # 1.2.840.113549.1.1.1 rsaEncryption
_SELECTOR = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$")


def is_valid_selector(selector: str) -> bool:
    return bool(_SELECTOR.match(selector)) and len(selector) <= 200


# --- DER, just enough to read an RSA modulus ------------------------------------

def _read_tlv(data: bytes, pos: int) -> tuple[int, int, int]:
    """Return (tag, value_start, value_end) of the DER element at ``pos``."""
    if pos + 2 > len(data):
        raise ValueError("truncated DER")
    tag, length = data[pos], data[pos + 1]
    pos += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise ValueError("bad DER length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise ValueError("truncated DER")
    return tag, pos, end


def rsa_modulus_bits(der: bytes) -> int:
    """Bit length of the RSA modulus in a SubjectPublicKeyInfo or a bare PKCS#1 RSAPublicKey.

    Most DKIM keys are SubjectPublicKeyInfo (``MIIBIjANBgkqh...``); some generators
    publish the bare RSAPublicKey (``MIIBCgKCAQEA...``). Both are accepted.
    """
    tag, start, end = _read_tlv(der, 0)
    if tag != 0x30:
        raise ValueError("not a DER SEQUENCE")
    first_tag, first_start, first_end = _read_tlv(der, start)
    if first_tag == 0x02:  # RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
        return int.from_bytes(der[first_start:first_end], "big").bit_length()
    if first_tag != 0x30:
        raise ValueError("unexpected DER structure")
    # SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING }
    oid_tag, oid_start, oid_end = _read_tlv(der, first_start)
    if oid_tag != 0x06 or der[oid_start:oid_end] != _RSA_OID:
        raise ValueError("not an RSA key")
    bits_tag, bits_start, bits_end = _read_tlv(der, first_end)
    if bits_tag != 0x03 or bits_end - bits_start < 2:
        raise ValueError("missing key BIT STRING")
    return rsa_modulus_bits(der[bits_start + 1:bits_end])  # skip the "unused bits" byte


def decode_key(p: str) -> bytes:
    """Base64-decode a ``p=`` value; whitespace inside it is legal (RFC 6376 3.6.1)."""
    compact = re.sub(r"\s+", "", p)
    try:
        return base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("p= is not valid base64") from exc


# --- one key record ------------------------------------------------------------

@dataclass
class DkimKey:
    selector: str
    record: str
    key_type: str = "rsa"
    bits: Optional[int] = None
    revoked: bool = False
    testing: bool = False
    findings: list[Finding] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return not self.revoked and not any(f.status is Status.FAIL for f in self.findings)

    def describe(self) -> str:
        if self.revoked:
            return f"{self.selector} (revoked)"
        if self.bits:
            return f"{self.selector} ({self.key_type} {self.bits})"
        return f"{self.selector} ({self.key_type})"

    def to_dict(self) -> dict:
        return {
            "selector": self.selector, "record": self.record, "key_type": self.key_type,
            "bits": self.bits, "revoked": self.revoked, "testing": self.testing,
        }


def looks_like_dkim(txt: str) -> bool:
    """Tell a key record apart from unrelated TXT data (e.g. a wildcard SPF record)."""
    stripped = txt.strip()
    if re.match(r"^v\s*=\s*DKIM1\b", stripped, re.IGNORECASE):
        return True
    return "p" in parse_tag_list(stripped).tags and not stripped.lower().startswith("v=spf1")


def analyse_key(selector: str, record: str) -> DkimKey:
    key = DkimKey(selector, record)
    parsed = parse_tag_list(record)
    tags = parsed.tags

    def add(status: Status, message: str, why: str = "") -> None:
        key.findings.append(Finding(status, f"{selector}: {message}", why))

    for error in parsed.errors:
        add(Status.FAIL, f"invalid syntax: {error}", "verifiers may reject the key record")
    if "v" in tags and (tags["v"] != "DKIM1" or parsed.order[0] != "v"):
        add(Status.FAIL, f"v={tags['v']} must be the first tag and read exactly DKIM1",
            "RFC 6376 3.6.1: verifiers ignore the record otherwise")

    key.key_type = tags.get("k", "rsa").lower() or "rsa"
    flags = [f.strip().lower() for f in tags.get("t", "").split(":") if f.strip()]
    if "y" in flags:
        key.testing = True
        add(Status.WARN, "t=y (testing mode)",
            "receivers may treat signed mail as unsigned; remove t=y once signing works")
    hashes = [h.strip().lower() for h in tags.get("h", "").split(":") if h.strip()]
    if hashes and "sha256" not in hashes:
        add(Status.FAIL, f"h={tags['h']} allows only {'/'.join(hashes)}",
            "RFC 8301: rsa-sha1 signatures must not be accepted, so this key can't produce a valid signature")
    services = [s.strip().lower() for s in tags.get("s", "").split(":") if s.strip()]
    if services and not {"*", "email"} & set(services):
        add(Status.FAIL, f"s={tags['s']} does not cover email", "verifiers won't use this key for mail")

    if "p" not in tags:
        add(Status.FAIL, "no p= tag", "the record has no public key")
        return key
    if tags["p"].strip() == "":
        key.revoked = True
        key.findings.append(Finding(Status.INFO, f"{selector}: revoked key (empty p=), normal after a rotation"))
        return key

    try:
        raw = decode_key(tags["p"])
    except ValueError as exc:
        add(Status.FAIL, str(exc),
            "verifiers can't load the key; often a record split by hand with literal quotes inside it")
        return key

    if key.key_type == "rsa":
        try:
            key.bits = rsa_modulus_bits(raw)
        except ValueError as exc:
            add(Status.FAIL, f"p= is not a valid RSA public key ({exc})", "every signature with it fails")
            return key
        if key.bits < MIN_RSA_BITS:
            add(Status.FAIL, f"rsa {key.bits}-bit key",
                f"verifiers reject keys under {MIN_RSA_BITS} bits (RFC 8301), and a key this short can be "
                "factored cheaply, letting someone else sign as you")
        elif key.bits < RECOMMENDED_RSA_BITS:
            add(Status.WARN, f"rsa {key.bits}-bit key",
                f"accepted today, but RFC 8301 recommends {RECOMMENDED_RSA_BITS} bits; rotate when convenient")
        else:
            add(Status.PASS, f"rsa {key.bits}-bit key")
    elif key.key_type == "ed25519":
        if len(raw) != 32:
            add(Status.FAIL, f"ed25519 key is {len(raw)} bytes, expected 32", "every signature with it fails")
        else:
            key.bits = 256
            add(Status.PASS, "ed25519 key (pair it with an RSA key: not every receiver verifies ed25519)")
    else:
        add(Status.FAIL, f"unknown key type k={key.key_type}", "verifiers ignore keys of an unknown type")
    return key


# --- the check -----------------------------------------------------------------

def _dedupe(selectors: Iterable[str]) -> list[str]:
    seen: dict[str, None] = {}
    for selector in selectors:
        seen.setdefault(selector.strip().lower(), None)
    return [s for s in seen if s]


def check_dkim(domain: str, resolver: Resolver, selectors: Sequence[str] = (),
               common: Sequence[str] = COMMON_SELECTORS, max_workers: int = 8) -> CheckResult:
    result = CheckResult("DKIM")
    domain = normalize_name(domain)
    requested = _dedupe(selectors)
    to_check = _dedupe([*requested, *common])

    def lookup(selector: str):
        name = f"{selector}._domainkey.{domain}"
        try:
            return selector, [t for t in resolver(name, "TXT") if looks_like_dkim(t)], None
        except NXDomain:
            return selector, [], None
        except LookupFailed as exc:
            return selector, [], exc.reason

    with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(to_check)))) as pool:
        answers = list(pool.map(lookup, to_check))  # map() keeps input order

    keys: list[DkimKey] = []
    failed: list[str] = []
    for selector, records, error in answers:
        if error:
            failed.append(selector)
            if selector in requested:
                result.add(Status.ERROR, f"could not look up selector '{selector}': {error}",
                           "the answer is unknown, not necessarily wrong")
            continue
        if not records:
            if selector in requested:
                result.add(Status.FAIL, f"no key at {selector}._domainkey.{domain}",
                           "mail signed with this selector fails DKIM; check the s= tag of a DKIM-Signature header")
            continue
        if len(records) > 1:
            result.add(Status.WARN, f"{selector}: {len(records)} key records at the same selector",
                       "RFC 6376 leaves the choice to the verifier, so signatures may fail at random")
        key = analyse_key(selector, records[0])
        keys.append(key)
        result.findings.extend(key.findings)

    usable = [k for k in keys if k.usable]
    revoked = [k for k in keys if k.revoked]
    checked = len(to_check)
    if not keys:
        if failed and len(failed) == checked:
            result.add(Status.ERROR, f"all {checked} selector lookups failed", "DKIM could not be checked")
        elif failed:
            result.add(Status.ERROR, f"no key found, and {len(failed)} of {checked} selector lookups failed",
                       "a key may exist behind a failed lookup")
        elif not requested:
            result.add(Status.WARN, f"no DKIM key found among {checked} common selectors",
                       "this does not prove DKIM is off: selectors can't be listed via DNS; pass --selector "
                       "with the s= value from a DKIM-Signature header")
        result.summary = f"no key found ({checked} selectors checked)"
    elif not usable:
        if revoked and len(revoked) == len(keys):
            result.add(Status.WARN, f"only revoked keys found ({', '.join(k.selector for k in revoked)})",
                       "the active selector is not in the list checked; pass --selector with the s= value "
                       "from a DKIM-Signature header")
        result.summary = "no usable key: " + ", ".join(k.describe() for k in keys)
    else:
        result.summary = f"{len(usable)} active key{'s' if len(usable) > 1 else ''}: " + ", ".join(
            k.describe() for k in usable)
    if failed and keys:
        result.add(Status.INFO, f"{len(failed)} selector lookups failed and were skipped")

    result.details.update({
        "selectors_checked": to_check,
        "selectors_failed": failed,
        "keys": [k.to_dict() for k in keys],
    })
    return result
