"""Test helpers: a dictionary-backed resolver (no test touches the network) and sample keys."""

from __future__ import annotations

from typing import Union

from email_auth_checker.resolver import LookupFailed, NXDomain, normalize_name

Answer = Union[list, Exception]


class FakeResolver:
    """``zone`` maps a name to ``{rdtype: [answers]}``.

    * a name absent from the zone raises NXDomain, like real DNS
    * a present name without that rdtype returns [] (NOERROR, no data)
    * an exception instance as the answer is raised (e.g. a timeout)
    """

    def __init__(self, zone: dict[str, dict[str, Answer]]) -> None:
        self.zone = {normalize_name(name): dict(types) for name, types in zone.items()}
        self.queries: list[tuple[str, str]] = []

    def __call__(self, name: str, rdtype: str) -> list:
        name = normalize_name(name)
        self.queries.append((name, rdtype))
        if name not in self.zone:
            raise NXDomain(name, rdtype, "does not exist")
        answer = self.zone[name].get(rdtype, [])
        if isinstance(answer, Exception):
            raise answer
        return list(answer)

    def count(self, name: str, rdtype: str) -> int:
        return self.queries.count((normalize_name(name), rdtype))


def timeout(name: str = "x", rdtype: str = "TXT") -> LookupFailed:
    return LookupFailed(name, rdtype, "timed out after 5s")


def messages(result, status=None) -> list[str]:
    """Finding messages of a CheckResult, optionally filtered by status."""
    return [f.message for f in result.findings if status is None or f.status is status]


def has_message(result, status, fragment: str) -> bool:
    return any(fragment in m for m in messages(result, status))


# Public keys as they appear in DKIM p= values, generated with the `cryptography` package.
# SubjectPublicKeyInfo, the usual DKIM form.
RSA_1024 = (
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDf9n56/tay92LDVRGXlPbjDTRQWLOKQJSxb/p/Ukc0EnvRE5SuL/Gze"
    "XNfVXrbERtZyW158VlZKuOxQrq0WZspYSS6SddtxQoRhSR03H32ccOgjZe0QFNoSH/K4Rx9AMzVC1KbHGpBrvk6xeeMNhs"
    "BQrA94ueqqhLmfICWuSJLTQIDAQAB"
)
RSA_2048 = (
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7VZDR8s+glPYQrZvh8q6i2JK1ITTz+0hWk3m0s/HYvdBqFkazd"
    "ZvX5Moulc9x0iidk1ofcEvFeb6qsCV6xkD/RBfTWVw3p0/1Lyp9saBqjQbaMTrDaR3l5OSClgn4uLh/rLCZJnoyRGX0ABY0"
    "oAJ2DrQzWo3EnEpEaFBFGdEuBwm3XUmJ9Ic1a7hzgaST238JmngvS9t0qXIUZI8Pt0fOf70MwP3I0MH+Eb460nNwIGFoxle"
    "rikBrRTZlQX75OoiDEHQHYAEz48N/XLlBC7VTeLtwdhBRluBY0Pp+xrd6wz0xAbEcFppUILy2HLnpof84c2XJ4pAnAQnXjzq"
    "KIYPXQIDAQAB"
)
# The same 2048-bit key as a bare PKCS#1 RSAPublicKey, which some generators publish.
RSA_2048_PKCS1 = (
    "MIIBCgKCAQEA7VZDR8s+glPYQrZvh8q6i2JK1ITTz+0hWk3m0s/HYvdBqFkazdZvX5Moulc9x0iidk1ofcEvFeb6qsCV6xk"
    "D/RBfTWVw3p0/1Lyp9saBqjQbaMTrDaR3l5OSClgn4uLh/rLCZJnoyRGX0ABY0oAJ2DrQzWo3EnEpEaFBFGdEuBwm3XUmJ9I"
    "c1a7hzgaST238JmngvS9t0qXIUZI8Pt0fOf70MwP3I0MH+Eb460nNwIGFoxlerikBrRTZlQX75OoiDEHQHYAEz48N/XLlBC7"
    "VTeLtwdhBRluBY0Pp+xrd6wz0xAbEcFppUILy2HLnpof84c2XJ4pAnAQnXjzqKIYPXQIDAQAB"
)
# A 512-bit modulus. `cryptography` refuses to generate keys this small, so it was built from a
# random 512-bit odd number; only the size matters here.
RSA_512 = (
    "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAK81x6+gayp9ABUOOA06iDUW8BIgGc9VxtL+jdY++MhNb0TOVN2s1fJjb0DMUv0S"
    "flg9DKsrSeJXOVd4Jn3flTUCAwEAAQ=="
)
ED25519 = "RGVWgS3o2O3FWN0NwtUk48tADWqNk1Z+3MhAsvt6n5g="
