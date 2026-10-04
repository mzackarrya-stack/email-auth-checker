"""Command line entry point: ``email-auth-check example.com [more.com ...]``."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
from typing import Optional, Sequence, TextIO
from urllib.parse import urlsplit

from . import __version__
from .dkim import is_valid_selector
from .report import EXIT_INCOMPLETE, EXIT_USAGE, check_domain, exit_code, render_json, render_text
from .resolver import Resolver, cached, system_resolver

_LABEL = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?$")

EPILOG = """\
exit codes:
  0  no FAIL (every lookup answered)
  1  at least one FAIL
  2  usage error
  3  no FAIL, but some lookups failed (timeout, SERVFAIL): result incomplete
"""


def normalize_domain(raw: str) -> str:
    """Accept 'Example.com.', 'https://example.com/path' or 'user@example.com'; return 'example.com'."""
    text = raw.strip()
    if "://" in text:
        text = urlsplit(text).hostname or ""
    elif "@" in text:
        text = text.rsplit("@", 1)[1]
    text = text.split("/", 1)[0].rstrip(".").lower()
    try:
        text = text.encode("idna").decode("ascii")  # internationalized names -> punycode
    except UnicodeError:
        raise ValueError(f"'{raw}' is not a valid domain name") from None
    labels = text.split(".")
    if (len(labels) < 2 or len(text) > 253
            or not all(len(label) <= 63 and _LABEL.match(label) for label in labels)):
        raise ValueError(f"'{raw}' is not a valid domain name")
    if not re.search(r"[a-z]", labels[-1]):
        raise ValueError(f"'{raw}' looks like an IP address; give a domain name")
    return text


def _timeout(value: str) -> float:
    try:
        seconds = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{value}' is not a number") from None
    if not 0 < seconds <= 60:
        raise argparse.ArgumentTypeError("must be between 0 and 60 seconds")
    return seconds


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="email-auth-check",
        description="Check the DNS records that decide whether a domain's mail reaches the inbox: "
                    "SPF, DKIM, DMARC and MX.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("domains", nargs="+", metavar="DOMAIN", help="domain(s) to check")
    parser.add_argument("-s", "--selector", action="append", default=[], metavar="NAME",
                        help="DKIM selector to check besides the common ones; repeatable or comma-separated. "
                             "Take it from the s= tag of a DKIM-Signature header")
    parser.add_argument("--json", action="store_true", help="print JSON instead of the text report")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="also show passing findings and the SPF include tree")
    parser.add_argument("--timeout", type=_timeout, default=5.0, metavar="SECONDS",
                        help="per-query DNS timeout (default: 5)")
    parser.add_argument("--nameserver", action="append", default=[], metavar="IP",
                        help="query this resolver instead of the system one; repeatable")
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _enable_ansi(stream: TextIO) -> bool:
    if os.name != "nt":
        return True
    try:  # Windows: colors need virtual terminal processing on the console handle
        import ctypes
        import msvcrt

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = msvcrt.get_osfhandle(stream.fileno())
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(mode.value & 0x0004 or kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:  # noqa: BLE001 - no colors is always a safe fallback
        return False


def _use_color(stream: TextIO, disabled: bool) -> bool:
    if disabled or "NO_COLOR" in os.environ or os.environ.get("TERM") == "dumb":
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty()) and _enable_ansi(stream)


def main(argv: Optional[Sequence[str]] = None, resolver: Optional[Resolver] = None,
         stdout: Optional[TextIO] = None, stderr: Optional[TextIO] = None) -> int:
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    for stream in (stdout, stderr):
        try:  # TXT data can contain anything; never die on a console that can't print it
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass

    def usage_error(message: str) -> int:
        stderr.write(f"email-auth-check: error: {message}\n")
        return EXIT_USAGE

    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:  # --help / --version exit 0, bad arguments exit 2
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE

    domains: list[str] = []
    for raw in args.domains:
        try:
            domain = normalize_domain(raw)
        except ValueError as exc:
            return usage_error(str(exc))
        if domain not in domains:
            domains.append(domain)

    selectors = [s.strip() for value in args.selector for s in value.split(",") if s.strip()]
    for selector in selectors:
        if not is_valid_selector(selector):
            return usage_error(f"'{selector}' is not a valid DKIM selector")
    for server in args.nameserver:
        try:
            ipaddress.ip_address(server)
        except ValueError:
            return usage_error(f"--nameserver expects an IP address, got '{server}'")

    try:
        if resolver is None:
            try:
                resolver = system_resolver(args.timeout, args.nameserver or None)
            except RuntimeError as exc:
                stderr.write(f"email-auth-check: {exc}\n")
                return EXIT_INCOMPLETE
        resolver = cached(resolver)
        reports = [check_domain(domain, resolver, selectors) for domain in domains]
    except KeyboardInterrupt:
        stderr.write("interrupted\n")
        return 130

    if args.json:
        stdout.write(render_json(reports))
    else:
        stdout.write(render_text(reports, color=_use_color(stdout, args.no_color), verbose=args.verbose))
    stdout.flush()
    return exit_code(reports)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
