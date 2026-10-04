# email-auth-checker

Give it a domain, it reads the four DNS records that decide whether that domain's mail
is trusted or sent to spam (SPF, DKIM, DMARC, MX) and says, for each problem, what
breaks and why. One dependency (`dnspython`), no API key, nothing sent anywhere except
DNS queries.

The records themselves are short. The hard part is that most of the ways they fail are
silent: the syntax is valid, a quick look says "SPF: present, DMARC: present", and mail
still fails for some senders. This tool is mostly a list of those cases turned into
checks.

## What a run looks like

A real run against `gmail.com` on 4 October 2026:

```
$ email-auth-check gmail.com
gmail.com  WARN
  SPF    PASS   1/10 lookups, ends in ~all via redirect=_spf.google.com
  DMARC  WARN   p=none, sp=quarantine, reports to mailauth-reports@google.com
         record: v=DMARC1; p=none; sp=quarantine; rua=mailto:mailauth-reports@google.com
         WARN   p=none: monitoring only
                why: failing mail is still delivered; DMARC protects nothing until p=quarantine or p=reject
  DKIM   WARN   no usable key: 20230601 (revoked), 20210112 (revoked), 20161025 (revoked)
         WARN   only revoked keys found (20230601, 20210112, 20161025)
                why: the active selector is not in the list checked; pass --selector with the s= value from a DKIM-Signature header
  MX     PASS   5 hosts, primary gmail-smtp-in.l.google.com
  -> 0 fail, 2 warn
```

Both warnings are accurate, and both are typical. `gmail.com` publishes `p=none` for
itself (subdomains get `sp=quarantine`). And Google has rotated its DKIM keys: the three
date-style selectors it used in past years are still published but revoked, and the
current one is not something DNS will tell you (see below).

What failures look like. **Illustrative only:** this comes from a fake DNS zone like the
ones in the test suite, not from a real domain.

```
shop.example  FAIL
  SPF    FAIL   13 lookups (limit 10), ends in ~all
         record: v=spf1 include:spf.mailer-a.example include:spf.mailer-b.example include:spf.crm.example include:old-esp.example mx a ~all
         FAIL   include:old-esp.example does not exist
                why: an include or redirect to a missing domain is a permanent error: SPF fails for every message (common after leaving a provider)
         FAIL   13 DNS lookups; RFC 7208 allows 10
                why: receivers return permerror as soon as an 11th lookup is needed: every server not matched before that point fails SPF, usually the provider listed last
         lookups per record:
           shop.example  6
             include:spf.mailer-a.example  3
               include:a1.mailer-a.example  0
               include:a2.mailer-a.example  0
               include:a3.mailer-a.example  0
             include:spf.mailer-b.example  2
               include:b1.mailer-b.example  0
               include:b2.mailer-b.example  0
             include:spf.crm.example  2
             include:old-esp.example  no record
  DMARC  WARN   p=quarantine, pct=20, reports to reports@dmarc-saas.example
         ...
```

## What it checks

| Record | What is checked | Why it matters |
| --- | --- | --- |
| **SPF** (`TXT` on the domain) | exactly one `v=spf1` record; every term parsed (unknown mechanisms, bad IPs, `include:` pointing at an IP); DNS lookups counted through nested includes and redirects against the limit of 10, with loop detection; how the record ends (`+all`, `?all`, `~all`, `-all`, nothing); `ptr`; includes that lead to no SPF record | Lists the servers allowed to send as you. Gmail and Yahoo require SPF or DKIM from every sender |
| **DMARC** (`_dmarc.<domain>`) | one valid record; `p`, `sp`, `pct`, `adkim`/`aspf`; `rua` syntax and, for reports sent to another domain, whether that domain accepted them; unknown tags; subdomains fall back to the parent record | Tells receivers what to do when SPF and DKIM fail. Without it, spoofing your domain costs nothing. Required for bulk senders |
| **DKIM** (`<selector>._domainkey.<domain>`) | 33 common selectors plus any you pass; key type; exact RSA key size; revoked keys; testing mode (`t=y`); sha1-only keys | Proves a message was not altered and came from someone holding your key |
| **MX** | hosts and preferences; null MX (RFC 7505); no MX (implicit fallback to the A record); hosts with no address; MX pointing at an IP | Bounces and replies need somewhere to go, and many receivers refuse mail from domains that can't receive any |

Each finding is `PASS`, `INFO`, `WARN`, `FAIL`, or `ERROR`. `ERROR` means a lookup failed
(timeout, SERVFAIL) and the answer is unknown. It is never shown as "fine".

## Things that look fine but aren't

**SPF over 10 lookups fails silently, and not for everyone.** The limit counts every
`include`, `a`, `mx`, `ptr`, `exists` and `redirect` in the whole tree, nested includes
included, and a single provider's include can cost several lookups on its own. The
record stays syntactically valid, so anything that only parses the top-level record
says it's fine.
Receivers return `permerror` when evaluation needs an 11th lookup, which means servers
matched early still pass: the breakage only hits whichever provider is listed late,
often the one you just added. The count can also change without you touching anything,
because the nested records belong to your providers. That is why 9 or 10 is already a
warning here.

**`p=none` protects nothing.** It asks receivers to send reports and change nothing.
Since Gmail and Yahoo started requiring DMARC from bulk senders, `p=none` is accepted
there, so many domains publish it and consider the job done. It is a measuring phase.
The protection starts at `p=quarantine`.

**DKIM selectors can't be enumerated.** There is no DNS query that lists them. This
tool probes 33 common names (Google Workspace's `google`, Microsoft 365's
`selector1`/`selector2`, SendGrid's `s1`/`s2`, and so on), so "no key found" is a
warning, never a failure. The authoritative answer is the `s=` tag in the
`DKIM-Signature` header of a message you actually sent; pass it with `--selector`. A
selector you name explicitly and that is missing is a failure.

**An include that points nowhere breaks the whole record.** Leave an email provider,
or have one retire an SPF hostname, and `include:` now leads to a domain with no SPF
record. That is not skipped: it is a permanent error (RFC 7208 section 5.2) and SPF
fails for every message.

**One wrong character changes the meaning.** `include=_spf.example.com` (with `=`) is
read as an unknown modifier and ignored, so that provider is simply not authorized. A
bare `all` with no qualifier means `+all`: every server on the internet may send as
you. Mechanisms placed after `all` are never evaluated, and a `redirect=` next to an
`all` is ignored.

**`pct=20` is not "a bit stricter", it is mostly weaker.** The other 80% of failing
mail gets the next weaker policy (`reject` becomes `quarantine`, `quarantine` becomes
`none`). It is a rollout step.

**Reports sent to another domain are dropped unless it opts in.**
`rua=mailto:dmarc@vendor.example` only works if `vendor.example` publishes
`yourdomain._report._dmarc.vendor.example`. DMARC vendors publish it; for a personal
mailbox you would need the mailbox provider to publish it for you, so receivers that
follow RFC 7489 section 7.1 send nothing there. The tool queries that record.

## Design decisions

- **The network is injected.** Every check takes a resolver function
  `(name, rdtype) -> list[str]`; only `resolver.py` imports dnspython. The tests pass a
  dictionary instead, so the suite runs offline and can build any broken zone it needs.
- **SPF is counted worst-case**, as if no mechanism matched, because that is the path
  a receiver takes for a server you didn't list. Terms after `all` are not counted, a
  redirect ignored because of `all` is not counted, and macros (`%{i}`) count as one
  lookup without being followed.
- **RSA key sizes are exact.** The modulus is read from the DER structure in `p=`, both
  the usual SubjectPublicKeyInfo and the bare PKCS#1 form some generators publish, with
  no crypto dependency. The tests compare the result with the `cryptography` package for
  1024 to 4096-bit keys.
- **A timeout is not a misconfiguration.** It is reported as `ERROR`, and the exit code
  is 3 rather than 0, so a CI job doesn't go green because DNS was down.
- **No Public Suffix List.** For a subdomain without its own DMARC record, parent domains
  are tried in turn (close to the DMARCbis tree walk). "Same organization" for report
  addresses compares the last two labels. Both are approximations and wrong for
  suffixes like `co.uk`; the second only means a report-authorization check may be
  skipped.
- **One bug can't hide the other checks.** If a check raises unexpectedly, it is
  reported as an internal `ERROR` and the other three still run. No tracebacks.

## What it does not do

It reads DNS; it does not send or receive mail. So it can't tell whether your messages
are actually signed, which selector they use, or whether the domains align with the
`From:` header: that is per message, and needs a real header. It doesn't count SPF
"void lookups" beyond includes and redirects, and it doesn't look at blocklists, reverse
DNS of your sending IPs, BIMI, MTA-STS or TLS-RPT.

## Install and use

```bash
pip install .                      # installs the email-auth-check command
email-auth-check example.com
email-auth-check example.com example.org --json
email-auth-check example.com -s s2024 -s mandrill      # selectors from DKIM-Signature s=
email-auth-check example.com -v                        # also passing findings + SPF tree
email-auth-check example.com --nameserver 1.1.1.1 --timeout 3
```

Without installing: `pip install dnspython`, then from the repository root
`python -m email_auth_checker example.com`.
URLs and addresses are accepted (`https://www.example.com/contact`, `postmaster@example.com`).

| Exit code | Meaning |
| --- | --- |
| 0 | no FAIL, every lookup answered |
| 1 | at least one FAIL |
| 2 | usage error (bad domain, bad option) |
| 3 | no FAIL, but some lookups failed: result incomplete |

## JSON

`--json` prints every check with its findings and the parsed data: SPF lookup tree,
DMARC tags, DKIM keys, MX hosts. Trimmed, from the same `gmail.com` run:

```json
{
  "tool": "email-auth-checker",
  "version": "0.1.0",
  "exit_code": 0,
  "domains": [
    {
      "domain": "gmail.com",
      "status": "WARN",
      "checks": {
        "spf": {
          "status": "PASS",
          "summary": "1/10 lookups, ends in ~all via redirect=_spf.google.com",
          "findings": [
            { "status": "PASS", "message": "1/10 DNS lookups" },
            { "status": "PASS", "message": "ends in '~all' via redirect=_spf.google.com (softfail): unlisted servers are flagged" }
          ],
          "details": { "lookups": 1, "lookups_is_lower_bound": false, "limit": 10, "all": "~all", "tree": { "...": "..." } }
        },
        "dmarc": {
          "status": "WARN",
          "summary": "p=none, sp=quarantine, reports to mailauth-reports@google.com",
          "findings": [
            {
              "status": "WARN",
              "message": "p=none: monitoring only",
              "why": "failing mail is still delivered; DMARC protects nothing until p=quarantine or p=reject"
            },
            { "status": "INFO", "message": "external report destination google.com has authorized reports for gmail.com" }
          ],
          "details": { "policy": "none", "subdomain_policy": "quarantine", "adkim": "r", "aspf": "r", "pct": null }
        },
        "dkim": { "status": "WARN", "...": "..." },
        "mx": { "status": "PASS", "...": "..." }
      }
    }
  ]
}
```

## Tests

```bash
pip install -e ".[test]"     # pytest, cryptography
pytest
```

190 tests, no network. `tests/fakes.py` holds the fake resolver. Covered: SPF lookup
counting through nested includes, diamonds (the same include reached twice counts
twice), loops, deep chains, redirects, terms after `all`, `+all` hidden inside an
include, `?all`, multiple records, typos; DMARC parsing edge cases (commas instead of
semicolons, duplicate tags, missing `p`, `pct` bounds, inheritance, report
authorization); DKIM key sizes from real generated keys in both encodings, revoked and
malformed keys; MX null, missing and dangling hosts; the dnspython adapter's error
mapping; exit codes and JSON.

## En français

`email-auth-checker` vérifie les enregistrements DNS qui décident si les e-mails d'un
domaine arrivent en boîte de réception ou en spam : SPF (avec le comptage réel des 10
requêtes DNS, includes imbriqués compris), DKIM (taille exacte des clés RSA), DMARC et
MX. Chaque problème est expliqué en une ligne. Sortie texte ou JSON, codes de sortie
exploitables en CI, tests sans réseau.

MIT licensed.
