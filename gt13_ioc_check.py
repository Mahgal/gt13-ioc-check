#!/usr/bin/env python3
"""gt13_ioc_check.py -- offline scanner for GreyNoise GT13 indicators in HTTP access logs.

GT13 is the intrusion campaign GreyNoise disclosed on 2026-11-23 that
compromised 24 Check Point Security Management Servers at 22+ organizations
(confirmed activity 2026-10-17 to 2026-11-02, believed ongoing). This tool
checks your access logs against the indicators GreyNoise published, so you
can tell in seconds whether GT13 traces ever touched your servers.

Indicators are copied verbatim from the GreyNoise report:
  https://www.greynoise.io/blog/check-point-security-management-servers-intrusion-campaign
  - 4 domains: newpayapp.com (+ data-zt, api-zt, 2ev5 subdomains)
  - 2 User-Agents ending in "research"
  - 69 ExpressVPN exit IPs (of 99 total attacker IPs; the other ~30 were
    compromised victim Check Point devices and were NOT enumerated)
  - HASSH eeca2460550b9ded084ecf2f70a75356 (OpenSSH 10; common -- useful
    only combined with other GT13 traits, per GreyNoise)
  - implant artifact /usr/lib/.libproc.so (seen via /etc/ld.so.preload)

Usage:
  python3 gt13_ioc_check.py [file ...]     scan files (or stdin if none)
  python3 gt13_ioc_check.py --demo         deterministic before/after showcase
  python3 gt13_ioc_check.py --help         this help

Exit codes: 0 = no hits, 1 = hits found (by design), 2 = usage error.
Fully offline: no network calls, no dependencies beyond the standard library.
"""

import re
import sys

VERSION = "1.0.0"

# --- Indicators (raw values live ONLY here, where matching needs them) -------
DOMAINS = (
    "data-zt.newpayapp.com",  # GT13 "ZULT" malware download domain
    "api-zt.newpayapp.com",   # GT13 subdomain
    "2ev5.newpayapp.com",     # GT13 subdomain
    "newpayapp.com",          # GT13-controlled domain (registered 2026-03-13)
)
USER_AGENTS = (
    "Mozilla/5.0 (X11; Linux x86_64) research",  # HFS exploitation + commands
    "Mozilla/5.0 research",                      # seen once near HFS commands
)
HASSH = "eeca2460550b9ded084ecf2f70a75356"
ARTIFACT_PATH = "/usr/lib/.libproc.so"
ARTIFACT_NAME = ".libproc.so"

# All 69 ExpressVPN exit IPs enumerated in the GreyNoise report (AS206092).
# The campaign used 99 IPs in total; the remaining ~30 were compromised
# victim Check Point devices and are NOT listed in the report.
IPS = frozenset({
    "216.73.161.130", "216.73.161.123", "45.92.229.10", "45.92.229.9",
    "173.239.211.240", "45.92.229.6", "173.239.211.248", "216.73.161.118",
    "173.239.211.238", "45.92.229.11", "216.73.161.120", "216.73.161.116",
    "173.239.211.251", "216.73.161.131", "45.92.229.8", "173.239.211.243",
    "216.73.161.134", "216.73.161.129", "173.239.211.242", "173.239.211.245",
    "216.73.161.117", "45.92.229.1", "216.73.161.112", "173.239.211.246",
    "173.239.211.241", "173.239.211.234", "216.73.161.132", "63.135.161.10",
    "63.135.161.27", "63.135.161.29", "63.135.161.22", "63.135.161.24",
    "216.73.160.188", "216.73.160.190", "216.73.160.183", "216.73.160.29",
    "216.73.160.23", "45.130.83.138", "45.130.83.119", "45.92.229.208",
    "45.130.83.34", "45.130.83.49", "45.130.83.39", "45.130.83.43",
    "45.130.83.48", "45.130.83.47", "45.130.83.46", "45.130.83.55",
    "45.130.83.45", "45.92.229.171", "45.130.83.58", "45.92.229.181",
    "45.92.229.174", "45.130.83.57", "45.130.83.42", "45.130.83.51",
    "45.130.83.30", "45.130.83.53", "45.130.83.40", "45.130.83.56",
    "45.92.229.170", "45.92.229.161", "45.92.229.175", "45.8.19.209",
    "216.73.161.174", "45.8.19.244", "216.73.161.233", "216.73.161.107",
    "216.73.160.129",
})

_DOMAIN_RES = [
    (d, re.compile(r"(?<![A-Za-z0-9-])" + re.escape(d) + r"(?![A-Za-z0-9-])"))
    for d in DOMAINS
]
_IP_RES = [
    (ip, re.compile(r"(?<![0-9.])" + re.escape(ip) + r"(?![0-9.])"))
    for ip in sorted(IPS)
]

# Demo log: 6 lines, exactly 3 hits (ip, domain, user-agent). IPs in clean
# lines are TEST-NET documentation addresses (RFC 5737), never real hosts.
SAMPLE_LOG = (
    '203.0.113.7 - - [25/Nov/2026:10:00:01 +0000] "GET /health HTTP/1.1" '
    '200 15 "-" "curl/8.5.0"',
    '45.92.229.10 - - [25/Nov/2026:10:01:12 +0000] "POST /loginSrp1 HTTP/1.1" '
    '200 512 "-" "Mozilla/5.0"',
    '198.51.100.9 - - [25/Nov/2026:10:02:40 +0000] "GET /index.html HTTP/1.1" '
    '200 1024 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"',
    '198.51.100.23 - - [25/Nov/2026:10:03:55 +0000] "GET /zult HTTP/1.1" '
    '404 178 "https://data-zt.newpayapp.com/" "curl/8.5.0"',
    '203.0.113.44 - - [25/Nov/2026:10:05:19 +0000] "POST /loginSrp1 HTTP/1.1" '
    '200 640 "-" "Mozilla/5.0 (X11; Linux x86_64) research"',
    '203.0.113.91 - - [25/Nov/2026:10:06:02 +0000] "GET /robots.txt HTTP/1.1" '
    '200 88 "-" "Mozilla/5.0 (compatible; Googlebot/2.1)"',
)

USAGE = (
    "usage: gt13_ioc_check.py [--demo] [--help] [file ...]\n"
    "  Scan HTTP access logs (stdin if no file) for GreyNoise GT13 indicators.\n"
    "  exit 0 = no hits, 1 = hits found, 2 = usage error."
)

HIT_TYPES = ("domain", "user-agent", "ip", "hassh", "artifact")


def _defang_normalize(line):
    """Fold defanged indicators (newpayapp[.]com) back so pasted logs match."""
    return line.replace("[.]", ".")


def match_line(line):
    """Return a list of (ioc_type, matched_value) for one log line."""
    norm = _defang_normalize(line)
    hits = []
    for domain, rx in _DOMAIN_RES:
        if rx.search(norm):
            hits.append(("domain", domain))
            break
    for ua in USER_AGENTS:
        if ua in norm:
            hits.append(("user-agent", ua))
            break
    for ip, rx in _IP_RES:
        if rx.search(norm):
            hits.append(("ip", ip))
            break
    if HASSH in norm.lower():
        hits.append(("hassh", HASSH))
    if ARTIFACT_PATH in norm:
        hits.append(("artifact", ARTIFACT_PATH))
    elif ARTIFACT_NAME in norm:
        hits.append(("artifact", ARTIFACT_NAME))
    return hits


def scan_lines(lines):
    """Scan an iterable of raw log lines.

    Returns (hits, scanned, skipped) where hits is a list of
    (line_number, ioc_type, matched_value, original_line).
    A line is skipped (not scanned, not matched) when it is blank or has
    fewer than 3 whitespace-separated fields -- i.e. it is not a log line.
    Line numbers count scanned lines only, starting at 1.
    """
    hits = []
    scanned = 0
    skipped = 0
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip() or len(line.split()) < 3:
            skipped += 1
            continue
        scanned += 1
        for ioc_type, value in match_line(line):
            hits.append((scanned, ioc_type, value, line))
    return hits, scanned, skipped


def _counts(hits):
    counts = {t: 0 for t in HIT_TYPES}
    for _, ioc_type, _, _ in hits:
        counts[ioc_type] += 1
    return counts


def format_summary(hits, scanned, skipped):
    counts = _counts(hits)
    parts = " ".join("%s=%d" % (t, counts[t]) for t in HIT_TYPES)
    return ("scanned %d lines (%d skipped), %d hits: %s"
            % (scanned, skipped, len(hits), parts))


def print_scan(hits, scanned, skipped, out):
    for lineno, ioc_type, value, line in hits:
        out.write("line %d [%s] %s :: %s\n" % (lineno, ioc_type, value, line))
    out.write(format_summary(hits, scanned, skipped) + "\n")
    if hits:
        out.write("RESULT: HITS FOUND -- investigate these lines now\n")
    else:
        out.write("RESULT: clean -- no GT13 indicators found\n")


def run_demo(out):
    """Deterministic before/after showcase over the embedded sample log."""
    out.write("$ gt13_ioc_check.py --demo\n")
    out.write("BEFORE -- raw access log: 6 lines, 3 GT13 traces hiding in plain sight\n")
    for i, line in enumerate(SAMPLE_LOG, 1):
        out.write("  %d %s\n" % (i, line))
    out.write("AFTER -- gt13_ioc_check.py fixtures/sample.log:\n")
    hits, scanned, skipped = scan_lines(SAMPLE_LOG)
    print_scan(hits, scanned, skipped, out)
    return 0


def main(argv):
    args = list(argv)
    if "--help" in args or "-h" in args:
        sys.stdout.write(__doc__.split("Usage:")[0])
        sys.stdout.write(USAGE + "\n")
        return 0
    if "--demo" in args:
        if len(args) != 1:
            sys.stderr.write(USAGE + "\n")
            return 2
        return run_demo(sys.stdout)

    files = []
    for arg in args:
        if arg.startswith("-"):
            sys.stderr.write("unknown option: %s\n%s\n" % (arg, USAGE))
            return 2
        files.append(arg)

    lines = []
    try:
        if not files:
            lines = sys.stdin.read().splitlines()
        else:
            for path in files:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    lines.extend(fh.read().splitlines())
    except OSError as exc:
        sys.stderr.write("error: %s\n%s\n" % (exc, USAGE))
        return 2

    hits, scanned, skipped = scan_lines(lines)
    print_scan(hits, scanned, skipped, sys.stdout)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
