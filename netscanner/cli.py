"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
import time

from . import __version__, baseline, report, report_html, risks, scanner

BANNER = f"netscanner {__version__} - TCP port & basic security risk scanner"
NOTICE = "Only scan systems you own or have explicit written permission to test."


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netscanner",
        description=f"{BANNER}\n{NOTICE}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="examples:\n"
               "  netscanner 192.168.1.10\n"
               "  netscanner 192.168.1.0/24 -p 22,80,443,3389 --html report.html\n"
               "  netscanner example.com --cve --json today.json --baseline yesterday.json\n"
               "  netscanner -iL hosts.txt -p all -w 500 -t 0.5 --fail-on high",
    )
    p.add_argument("targets", nargs="?", default="",
                   help="IP, hostname, CIDR (10.0.0.0/24) or range (10.0.0.1-50); comma separated")
    p.add_argument("--version", action="version", version=__version__)

    g = p.add_argument_group("scanning")
    g.add_argument("-iL", dest="target_file", metavar="FILE",
                   help="read targets from FILE (one per line, '#' comments allowed)")
    g.add_argument("-p", "--ports", default="top",
                   help="'top' (default, 67 common ports), 'all', or list/ranges e.g. 22,80,8000-8100")
    g.add_argument("-t", "--timeout", type=float, default=1.0, help="connect timeout in seconds (default 1.0)")
    g.add_argument("-w", "--workers", type=int, default=200, help="concurrent connections (default 200)")
    g.add_argument("--no-discovery", action="store_true",
                   help="scan every host even if it doesn't answer discovery probes")
    g.add_argument("--no-detect", action="store_true", help="skip banner grabbing / service detection")
    g.add_argument("--max-hosts", type=int, default=1024, help="safety limit on number of hosts (default 1024)")

    g = p.add_argument_group("vulnerability intelligence (needs internet)")
    g.add_argument("--cve", action="store_true",
                   help="look up known CVEs (NVD) for detected versions, prioritised by CISA KEV and EPSS")
    g.add_argument("--nvd-api-key", metavar="KEY",
                   help="NVD API key for 10x faster lookups (or set NVD_API_KEY)")
    g.add_argument("--cache-hours", type=float, default=24, help="reuse cached CVE data this long (default 24)")

    g = p.add_argument_group("output")
    g.add_argument("--json", metavar="FILE", help="write a JSON report to FILE ('-' for stdout only)")
    g.add_argument("--html", metavar="FILE", help="write a self-contained HTML report to FILE")
    g.add_argument("--baseline", metavar="FILE", help="compare against a previous JSON report and show changes")
    g.add_argument("--no-color", action="store_true", help="disable colored output")
    g.add_argument("--fail-on", choices=[s.lower() for s in risks.SEVERITIES],
                   help="exit with code 2 if any finding at or above this severity (for CI)")
    g.add_argument("--fail-on-change", action="store_true",
                   help="exit with code 3 if anything changed versus --baseline")
    return p


def read_target_file(path: str) -> str:
    with open(path, encoding="utf-8") as fh:
        lines = (line.split("#", 1)[0].strip() for line in fh)
        return ",".join(line for line in lines if line)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):  # never crash on unencodable banner/CVE text
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    quiet = args.json == "-"
    log = (lambda *a, **k: None) if quiet else (lambda *a, **k: print(*a, file=sys.stderr, **k))

    try:
        spec = ",".join(filter(None, [args.targets,
                                      read_target_file(args.target_file) if args.target_file else ""]))
        if not spec:
            parser.error("give a target or -iL FILE")
        ports = scanner.parse_ports(args.ports)
        targets = scanner.parse_targets(spec, args.max_hosts)
        previous = baseline.load(args.baseline) if args.baseline else None
        if args.fail_on_change and previous is None:
            parser.error("--fail-on-change requires --baseline")
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    log(BANNER)
    log(f"[!] {NOTICE}")
    log(f"[*] Scanning {len(targets)} host(s) x {len(ports)} port(s), "
        f"timeout {args.timeout}s, {args.workers} workers")

    def progress(done: int, total: int) -> None:
        if not quiet and sys.stderr.isatty():
            print(f"\r[*] Port scan progress: {done}/{total} ({done * 100 // total}%)",
                  end="", file=sys.stderr, flush=True)

    start = time.monotonic()
    try:
        hosts = scanner.scan(targets, ports, timeout=args.timeout, workers=args.workers,
                             discover=not args.no_discovery, detect=not args.no_detect,
                             progress=progress)
        if not quiet and sys.stderr.isatty():
            print(file=sys.stderr)
        if args.cve:
            from . import vulns  # only needed (and only touches the network) when asked
            db = vulns.VulnDB(api_key=args.nvd_api_key, cache_hours=args.cache_hours, log=log)
            vulns.enrich(hosts, db)
    except KeyboardInterrupt:
        print("\n[!] Interrupted.", file=sys.stderr)
        return 130
    elapsed = time.monotonic() - start

    for host in hosts:
        risks.analyze(host)
    changes = baseline.compare(hosts, previous) if previous is not None else None

    if not quiet:
        report.print_report(hosts, elapsed, color=not args.no_color)
        if changes is not None:
            report.print_changes(changes, color=not args.no_color)

    meta = {"targets": spec, "ports": args.ports, "elapsed_seconds": round(elapsed, 2)}
    if args.json:
        data = report.to_json(hosts, meta, changes)
        if args.json == "-":
            print(data)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(data)
            log(f"[*] JSON report written to {args.json}")
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(report_html.render(hosts, meta, changes))
        log(f"[*] HTML report written to {args.html}")

    if args.fail_on:
        threshold = risks.SEVERITIES.index(args.fail_on.upper())
        if any(risks.SEVERITIES.index(f.severity) <= threshold for h in hosts for f in h.findings):
            return 2
    if args.fail_on_change and baseline.has_changes(changes):
        return 3
    return 0
