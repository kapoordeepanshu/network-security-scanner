"""Console and JSON reporting."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from datetime import datetime, timezone

from .risks import SEVERITIES
from .scanner import HostResult

COLORS = {"CRITICAL": "\033[1;97;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[33m",
          "LOW": "\033[36m", "INFO": "\033[90m", "bold": "\033[1m", "green": "\033[32m",
          "dim": "\033[2m", "reset": "\033[0m"}


class Painter:
    def __init__(self, enabled: bool):
        self.enabled = enabled
        if enabled and os.name == "nt":
            os.system("")  # enables ANSI escape processing in the Windows console

    def __call__(self, text: str, style: str) -> str:
        return f"{COLORS[style]}{text}{COLORS['reset']}" if self.enabled else text


def severity_counts(hosts: list[HostResult]) -> dict[str, int]:
    counts = dict.fromkeys(SEVERITIES, 0)
    for h in hosts:
        for f in h.findings:
            counts[f.severity] += 1
    return counts


def print_report(hosts: list[HostResult], elapsed: float, color: bool = True,
                 show_closed_hosts: bool = False, out=sys.stdout) -> None:
    c = Painter(color and out.isatty())
    w = lambda s="": print(s, file=out)

    for h in hosts:
        if not h.up and not show_closed_hosts:
            continue
        name = f"{h.target.address}" + (f" ({h.target.hostname})" if h.target.hostname else "")
        w()
        w(c(f"Host: {name}", "bold") + ("" if h.up else c("  [no response]", "dim")))
        if not h.ports:
            w("  No open ports found.")
            continue
        w(f"  {'PORT':<10}{'SERVICE':<16}{'VERSION / BANNER'}")
        for p in sorted(h.ports, key=lambda p: p.port):
            detail = f"{p.product} {p.version}".strip() or p.banner
            if p.tls and p.tls.get("protocol"):
                detail = f"{detail}  [{p.tls['protocol']}]".strip()
            if p.cves:
                kev = sum(1 for cve in p.cves if cve.get("kev"))
                detail += f"  [{len(p.cves)} CVEs" + (f", {kev} exploited]" if kev else "]")
            w(f"  {c(f'{p.port}/tcp', 'green'):<{10 + (len(c('', 'green')))}}"
              f"{p.service:<16}{detail}")
        if h.findings:
            w()
            w(c("  Findings:", "bold"))
            for f in h.findings:
                where = f"{f.port}/tcp" if f.port else "host"
                w(f"   {c(f'[{f.severity}]', f.severity):<{10 + len(c('', f.severity))}} "
                  f"{where:<10}{f.title}")
                if f.detail:
                    w(c(f"{'':24}{f.detail}", "dim"))
                w(f"{'':24}-> {f.recommendation}")

    up = sum(h.up for h in hosts)
    open_ports = sum(len(h.ports) for h in hosts)
    counts = severity_counts(hosts)
    w()
    w(c("=" * 70, "dim"))
    w(f"Scanned {len(hosts)} host(s), {up} up, {open_ports} open port(s) in {elapsed:.1f}s")
    w("Findings: " + ", ".join(c(f"{n} {s}", s) if n else f"{n} {s}" for s, n in counts.items()))


def _where(change: dict) -> str:
    return change["address"] + (f":{change['port']}" if change.get("port") else "")


def print_changes(changes: dict, color: bool = True, out=sys.stdout) -> None:
    c = Painter(color and out.isatty())
    w = lambda s="": print(s, file=out)
    w()
    w(c(f"Changes since baseline ({changes['baseline_generated'] or 'unknown date'}):", "bold"))
    lines = (
        [c(f"  + host up      {h}", "HIGH") for h in changes["new_hosts"]]
        + [f"  - host gone    {h}" for h in changes["missing_hosts"]]
        + [c(f"  + port opened  {x['address']}:{x['port']} ({x['service']})", "HIGH")
           for x in changes["opened_ports"]]
        + [c(f"  - port closed  {x['address']}:{x['port']} ({x['service']})", "green")
           for x in changes["closed_ports"]]
        + [c(f"  + new finding  {_where(x)} [{x['severity']}] {x['title']}", x["severity"])
           for x in changes["new_findings"]]
        + [c(f"  - resolved     {_where(x)} [{x['severity']}] {x['title']}", "green")
           for x in changes["resolved_findings"]]
    )
    for line in lines or ["  No changes."]:
        w(line)


def to_json(hosts: list[HostResult], meta: dict, changes: dict | None = None) -> str:
    data = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        **meta,
        "summary": severity_counts(hosts),
        **({"changes": changes} if changes is not None else {}),
        "hosts": [
            {
                "address": h.target.address,
                "hostname": h.target.hostname,
                "up": h.up,
                "ports": [asdict(p) for p in sorted(h.ports, key=lambda p: p.port)],
                "findings": [asdict(f) for f in h.findings],
            }
            for h in hosts if h.up
        ],
    }
    return json.dumps(data, indent=2)
