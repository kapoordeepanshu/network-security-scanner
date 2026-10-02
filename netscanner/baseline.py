"""Compare a scan against a previous JSON report to see what changed."""

from __future__ import annotations

import json

from .scanner import HostResult


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if "hosts" not in data:
        raise ValueError(f"{path} is not a netscanner JSON report")
    return data


def compare(hosts: list[HostResult], previous: dict) -> dict:
    """Return new/missing hosts, opened/closed ports and new/resolved findings."""
    old_hosts = {h["address"]: h for h in previous.get("hosts", [])}
    new_hosts = {h.target.address: h for h in hosts if h.up}

    changes = {
        "baseline_generated": previous.get("generated", ""),
        "new_hosts": sorted(set(new_hosts) - set(old_hosts)),
        "missing_hosts": sorted(set(old_hosts) - set(new_hosts)),
        "opened_ports": [], "closed_ports": [],
        "new_findings": [], "resolved_findings": [],
    }

    for address in sorted(set(old_hosts) | set(new_hosts)):
        old = old_hosts.get(address, {"ports": [], "findings": []})
        cur = new_hosts.get(address)
        old_ports = {p["port"]: p.get("service", "") for p in old["ports"]}
        cur_ports = {p.port: p.service for p in cur.ports} if cur else {}
        old_findings = {(f.get("port"), f["title"]): f for f in old["findings"]}
        cur_findings = {(f.port, f.title): f for f in cur.findings} if cur else {}

        if cur is None:
            continue  # host vanished: listed once in missing_hosts, not per port
        for port in sorted(set(cur_ports) - set(old_ports)):
            changes["opened_ports"].append({"address": address, "port": port, "service": cur_ports[port]})
        for port in sorted(set(old_ports) - set(cur_ports)):
            changes["closed_ports"].append({"address": address, "port": port, "service": old_ports[port]})
        for key in sorted(set(cur_findings) - set(old_findings), key=str):
            f = cur_findings[key]
            changes["new_findings"].append({"address": address, "port": f.port,
                                            "severity": f.severity, "title": f.title})
        for key in sorted(set(old_findings) - set(cur_findings), key=str):
            f = old_findings[key]
            changes["resolved_findings"].append({"address": address, "port": f.get("port"),
                                                 "severity": f["severity"], "title": f["title"]})
    return changes


def has_changes(changes: dict) -> bool:
    return any(changes[k] for k in ("new_hosts", "missing_hosts", "opened_ports",
                                    "closed_ports", "new_findings", "resolved_findings"))
