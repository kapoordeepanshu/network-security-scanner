"""Tests for CVE enrichment, baseline comparison and the HTML report (offline)."""

import json
import os
import tempfile
import unittest

from netscanner import baseline, cli, report, report_html, risks, vulns
from netscanner.scanner import HostResult, PortResult, Target


class FakeDB(vulns.VulnDB):
    """VulnDB with canned data instead of network calls."""

    def __init__(self):
        super().__init__(cache_dir=tempfile.mkdtemp())
        self.queried = []

    def cves_for_cpe(self, cpe):
        self.queried.append(cpe)
        return [
            {"id": "CVE-2024-6387", "cvss": 8.1, "severity": "HIGH", "summary": "regreSSHion"},
            {"id": "CVE-2016-0777", "cvss": 6.5, "severity": "MEDIUM", "summary": "roaming leak"},
            {"id": "CVE-2000-0001", "cvss": 9.8, "severity": "CRITICAL", "summary": "old"},
        ]

    def kev(self):
        return {"CVE-2024-6387": {"knownRansomwareCampaignUse": "Unknown"}}

    def epss(self, ids):
        return {"CVE-2024-6387": 0.99, "CVE-2016-0777": 0.63, "CVE-2000-0001": 0.01}


def host_with(*ports, address="10.0.0.1"):
    return HostResult(Target(address), up=True, ports=list(ports))


class CpeTests(unittest.TestCase):
    def test_cpe_mapping(self):
        self.assertEqual(vulns.cpe_for("OpenSSH", "8.9p1"), "cpe:2.3:a:openbsd:openssh:8.9")
        self.assertEqual(vulns.cpe_for("nginx", "1.10.3"), "cpe:2.3:a:f5:nginx:1.10.3")
        self.assertEqual(vulns.cpe_for("Apache", "2.4.7"), "cpe:2.3:a:apache:http_server:2.4.7")
        self.assertIsNone(vulns.cpe_for("SomethingElse", "1.0"))
        self.assertIsNone(vulns.cpe_for("OpenSSH", ""))

    def test_mariadb_version_is_unwrapped(self):
        port = PortResult(3306, "mysql", product="MySQL/MariaDB", version="5.5.5-10.4.28-MariaDB")
        self.assertEqual(vulns.products_for(port), [("MariaDB", "10.4.28")])

    def test_php_from_header(self):
        port = PortResult(80, "http", http={"headers": {"x-powered-by": "PHP/7.4.3"}})
        self.assertEqual(vulns.products_for(port), [("PHP", "7.4.3")])


class EnrichTests(unittest.TestCase):
    def test_prioritised_and_findings(self):
        port = PortResult(22, "ssh", product="OpenSSH", version="8.9p1")
        host = host_with(port)
        db = FakeDB()
        vulns.enrich([host], db)
        self.assertEqual(db.queried, ["cpe:2.3:a:openbsd:openssh:8.9"])
        # KEV first, then by EPSS - not by raw CVSS
        self.assertEqual([c["id"] for c in port.cves], ["CVE-2024-6387", "CVE-2016-0777", "CVE-2000-0001"])
        findings = {f.title: f.severity for f in risks.analyze(host)}
        self.assertEqual(findings["Actively exploited vulnerability CVE-2024-6387"], "CRITICAL")
        self.assertEqual(findings["3 known CVE(s) for OpenSSH 8.9p1"], "CRITICAL")

    def test_lookup_failure_does_not_crash(self):
        class Broken(FakeDB):
            def cves_for_cpe(self, cpe):
                raise OSError("network down")
        port = PortResult(22, "ssh", product="OpenSSH", version="8.9p1")
        vulns.enrich([host_with(port)], Broken())
        self.assertEqual(port.cves, [])

    def test_cache_roundtrip(self):
        db = vulns.VulnDB(cache_dir=tempfile.mkdtemp())
        calls = []
        fetch = lambda: calls.append(1) or {"x": 1}
        self.assertEqual(db._cached("k", fetch), {"x": 1})
        self.assertEqual(db._cached("k", fetch), {"x": 1})
        self.assertEqual(len(calls), 1)


class BaselineTests(unittest.TestCase):
    def test_compare(self):
        old_host = host_with(PortResult(22, "ssh"), PortResult(23, "telnet"))
        gone = host_with(PortResult(80, "http"), address="10.0.0.9")
        for h in (old_host, gone):
            risks.analyze(h)
        previous = json.loads(report.to_json([old_host, gone], {}))

        new_host = host_with(PortResult(22, "ssh"), PortResult(3389, "rdp"))
        risks.analyze(new_host)
        changes = baseline.compare([new_host], previous)

        self.assertEqual(changes["missing_hosts"], ["10.0.0.9"])
        self.assertEqual([x["port"] for x in changes["opened_ports"]], [3389])
        self.assertEqual([x["port"] for x in changes["closed_ports"]], [23])
        self.assertEqual([x["title"] for x in changes["new_findings"]], ["RDP exposed"])
        self.assertEqual([x["title"] for x in changes["resolved_findings"]], ["Telnet exposed"])
        self.assertTrue(baseline.has_changes(changes))
        self.assertFalse(baseline.has_changes(baseline.compare([old_host, gone], previous)))


class HtmlTests(unittest.TestCase):
    def test_banner_is_escaped(self):
        evil = PortResult(8080, "http", banner='<script>alert("x")</script>')
        host = host_with(evil)
        risks.analyze(host)
        page = report_html.render([host], {"targets": "10.0.0.1", "ports": "top"})
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("</script><", page.split('id="scan-data">', 1)[1].split("</script>", 1)[0])
        escaped = chr(92) + "u003cscript" + chr(92) + "u003ealert"  # how < > appear in the JSON
        self.assertIn(escaped, page)
        self.assertIn("Unencrypted HTTP service", page)

    def test_hostname_in_meta_is_escaped(self):
        page = report_html.render([], {"targets": "<img src=x onerror=alert(1)>", "ports": "top"})
        self.assertNotIn("<img src=x", page)


class CliTests(unittest.TestCase):
    def test_target_file_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            targets = os.path.join(tmp, "hosts.txt")
            with open(targets, "w") as fh:
                fh.write("# lab hosts\n127.0.0.1  # loopback\n\n")
            out_json, out_html = os.path.join(tmp, "r.json"), os.path.join(tmp, "r.html")
            code = cli.main(["-iL", targets, "-p", "1", "--no-color",
                             "--json", out_json, "--html", out_html])
            self.assertEqual(code, 0)
            self.assertEqual(json.load(open(out_json))["targets"], "127.0.0.1")
            self.assertIn("Network Scan Report", open(out_html, encoding="utf-8").read())
            code = cli.main(["127.0.0.1", "-p", "1", "--no-color", "--baseline", out_json,
                             "--fail-on-change"])
            self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
