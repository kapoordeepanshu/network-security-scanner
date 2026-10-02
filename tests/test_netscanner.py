"""Tests for netscanner. Run with: python -m unittest discover tests"""

import socket
import socketserver
import threading
import unittest

from netscanner import risks, scanner, services
from netscanner.scanner import PortResult, Target


class ParsingTests(unittest.TestCase):
    def test_ports(self):
        self.assertEqual(scanner.parse_ports("22,80,8000-8002"), [22, 80, 8000, 8001, 8002])
        self.assertEqual(scanner.parse_ports("all")[-1], 65535)
        self.assertEqual(scanner.parse_ports("top"), services.DEFAULT_PORTS)
        for bad in ("0", "70000", ""):
            with self.assertRaises(ValueError):
                scanner.parse_ports(bad)

    def test_targets(self):
        self.assertEqual(len(scanner.parse_targets("192.168.1.0/30")), 2)
        self.assertEqual([t.address for t in scanner.parse_targets("10.0.0.1-3")],
                         ["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        self.assertEqual(scanner.parse_targets("localhost")[0].hostname, "localhost")
        with self.assertRaises(ValueError):
            scanner.parse_targets("10.0.0.0/16", max_hosts=100)


class FingerprintTests(unittest.TestCase):
    def test_ssh(self):
        info = services.fingerprint(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3\r\n", "ssh")
        self.assertEqual((info["service"], info["product"], info["version"]),
                         ("ssh", "OpenSSH", "8.9p1"))

    def test_http_on_odd_port(self):
        raw = b"HTTP/1.1 200 OK\r\nServer: Apache/2.2.15 (CentOS)\r\n\r\nhi"
        info = services.fingerprint(raw, "unknown")
        self.assertEqual((info["service"], info["product"], info["version"]),
                         ("http", "Apache", "2.2.15"))

    def test_ftp_and_mysql_and_redis(self):
        self.assertEqual(services.fingerprint(b"220 (vsFTPd 2.3.4)\r\n", "ftp")["version"], "2.3.4")
        mysql = b"\x4a\x00\x00\x00\x0a8.0.36\x00rest"
        self.assertEqual(services.fingerprint(mysql, "mysql")["version"], "8.0.36")
        self.assertIs(services.fingerprint(b"+PONG\r\n", "unknown")["redis_auth"], False)
        self.assertIs(services.fingerprint(b"-NOAUTH Authentication required.\r\n", "redis")["redis_auth"], True)


class RiskTests(unittest.TestCase):
    def findings(self, *ports):
        host = scanner.HostResult(Target("10.0.0.1"), up=True, ports=list(ports))
        return {f.title: f.severity for f in risks.analyze(host)}

    def test_risky_services(self):
        f = self.findings(PortResult(23, "telnet"), PortResult(445, "smb"))
        self.assertEqual(f["Telnet exposed"], "HIGH")
        self.assertEqual(f["SMB exposed"], "HIGH")

    def test_unauthenticated_redis_is_critical(self):
        f = self.findings(PortResult(6379, "redis", redis_auth=False))
        self.assertEqual(f["Redis exposed WITHOUT authentication"], "CRITICAL")

    def test_outdated_software(self):
        f = self.findings(PortResult(21, "ftp", product="vsFTPd", version="2.3.4"),
                          PortResult(22, "ssh", product="OpenSSH", version="8.9p1"))
        self.assertEqual(f["vsFTPd 2.3.4 (known backdoored release)"], "CRITICAL")
        self.assertIn("OpenSSH older than 9.8 (possible regreSSHion CVE-2024-6387 / other CVEs)", f)

    def test_tls_findings(self):
        tls = {"verified": False, "verify_code": 18, "verify_message": "self-signed certificate",
               "legacy_protocol": "TLSv1", "cipher": "DES-CBC3-SHA"}
        f = self.findings(PortResult(443, "https", tls=tls))
        self.assertEqual(f["Self-signed TLS certificate"], "MEDIUM")
        self.assertEqual(f["Deprecated TLS protocol accepted"], "MEDIUM")
        self.assertEqual(f["Weak TLS cipher negotiated"], "HIGH")

    def test_http_headers(self):
        http = {"status": "HTTP/1.1 200 OK", "headers": {"server": "nginx/1.18.0"}}
        f = self.findings(PortResult(80, "http", http=http))
        self.assertIn("Software version disclosed in HTTP headers", f)
        self.assertIn("Missing HTTP security headers", f)
        self.assertIn("Outdated nginx version", f)


class _Server:
    """Tiny local TCP server that replies like a real service."""

    def __init__(self, greeting=b"", reply=b""):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                if greeting:
                    self.request.sendall(greeting)
                else:
                    self.request.settimeout(10)
                    try:
                        self.request.recv(1024)
                    except OSError:
                        return
                    self.request.sendall(reply)

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class IntegrationTests(unittest.TestCase):
    def test_scan_localhost(self):
        ssh = _Server(greeting=b"SSH-2.0-OpenSSH_6.6.1\r\n")
        http = _Server(reply=b"HTTP/1.0 200 OK\r\nServer: Apache/2.2.3\r\n\r\n")
        redis = _Server(reply=b"+PONG\r\n")
        # find a closed port by binding and releasing it
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            closed = s.getsockname()[1]
        try:
            target = Target("127.0.0.1")
            self.assertEqual(scanner.tcp_probe(target, ssh.port, 1), scanner.OPEN)
            self.assertNotEqual(scanner.tcp_probe(target, closed, 1), scanner.OPEN)

            [host] = scanner.scan([target], [ssh.port, http.port, redis.port, closed], timeout=1)
            by_port = {p.port: p for p in host.ports}
            self.assertEqual(set(by_port), {ssh.port, http.port, redis.port})
            self.assertEqual(by_port[ssh.port].service, "ssh")
            self.assertEqual(by_port[http.port].product, "Apache")
            self.assertEqual(by_port[redis.port].service, "redis")

            titles = {f.title for f in risks.analyze(host)}
            self.assertIn("Outdated OpenSSH version", titles)
            self.assertIn("End-of-life Apache httpd", titles)
            self.assertIn("Redis exposed WITHOUT authentication", titles)
        finally:
            for srv in (ssh, http, redis):
                srv.close()


if __name__ == "__main__":
    unittest.main()
