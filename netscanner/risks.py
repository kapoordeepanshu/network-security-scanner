"""Rules that turn scan results into security findings.

These are heuristics meant to highlight *likely* problems for follow-up,
not a substitute for a vulnerability scanner or manual verification.
"""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from .scanner import HostResult, PortResult

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


@dataclass
class Finding:
    severity: str
    title: str
    port: int | None
    detail: str
    recommendation: str


# service -> (severity, title, why it matters, what to do)
RISKY_SERVICES: dict[str, tuple[str, str, str, str]] = {
    "telnet": ("HIGH", "Telnet exposed",
               "Telnet sends credentials and session data in cleartext.",
               "Disable Telnet and use SSH instead."),
    "ftp": ("MEDIUM", "FTP exposed",
            "FTP sends credentials and files in cleartext.",
            "Replace with SFTP/FTPS, or restrict access to trusted hosts."),
    "rexec": ("HIGH", "Legacy r-service (rexec) exposed",
              "r-services use cleartext and weak host-based trust.",
              "Disable rexec/rlogin/rsh; use SSH."),
    "rlogin": ("HIGH", "Legacy r-service (rlogin) exposed",
               "r-services use cleartext and weak host-based trust.",
               "Disable rexec/rlogin/rsh; use SSH."),
    "rsh": ("HIGH", "Legacy r-service (rsh) exposed",
            "r-services use cleartext and weak host-based trust.",
            "Disable rexec/rlogin/rsh; use SSH."),
    "smb": ("HIGH", "SMB exposed",
            "SMB is a common target for wormable exploits (e.g. EternalBlue) and credential attacks.",
            "Block 445/tcp at the network edge; disable SMBv1 and keep systems patched."),
    "netbios-ssn": ("MEDIUM", "NetBIOS session service exposed",
                    "NetBIOS leaks host/domain information and enables legacy SMB access.",
                    "Disable NetBIOS over TCP/IP if not required; firewall 139/tcp."),
    "msrpc": ("MEDIUM", "Microsoft RPC exposed",
              "MS-RPC exposes Windows management interfaces useful for enumeration and lateral movement.",
              "Restrict 135/tcp to trusted management networks."),
    "rdp": ("HIGH", "RDP exposed",
            "RDP is heavily targeted by brute-force attacks and exploits (e.g. BlueKeep).",
            "Put RDP behind a VPN/gateway, enforce NLA, MFA and account lockout."),
    "vnc": ("HIGH", "VNC exposed",
            "VNC often uses weak or no authentication and unencrypted sessions.",
            "Tunnel VNC over SSH/VPN and require strong authentication."),
    "winrm": ("MEDIUM", "WinRM (HTTP) exposed",
              "Remote PowerShell management interface reachable over unencrypted HTTP.",
              "Restrict WinRM to management hosts; prefer HTTPS (5986)."),
    "docker": ("CRITICAL", "Docker API exposed without TLS",
               "An unauthenticated Docker API grants root-equivalent control of the host.",
               "Bind Docker to a unix socket, or require TLS client certificates on 2376."),
    "kubelet": ("HIGH", "Kubelet API exposed",
                "Misconfigured kubelets allow command execution inside pods.",
                "Disable anonymous auth and restrict 10250/tcp to the control plane."),
    "mysql": ("MEDIUM", "MySQL/MariaDB exposed",
              "Databases reachable from the network invite brute-force and data theft.",
              "Bind to localhost or restrict with firewall rules."),
    "postgresql": ("MEDIUM", "PostgreSQL exposed",
                   "Databases reachable from the network invite brute-force and data theft.",
                   "Bind to localhost or restrict with pg_hba.conf and firewall rules."),
    "mssql": ("MEDIUM", "Microsoft SQL Server exposed",
              "Databases reachable from the network invite brute-force and data theft.",
              "Restrict 1433/tcp to application servers only."),
    "oracle": ("MEDIUM", "Oracle TNS listener exposed",
               "Databases reachable from the network invite brute-force and data theft.",
               "Restrict 1521/tcp to application servers only."),
    "mongodb": ("HIGH", "MongoDB exposed",
                "MongoDB instances are frequently found without authentication and mass-ransomed.",
                "Enable authentication and bind to localhost/private interfaces."),
    "redis": ("HIGH", "Redis exposed",
              "Redis is designed for trusted networks; exposure can lead to data theft or RCE.",
              "Bind to localhost, enable requirepass/ACLs, and enable protected-mode."),
    "elasticsearch": ("HIGH", "Elasticsearch exposed",
                      "Open Elasticsearch clusters are a leading cause of large data leaks.",
                      "Enable security features (authentication/TLS) and restrict network access."),
    "memcached": ("HIGH", "Memcached exposed",
                  "Memcached has no auth by default and is abused for DDoS amplification.",
                  "Bind to localhost and disable UDP."),
    "rsync": ("MEDIUM", "rsync daemon exposed",
              "rsync modules are often readable (or writable) without authentication.",
              "Require authentication on modules or tunnel over SSH."),
    "nfs": ("MEDIUM", "NFS exposed",
            "NFS exports may be mountable by untrusted hosts.",
            "Restrict exports to specific hosts and use root_squash."),
    "pptp": ("MEDIUM", "PPTP VPN exposed",
             "PPTP/MS-CHAPv2 encryption is cryptographically broken.",
             "Migrate to WireGuard, IPsec/IKEv2 or OpenVPN."),
    "mqtt": ("MEDIUM", "MQTT broker exposed (cleartext)",
             "MQTT brokers are often unauthenticated, exposing IoT data and control.",
             "Require authentication and use MQTT over TLS (8883)."),
    "pop3": ("LOW", "POP3 without TLS",
             "Mailbox credentials may be sent in cleartext.",
             "Use POP3S (995) or enforce STARTTLS."),
    "imap": ("LOW", "IMAP without TLS",
             "Mailbox credentials may be sent in cleartext.",
             "Use IMAPS (993) or enforce STARTTLS."),
    "http": ("LOW", "Unencrypted HTTP service",
             "Traffic, including any credentials or session cookies, is sent in cleartext.",
             "Serve over HTTPS and redirect HTTP to HTTPS."),
}

# (regex on "product version" or banner, severity, title, recommendation)
OUTDATED_SOFTWARE = [
    (r"vsFTPd 2\.3\.4\b", "CRITICAL", "vsFTPd 2.3.4 (known backdoored release)",
     "Upgrade vsFTPd immediately and investigate for compromise."),
    (r"ProFTPD 1\.3\.[0-3]", "HIGH", "Outdated ProFTPD with known RCE vulnerabilities",
     "Upgrade ProFTPD to a supported release."),
    (r"OpenSSH[ _][1-6]\.", "MEDIUM", "Outdated OpenSSH version",
     "Upgrade OpenSSH; versions before 7.x have multiple known vulnerabilities."),
    (r"OpenSSH[ _](7\.|8\.|9\.[0-7](?!\d))", "LOW",
     "OpenSSH older than 9.8 (possible regreSSHion CVE-2024-6387 / other CVEs)",
     "Confirm the vendor has backported fixes, or upgrade OpenSSH."),
    (r"Apache[/ ](1\.|2\.[0-2]\.)", "MEDIUM", "End-of-life Apache httpd",
     "Upgrade to a supported Apache 2.4 release."),
    (r"Microsoft-IIS[/ ][5-7]\.", "MEDIUM", "End-of-life Microsoft IIS",
     "Upgrade the underlying Windows Server/IIS version."),
    (r"nginx[/ ](0\.|1\.([0-9]|1[0-9])\.)", "LOW", "Outdated nginx version",
     "Upgrade nginx to a currently supported release."),
    (r"PHP[/ ](4|5|7\.[0-4])\b", "MEDIUM", "End-of-life PHP version",
     "Upgrade PHP to a supported 8.x release."),
]

_TLS_SELF_SIGNED = {18, 19}  # X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT, SELF_SIGNED_CERT_IN_CHAIN
_TLS_EXPIRED = 10            # X509_V_ERR_CERT_HAS_EXPIRED


def analyze(host: HostResult) -> list[Finding]:
    findings: list[Finding] = []
    for port in host.ports:
        findings += _port_findings(port)
    if len(host.ports) >= 20:
        findings.append(Finding(
            "INFO", "Large attack surface", None,
            f"{len(host.ports)} open TCP ports detected.",
            "Review each service and close anything not strictly required."))
    findings.sort(key=lambda f: (SEVERITIES.index(f.severity), f.port or 0))
    host.findings = findings
    return findings


def _port_findings(p: PortResult) -> list[Finding]:
    out: list[Finding] = []
    add = lambda sev, title, detail, rec: out.append(Finding(sev, title, p.port, detail, rec))

    if p.service in RISKY_SERVICES:
        sev, title, detail, rec = RISKY_SERVICES[p.service]
        if p.service == "redis" and p.redis_auth is False:
            sev, title = "CRITICAL", "Redis exposed WITHOUT authentication"
            detail = "Redis answered PING without credentials; anyone can read/write data and often achieve RCE."
        add(sev, title, detail, rec)

    if p.service == "ssh" and p.ssh_protocol.startswith("1."):
        add("HIGH", "SSH protocol version 1 supported",
            f"Server advertises SSH-{p.ssh_protocol}; SSHv1 is cryptographically broken.",
            "Disable SSH protocol 1.")

    software = f"{p.product} {p.version}".strip()
    headers = (p.http or {}).get("headers", {})
    haystack = " | ".join([software, p.banner, headers.get("server", ""), headers.get("x-powered-by", "")])
    for pattern, sev, title, rec in OUTDATED_SOFTWARE:
        if re.search(pattern, haystack, re.I):
            add(sev, title, f"Detected: {software or p.banner}", rec)

    if p.cves:
        out += _cve_findings(p, software or p.banner)
    if p.http:
        out += _http_findings(p)
    if p.tls:
        out += _tls_findings(p)
    return out


BACKPORT_NOTE = ("Matched by version string only; Linux distributions often backport fixes, "
                 "so confirm against your vendor's advisories.")


def _shorten(text: str, limit: int = 200) -> str:
    return text if len(text) <= limit else text[:limit].rsplit(" ", 1)[0] + "..."


def _cve_label(cve: dict) -> str:
    parts = [cve["id"]]
    if cve.get("cvss") is not None:
        parts.append(f"CVSS {cve['cvss']}")
    if cve.get("epss") is not None:
        parts.append(f"EPSS {cve['epss']:.1%}")
    if cve.get("kev"):
        parts.append("CISA KEV" + (", ransomware" if cve.get("ransomware") else ""))
    return " ".join(parts[:1]) + (f" ({', '.join(parts[1:])})" if len(parts) > 1 else "")


def _cve_findings(p: PortResult, software: str) -> list[Finding]:
    out: list[Finding] = []
    exploited = [c for c in p.cves if c.get("kev")]
    for cve in exploited[:5]:
        out.append(Finding(
            "CRITICAL", f"Actively exploited vulnerability {cve['id']}", p.port,
            f"{software}: {_cve_label(cve)}. {_shorten(cve.get('summary', ''))}",
            "Patch immediately: CISA lists this CVE as exploited in the wild. " + BACKPORT_NOTE))

    rated = [c["severity"] for c in p.cves if c.get("severity") in SEVERITIES]
    worst = min(rated, key=SEVERITIES.index) if rated else "MEDIUM"
    if worst == "CRITICAL" and not exploited:
        worst = "HIGH"  # reserve CRITICAL for confirmed exploitation
    top = "; ".join(_cve_label(c) for c in p.cves[:5])
    out.append(Finding(
        worst, f"{len(p.cves)} known CVE(s) for {software}", p.port,
        f"Top by priority: {top}" + (" ..." if len(p.cves) > 5 else ""),
        "Upgrade to a patched release. " + BACKPORT_NOTE))
    return out


def _http_findings(p: PortResult) -> list[Finding]:
    out: list[Finding] = []
    headers = p.http.get("headers", {})
    leaks = [f"{h}: {headers[h]}" for h in ("server", "x-powered-by", "x-aspnet-version")
             if h in headers and re.search(r"\d", headers[h])]
    if leaks:
        out.append(Finding("LOW", "Software version disclosed in HTTP headers", p.port,
                           "; ".join(leaks),
                           "Suppress version details (e.g. 'server_tokens off', 'ServerTokens Prod')."))
    missing = []
    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        missing.append("X-Frame-Options/CSP frame-ancestors")
    if "x-content-type-options" not in headers:
        missing.append("X-Content-Type-Options")
    if "content-security-policy" not in headers:
        missing.append("Content-Security-Policy")
    if p.tls and "strict-transport-security" not in headers:
        missing.append("Strict-Transport-Security")
    if missing:
        out.append(Finding("INFO", "Missing HTTP security headers", p.port,
                           ", ".join(missing),
                           "Add the missing headers in the web server or application config."))
    return out


def _tls_findings(p: PortResult) -> list[Finding]:
    out: list[Finding] = []
    tls = p.tls
    if tls.get("verified") is False:
        code, msg = tls.get("verify_code"), tls.get("verify_message", "")
        if code == _TLS_EXPIRED:
            out.append(Finding("HIGH", "TLS certificate expired", p.port, msg,
                               "Renew the certificate (consider automated renewal, e.g. ACME)."))
        elif code in _TLS_SELF_SIGNED:
            out.append(Finding("MEDIUM", "Self-signed TLS certificate", p.port, msg,
                               "Use a certificate from a trusted CA so clients can detect MITM."))
        else:
            out.append(Finding("MEDIUM", "Untrusted TLS certificate", p.port, msg,
                               "Install a certificate chain that validates against public CAs."))
    elif tls.get("verified") and tls.get("not_after"):
        try:
            expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(tls["not_after"]), timezone.utc)
            days = (expires - datetime.now(timezone.utc)).days
            if days < 30:
                out.append(Finding("LOW", "TLS certificate expiring soon", p.port,
                                   f"Expires {expires:%Y-%m-%d} ({days} days).",
                                   "Renew the certificate before it expires."))
        except ValueError:
            pass

    if tls.get("legacy_protocol"):
        out.append(Finding("MEDIUM", "Deprecated TLS protocol accepted", p.port,
                           f"Server negotiated {tls['legacy_protocol']} (TLS 1.0/1.1 are deprecated, RFC 8996).",
                           "Disable TLS 1.0/1.1; allow only TLS 1.2 and 1.3."))
    cipher = tls.get("cipher", "")
    if re.search(r"RC4|3DES|DES-CBC|NULL|EXPORT|anon", cipher):
        out.append(Finding("HIGH", "Weak TLS cipher negotiated", p.port, cipher,
                           "Remove RC4/3DES/NULL/EXPORT ciphers from the server configuration."))
    return out
