"""Port-to-service mapping and banner fingerprinting."""

from __future__ import annotations

import re

# Well-known TCP ports and the service usually found on them.
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 119: "nntp",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 512: "rexec", 513: "rlogin", 514: "rsh",
    515: "printer", 548: "afp", 554: "rtsp", 587: "smtp", 631: "ipp",
    636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s", 1080: "socks",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 1883: "mqtt", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3000: "http", 3306: "mysql",
    3389: "rdp", 4443: "https", 5000: "http", 5432: "postgresql",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 5901: "vnc", 5985: "winrm",
    5986: "winrm-https", 6379: "redis", 6443: "kubernetes-api", 7001: "http",
    8000: "http", 8008: "http", 8080: "http", 8081: "http", 8443: "https",
    8888: "http", 9000: "http", 9090: "http", 9092: "kafka",
    9200: "elasticsearch", 9300: "elasticsearch", 10250: "kubelet",
    11211: "memcached", 27017: "mongodb",
}

# Ports where the service normally speaks TLS from the first byte.
TLS_PORTS = {443, 465, 636, 993, 995, 2376, 4443, 5986, 6443, 8443, 10250}

HTTP_SERVICES = {"http", "https", "kibana", "elasticsearch", "docker",
                 "docker-tls", "kubernetes-api", "kubelet", "winrm",
                 "winrm-https"}

DEFAULT_PORTS = sorted(COMMON_PORTS)


def guess_by_port(port: int) -> str:
    return COMMON_PORTS.get(port, "unknown")


def probe_for(service: str, host: str) -> bytes | None:
    """Payload to send when a service does not greet us with a banner."""
    if service == "redis":
        return b"PING\r\n"
    if service in {"mysql", "postgresql", "mssql", "oracle", "mongodb",
                   "smb", "msrpc", "netbios-ssn", "rdp", "memcached"}:
        return None  # binary protocols: don't send garbage
    # Default: a minimal HTTP request identifies most unknown TCP services.
    return (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
            "User-Agent: netscanner\r\nAccept: */*\r\n\r\n").encode()


def parse_http(raw: bytes) -> tuple[str, dict[str, str], str]:
    """Return (status_line, headers lowercase-keyed, body) of an HTTP reply."""
    text = raw.decode("latin-1")
    head, _, body = text.partition("\r\n\r\n")
    lines = head.split("\r\n")
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
    return lines[0], headers, body


_PRODUCT_VERSION = re.compile(r"([A-Za-z][\w\-. ]*?)[/ ]v?(\d[\w.\-]*)")


def _split_product(text: str) -> tuple[str, str]:
    m = _PRODUCT_VERSION.search(text)
    if m:
        return m.group(1).strip(), m.group(2)
    return text.strip(), ""


def fingerprint(raw: bytes, port_guess: str) -> dict:
    """Identify service/product/version from the raw bytes a port returned."""
    info = {"service": port_guess, "product": "", "version": "",
            "http": None, "redis_auth": None}
    if not raw:
        return info
    text = raw.decode("latin-1")
    first = text.split("\n", 1)[0].strip()

    if raw[0] == 0xFF and len(raw) > 1 and raw[1] in (0xFB, 0xFC, 0xFD, 0xFE):
        info["service"] = "telnet"
    elif m := re.match(r"SSH-([\d.]+)-(\S+)", first):
        info["service"] = "ssh"
        info["protocol"] = m.group(1)
        product, _, version = m.group(2).partition("_")
        info["product"], info["version"] = product, version
    elif first.startswith("HTTP/"):
        status, headers, body = parse_http(raw)
        if port_guess not in HTTP_SERVICES:
            info["service"] = "http"
        info["http"] = {"status": status, "headers": headers}
        server = headers.get("server", "")
        if server:
            info["product"], info["version"] = _split_product(server)
        if "You Know, for Search" in body or '"cluster_name"' in body:
            info["service"] = "elasticsearch"
        elif "docker" in server.lower() or '"ApiVersion"' in body:
            info["service"] = "docker"
    elif first.startswith(("+PONG", "-NOAUTH", "-DENIED", "-ERR")):
        info["service"] = "redis"
        info["redis_auth"] = not first.startswith("+PONG")
    elif first.startswith("RFB "):
        info["service"] = "vnc"
        info["version"] = first[4:]
    elif first.startswith("+OK"):
        info["service"] = "pop3"
        info["product"], info["version"] = _split_product(first[3:])
    elif first.startswith("* OK"):
        info["service"] = "imap"
    elif first.startswith("220"):
        if re.search(r"ftp", first, re.I):
            info["service"] = "ftp"
        elif re.search(r"smtp|mail", first, re.I):
            info["service"] = "smtp"
        for name in ("vsFTPd", "ProFTPD", "FileZilla Server", "Pure-FTPd",
                     "Postfix", "Exim", "Sendmail", "Microsoft FTP Service",
                     "Microsoft ESMTP"):
            if name.lower() in first.lower():
                info["product"] = name
                m = re.search(re.escape(name) + r"[ /]?v?(\d[\w.]*)", first, re.I)
                info["version"] = m.group(1) if m else ""
                break
    elif len(raw) > 5 and raw[4] == 0x0A and port_guess in ("mysql", "unknown"):
        info["service"] = "mysql"
        info["product"] = "MySQL/MariaDB"
        info["version"] = raw[5:].split(b"\0", 1)[0].decode("latin-1")
    elif b"MySQL" in raw or b"MariaDB" in raw:
        info["service"] = "mysql"
    elif raw[:2] in (b"\x15\x03", b"\x16\x03"):
        info["service"] = "tls"
    return info


def printable(raw: bytes, limit: int = 70) -> str:
    """First line of a banner with control characters removed."""
    if not raw:
        return ""
    sample = raw[:256]
    if sum(32 <= b < 127 or b in (9, 10, 13) for b in sample) < 0.8 * len(sample):
        return f"<binary response, {len(raw)} bytes>"
    text = raw.decode("latin-1").split("\n", 1)[0]
    text = "".join(c if 32 <= ord(c) < 127 else "" for c in text).strip()
    return text[:limit] + ("..." if len(text) > limit else "")
