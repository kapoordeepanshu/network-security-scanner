"""Target parsing, TCP connect scanning and service detection."""

from __future__ import annotations

import errno
import ipaddress
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from . import services

OPEN, CLOSED, FILTERED = "open", "closed", "filtered"
_REFUSED = {errno.ECONNREFUSED, 10061}  # 10061 = WSAECONNREFUSED on Windows
DISCOVERY_PORTS = [22, 80, 135, 443, 445, 3389]


@dataclass
class Target:
    address: str
    hostname: str = ""

    @property
    def family(self) -> int:
        return socket.AF_INET6 if ":" in self.address else socket.AF_INET


@dataclass
class PortResult:
    port: int
    service: str
    product: str = ""
    version: str = ""
    banner: str = ""
    tls: dict | None = None
    http: dict | None = None
    redis_auth: bool | None = None
    ssh_protocol: str = ""
    cpes: list[str] = field(default_factory=list)
    cves: list[dict] = field(default_factory=list)


@dataclass
class HostResult:
    target: Target
    up: bool = False
    ports: list[PortResult] = field(default_factory=list)
    findings: list = field(default_factory=list)


# --------------------------------------------------------------------------
# Input parsing
# --------------------------------------------------------------------------

def parse_ports(spec: str) -> list[int]:
    """'top' | 'all' | '22,80,8000-8100' -> sorted unique port list."""
    spec = spec.strip().lower()
    if spec in ("top", "default", "common"):
        return list(services.DEFAULT_PORTS)
    if spec == "all":
        return list(range(1, 65536))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError(f"invalid port specification: {spec!r}")
    return sorted(ports)


def parse_targets(spec: str, max_hosts: int = 1024) -> list[Target]:
    """Accept IPs, hostnames, CIDR blocks and last-octet ranges, comma separated.

    Examples: 192.168.1.10, scanme.example.com, 10.0.0.0/24, 192.168.1.1-50
    """
    targets: list[Target] = []
    for part in (p.strip() for p in spec.split(",")):
        if not part:
            continue
        if "/" in part:
            net = ipaddress.ip_network(part, strict=False)
            hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
            if len(hosts) > max_hosts:
                raise ValueError(f"{part} has {len(hosts)} hosts; raise --max-hosts to allow")
            targets += [Target(str(h)) for h in hosts]
        elif _is_octet_range(part):
            base, last = part.rsplit(".", 1)
            lo, hi = (int(x) for x in last.split("-"))
            targets += [Target(f"{base}.{i}") for i in range(lo, hi + 1)]
        else:
            try:
                targets.append(Target(str(ipaddress.ip_address(part))))
            except ValueError:
                targets.append(Target(_resolve(part), hostname=part))
        if len(targets) > max_hosts:
            raise ValueError(f"more than {max_hosts} hosts; raise --max-hosts to allow")
    if not targets:
        raise ValueError("no targets given")
    unique = {(t.address, t.hostname): t for t in targets}
    return list(unique.values())


def _is_octet_range(part: str) -> bool:
    if part.count(".") != 3 or "-" not in part:
        return False
    base, last = part.rsplit(".", 1)
    try:
        ipaddress.IPv4Address(base + ".0")
        lo, hi = (int(x) for x in last.split("-"))
    except ValueError:
        return False
    return 0 <= lo <= hi <= 255


def _resolve(hostname: str) -> str:
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve {hostname!r}: {exc}") from None
    infos.sort(key=lambda i: i[0] != socket.AF_INET)  # prefer IPv4
    return infos[0][4][0]


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------

def tcp_probe(target: Target, port: int, timeout: float) -> str:
    """Full TCP connect to one port; returns OPEN, CLOSED or FILTERED."""
    with socket.socket(target.family, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        try:
            code = sock.connect_ex((target.address, port))
        except OSError:
            return FILTERED
    if code == 0:
        return OPEN
    return CLOSED if code in _REFUSED else FILTERED


def is_host_up(target: Target, timeout: float) -> bool:
    """A host is up if any discovery port answers (open *or* refused)."""
    return any(tcp_probe(target, p, timeout) != FILTERED for p in DISCOVERY_PORTS)


def _recv_all(sock: socket.socket, timeout: float, limit: int = 8192) -> bytes:
    data = b""
    sock.settimeout(timeout)
    try:
        while len(data) < limit:
            chunk = sock.recv(limit - len(data))
            if not chunk:
                break
            data += chunk
            sock.settimeout(0.3)  # after the first chunk, only wait briefly
    except (socket.timeout, OSError):
        pass
    return data


def _exchange(sock: socket.socket, service: str, host: str, timeout: float) -> bytes:
    """Read a greeting banner; if there is none, send a probe and read again."""
    data = _recv_all(sock, timeout)
    if not data:
        payload = services.probe_for(service, host)
        if payload:
            try:
                sock.sendall(payload)
                data = _recv_all(sock, timeout)
            except OSError:
                pass
    return data


def _tls_details(target: Target, port: int, timeout: float) -> dict:
    """Check certificate validity, negotiated protocol and legacy TLS support."""
    sni = target.hostname or None
    info: dict = {"verified": None}

    verified_ctx = ssl.create_default_context()
    verified_ctx.check_hostname = False
    try:
        with socket.create_connection((target.address, port), timeout) as raw, \
                verified_ctx.wrap_socket(raw, server_hostname=sni) as tls:
            info["verified"] = True
            cert = tls.getpeercert() or {}
            info["not_after"] = cert.get("notAfter", "")
            info["subject"] = _rdn(cert.get("subject", ()))
            info["issuer"] = _rdn(cert.get("issuer", ()))
    except ssl.SSLCertVerificationError as exc:
        info["verified"] = False
        info["verify_code"] = exc.verify_code
        info["verify_message"] = exc.verify_message
    except (ssl.SSLError, OSError) as exc:
        info["error"] = str(exc)

    # Can the server still be talked into TLS 1.0/1.1?
    legacy_ctx = _permissive_context()
    try:
        legacy_ctx.maximum_version = ssl.TLSVersion.TLSv1_1
        with socket.create_connection((target.address, port), timeout) as raw, \
                legacy_ctx.wrap_socket(raw, server_hostname=sni) as tls:
            info["legacy_protocol"] = tls.version()
    except (ValueError, ssl.SSLError, OSError):
        pass  # rejected, or the local OpenSSL can't speak it either
    return info


def _permissive_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        pass
    return ctx


def _rdn(rdns) -> str:
    return ", ".join(f"{k}={v}" for rdn in rdns for k, v in rdn)


def detect_service(target: Target, port: int, timeout: float) -> PortResult:
    """Grab a banner (over TLS where appropriate) and fingerprint the service."""
    guess = services.guess_by_port(port)
    result = PortResult(port=port, service=guess)
    host = target.hostname or target.address
    use_tls = port in services.TLS_PORTS
    raw = b""

    if not use_tls:
        try:
            with socket.create_connection((target.address, port), timeout) as sock:
                raw = _exchange(sock, guess, host, timeout)
        except OSError:
            pass
        if raw[:2] in (b"\x15\x03", b"\x16\x03"):  # plaintext probe hit a TLS port
            use_tls, raw = True, b""

    if use_tls:
        result.tls = _tls_details(target, port, timeout)
        try:
            with socket.create_connection((target.address, port), timeout) as sock, \
                    _permissive_context().wrap_socket(
                        sock, server_hostname=target.hostname or None) as tls:
                result.tls["protocol"] = tls.version()
                result.tls["cipher"] = (tls.cipher() or ("",))[0]
                raw = _exchange(tls, guess, host, timeout)
        except (ssl.SSLError, OSError) as exc:
            result.tls.setdefault("error", str(exc))

    info = services.fingerprint(raw, guess)
    result.service = info["service"]
    if use_tls and result.service in ("http", "unknown"):
        result.service = "https"
    result.product, result.version = info["product"], info["version"]
    result.http, result.redis_auth = info["http"], info["redis_auth"]
    result.ssh_protocol = info.get("protocol", "")
    result.banner = services.printable(raw)
    return result


def scan(targets: list[Target], ports: list[int], timeout: float = 1.0,
         workers: int = 200, discover: bool = True, detect: bool = True,
         progress=None) -> list[HostResult]:
    """Scan every target and return one HostResult per target."""
    results = {id(t): HostResult(t) for t in targets}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        live = targets
        if discover and len(targets) > 1:
            up = list(pool.map(lambda t: is_host_up(t, max(timeout, 1.5)), targets))
            live = [t for t, alive in zip(targets, up) if alive]
        for t in live:
            results[id(t)].up = True

        jobs = [(t, p) for t in live for p in ports]
        states = pool.map(lambda job: tcp_probe(job[0], job[1], timeout), jobs)
        open_jobs = []
        for i, ((t, p), state) in enumerate(zip(jobs, states), 1):
            if state == OPEN:
                open_jobs.append((t, p))
            if progress and (i % 250 == 0 or i == len(jobs)):
                progress(i, len(jobs))

        if detect:
            found = pool.map(lambda job: detect_service(job[0], job[1], max(timeout * 2, 3.0)), open_jobs)
        else:
            found = (PortResult(p, services.guess_by_port(p)) for _, p in open_jobs)
        for (t, _), port_result in zip(open_jobs, found):
            results[id(t)].ports.append(port_result)

    return list(results.values())
