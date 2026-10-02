"""Known-vulnerability enrichment: NVD CVEs + CISA KEV + FIRST EPSS.

For every detected product/version we build a CPE string, ask the NVD which
CVEs affect it, then prioritise them using:

* CISA KEV  - is the CVE *known to be exploited in the wild*?
* EPSS      - probability of exploitation in the next 30 days (0..1)
* CVSS      - technical severity

Responses are cached on disk (default 24h) so repeated scans are fast and
stay within the NVD rate limit (5 requests / 30s without an API key).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import __version__
from .scanner import HostResult, PortResult

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
USER_AGENT = f"netscanner/{__version__}"

# (regex matched against "product version", CPE vendor, CPE product)
CPE_MAP = [
    (r"OpenSSH", "openbsd", "openssh"),
    (r"Dropbear", "dropbear_ssh_project", "dropbear_ssh"),
    (r"^Apache(?!-Coyote)", "apache", "http_server"),
    (r"Apache-Coyote|Tomcat", "apache", "tomcat"),
    (r"nginx", "f5", "nginx"),
    (r"lighttpd", "lighttpd", "lighttpd"),
    (r"Microsoft-IIS", "microsoft", "internet_information_services"),
    (r"vsFTPd", "vsftpd_project", "vsftpd"),
    (r"ProFTPD", "proftpd", "proftpd"),
    (r"Pure-FTPd", "pureftpd", "pure-ftpd"),
    (r"FileZilla Server", "filezilla-project", "filezilla_server"),
    (r"Exim", "exim", "exim"),
    (r"Postfix", "postfix", "postfix"),
    (r"MariaDB", "mariadb", "mariadb"),
    (r"MySQL", "oracle", "mysql"),
    (r"^PHP", "php", "php"),
]


def _clean_version(version: str) -> str:
    """'8.9p1' -> '8.9', '2.4.7 (Ubuntu)' -> '2.4.7'. NVD ranges match plain versions best."""
    m = re.match(r"\d+(?:\.\d+)*", version)
    return m.group(0) if m else ""


def products_for(port: PortResult) -> list[tuple[str, str]]:
    """(name, version) pairs worth looking up for one open port."""
    found = []
    if port.product and port.version:
        product, version = port.product, port.version
        if "MariaDB" in version:  # MariaDB reports e.g. '5.5.5-10.4.28-MariaDB'
            product = "MariaDB"
            version = version.split("-")[1] if version.count("-") >= 2 else version
        found.append((product, version))
    powered = (port.http or {}).get("headers", {}).get("x-powered-by", "")
    if m := re.match(r"(PHP)/([\d.]+)", powered):
        found.append((m.group(1), m.group(2)))
    return found


def cpe_for(product: str, version: str) -> str | None:
    version = _clean_version(version)
    if not version:
        return None
    for pattern, vendor, name in CPE_MAP:
        if re.search(pattern, product, re.I):
            return f"cpe:2.3:a:{vendor}:{name}:{version}"
    return None


class VulnDB:
    def __init__(self, api_key: str | None = None, cache_dir: str | None = None,
                 cache_hours: float = 24, log=lambda msg: None):
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        self.cache_dir = Path(cache_dir or os.environ.get("NETSCANNER_CACHE")
                              or Path.home() / ".cache" / "netscanner")
        self.cache_seconds = cache_hours * 3600
        self.log = log
        self._last_nvd_call = 0.0
        self._kev: dict | None = None

    # -- HTTP + cache -----------------------------------------------------

    def _cached(self, key: str, fetch):
        path = self.cache_dir / (hashlib.sha256(key.encode()).hexdigest()[:32] + ".json")
        if path.exists() and time.time() - path.stat().st_mtime < self.cache_seconds:
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                pass
        data = fetch()
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(data), encoding="utf-8")
        except OSError:
            pass
        return data

    def _get(self, url: str, headers: dict | None = None, retries: int = 3) -> dict:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
        for attempt in range(retries):
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return json.load(resp)
            except urllib.error.HTTPError as exc:
                if exc.code in (403, 429, 503) and attempt < retries - 1:
                    time.sleep(10 * (attempt + 1))  # NVD rate limiting
                    continue
                raise
        raise RuntimeError("unreachable")

    def _nvd_throttle(self) -> None:
        gap = 0.7 if self.api_key else 6.5  # 50 vs 5 requests per 30s
        wait = self._last_nvd_call + gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last_nvd_call = time.monotonic()

    # -- data sources -----------------------------------------------------

    def cves_for_cpe(self, cpe: str) -> list[dict]:
        def fetch():
            cves, start = [], 0
            while True:
                self._nvd_throttle()
                query = urllib.parse.urlencode({"virtualMatchString": cpe,
                                                "resultsPerPage": 2000, "startIndex": start})
                headers = {"apiKey": self.api_key} if self.api_key else {}
                data = self._get(f"{NVD_URL}?{query}", headers)
                cves += [_summarize_cve(v["cve"]) for v in data.get("vulnerabilities", [])]
                start += data.get("resultsPerPage", 0)
                if start >= data.get("totalResults", 0) or not data.get("resultsPerPage"):
                    return cves
        self.log(f"[*] Looking up CVEs for {cpe}")
        return self._cached("nvd:" + cpe, fetch)

    def kev(self) -> dict[str, dict]:
        if self._kev is None:
            data = self._cached("kev", lambda: self._get(KEV_URL))
            self._kev = {v["cveID"]: v for v in data.get("vulnerabilities", [])}
        return self._kev

    def epss(self, cve_ids: list[str]) -> dict[str, float]:
        scores: dict[str, float] = {}
        ids = sorted(set(cve_ids))
        for i in range(0, len(ids), 100):
            batch = ids[i:i + 100]
            data = self._cached("epss:" + ",".join(batch),
                                lambda: self._get(f"{EPSS_URL}?cve={','.join(batch)}"))
            scores.update({row["cve"]: float(row["epss"]) for row in data.get("data", [])})
        return scores


def _summarize_cve(cve: dict) -> dict:
    metrics = cve.get("metrics", {})
    score, severity = None, ""
    for key in ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2"):
        entries = sorted(metrics.get(key, []), key=lambda m: m.get("type") != "Primary")
        if entries:
            data = entries[0]["cvssData"]
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity", "")
            break
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {"id": cve["id"], "cvss": score, "severity": severity.upper(),
            "summary": description[:300]}


def enrich(hosts: list[HostResult], db: VulnDB) -> None:
    """Attach prioritised CVE lists to every port with an identifiable version."""
    lookups: dict[str, list[dict]] = {}
    targets: list[tuple[PortResult, str]] = []
    for host in hosts:
        for port in host.ports:
            for product, version in products_for(port):
                cpe = cpe_for(product, version)
                if cpe:
                    targets.append((port, cpe))
                    lookups.setdefault(cpe, [])
    if not targets:
        return

    for cpe in lookups:
        try:
            lookups[cpe] = db.cves_for_cpe(cpe)
        except Exception as exc:  # network errors must never kill the scan
            db.log(f"[!] CVE lookup failed for {cpe}: {exc}")

    all_ids = [c["id"] for cves in lookups.values() for c in cves]
    try:
        kev = db.kev()
    except Exception as exc:
        db.log(f"[!] Could not load CISA KEV catalog: {exc}")
        kev = {}
    try:
        epss = db.epss(all_ids) if all_ids else {}
    except Exception as exc:
        db.log(f"[!] Could not load EPSS scores: {exc}")
        epss = {}

    for port, cpe in targets:
        port.cpes.append(cpe)
        for cve in lookups[cpe]:
            entry = dict(cve)
            entry["summary"] = " ".join(cve.get("summary", "").split())  # NVD text has stray newlines
            entry["kev"] = cve["id"] in kev
            entry["ransomware"] = kev.get(cve["id"], {}).get("knownRansomwareCampaignUse") == "Known"
            entry["epss"] = epss.get(cve["id"])
            port.cves.append(entry)
        port.cves.sort(key=priority, reverse=True)


def priority(cve: dict) -> tuple:
    """Exploited-in-the-wild first, then likelihood of exploitation, then severity."""
    return (cve.get("kev", False), cve.get("epss") or 0.0, cve.get("cvss") or 0.0)
