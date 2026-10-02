# Changelog

## 1.0.0 (2026-10-02)

First public release.

- Multithreaded TCP connect scanner: IPs, hostnames, CIDR blocks, ranges and `-iL` target files
- Service fingerprinting from banners and protocol probes, TLS-aware
- Risk rules: exposed services, unauthenticated Redis, outdated software, TLS/certificate issues, HTTP security headers
- `--cve`: NVD CVE lookup prioritised by CISA KEV and FIRST EPSS, with an on-disk cache
- `--baseline`: compare scans to detect new hosts, ports and findings
- Reports: colored console, JSON and self-contained HTML
- CI exit codes: `--fail-on` and `--fail-on-change`
