# Contributing

Thanks for helping improve netscanner!

## Ground rules

- **No runtime dependencies.** netscanner must keep working with only the Python standard library (3.9+).
- **Safe by default.** Checks must be non-destructive: no exploitation, no brute-forcing, no payloads that could crash a service. Anything more intrusive must be opt-in behind a flag.
- **Tests stay offline.** Fake network services and external APIs (see `tests/`) instead of calling real hosts.

## Development

```bash
git clone https://github.com/kapoordeepanshu/network-security-scanner.git
cd network-security-scanner
python -m unittest discover tests -v
python -m netscanner 127.0.0.1
```

## Good first contributions

| You want to... | Edit |
|---|---|
| Recognise a new service from its banner | `services.py` → `fingerprint()` |
| Map a product to its NVD CPE name | `vulns.py` → `CPE_MAP` (look up the vendor/product at https://nvd.nist.gov/products/cpe/search) |
| Flag a risky service | `risks.py` → `RISKY_SERVICES` |
| Flag an outdated version | `risks.py` → `OUTDATED_SOFTWARE` |

Please add a test for every new rule or fingerprint.

## Pull requests

1. Fork the repository and create a feature branch.
2. Keep changes focused and match the existing style.
3. Make sure `python -m unittest discover tests` passes.
4. Describe what the change detects and how you verified it. A sanitized banner sample is ideal.
