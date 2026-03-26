# SSL/TLS Certificate Auditor

Audits a domain's SSL/TLS certificate and TLS configuration. No credentials required — uses outbound TCP on port 443 only.

## Checks

| ID | Name | Condition | Severity |
|---|---|---|---|
| TLS-00 | Connectivity | Could not connect | CRITICAL |
| TLS-01 | Certificate Expiry | Expired or < 14 days | CRITICAL |
| TLS-01 | Certificate Expiry | < 30 days | HIGH |
| TLS-02 | Hostname Match | Domain not in SAN/CN | CRITICAL |
| TLS-03 | Self-Signed | Issuer == Subject | HIGH |
| TLS-04 | Key Algorithm | DSA or unknown key | HIGH |
| TLS-05 | TLS Version | Below TLS 1.2 | HIGH |
| TLS-06 | Weak Cipher | RC4/DES/3DES/NULL/EXPORT/ANON | HIGH |
| TLS-07 | HSTS Header | Absent or max-age < 1 year | MEDIUM |

## Usage

### Standalone

```bash
python3 ssl_tls_auditor.py --domain acme.ie
python3 ssl_tls_auditor.py --domain acme.ie --port 8443
python3 ssl_tls_auditor.py --domain acme.ie --format all --output ssl_report
```

### Via orchestrator

```bash
python3 audit.py --client "Acme Corp" --ssl --domain acme.ie
python3 audit.py --client "Acme Corp" --email --ssl --domain acme.ie
```

## Requirements

- Python 3.8+
- No external dependencies (stdlib only: `ssl`, `socket`, `datetime`, `csv`, `json`)
- Outbound TCP access to port 443 on the target domain

## Limitations

- **TLS version check** reports the *negotiated* version only (the version agreed for this connection). It cannot enumerate all TLS versions the server supports. Use `testssl.sh` for full protocol range testing.
- **Key size** (RSA bits) is not checked — Python's stdlib `ssl` module does not expose key size without the `cryptography` library.
- **HSTS check** reads the HTTP response header from the initial GET request. If the server issues a redirect before setting HSTS, the header may not appear.

## Tests

```bash
cd Network/ssl-tls-auditor
python -m pytest tests/ -v
```
