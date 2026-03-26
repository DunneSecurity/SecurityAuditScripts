# Network

Network security auditors. These auditors check network-exposed services — no cloud credentials are required.

## Auditors

| Auditor | Script | What it checks |
|---|---|---|
| [ssl-tls-auditor](ssl-tls-auditor/) | `ssl_tls_auditor.py` | Cert expiry · Hostname match · Self-signed · Key algorithm · TLS version · Weak cipher · HSTS |
| [http-headers-auditor](http-headers-auditor/) | `http_headers_auditor.py` | X-Frame-Options · X-Content-Type-Options · Content-Security-Policy · Referrer-Policy · Permissions-Policy |
