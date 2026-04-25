# Cross-site Scripting in Apache superset

**GHSA**: GHSA-rwhh-6x83-84v6 | **CVE**: CVE-2023-49657 | **Severity**: critical (CVSS 9.6)

**CWE**: CWE-79

**Affected Packages**:
- **apache-superset** (pip): < 3.0.3

## Description

A stored cross-site scripting (XSS) vulnerability exists in Apache Superset before 3.0.3. An authenticated attacker with create/update permissions on charts or dashboards could store a script or add a specific HTML snippet that would act as a stored XSS.

For 2.X versions, users should change their config to include:

TALISMAN_CONFIG = {
    "content_security_policy": {
        "base-uri": ["'self'"],
        "default-src": ["'self'"],
        "img-src": ["'self'", "blob:", "data:"],
        "worker-src": ["'self'", "blob:"],
        "connect-src": [
            "'self'",
            " https://api.mapbox.com" https://api.mapbox.com" ;,
            " https://events.mapbox.com" https://events.mapbox.com" ;,
        ],
        "object-src": "'none'",
        "style-src": [
            "'self'",
            "'unsafe-inline'",
        ],
        "script-src": ["'self'", "'strict-dynamic'"],
    },
    "content_security_policy_nonce_in": ["script-src"],
    "force_https": False,
    "session_cookie_secure": False,
}
