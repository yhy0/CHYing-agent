# Keylime Missing Authentication for Critical Function and Improper Authentication

**GHSA**: GHSA-4jqp-9qjv-57m2 | **CVE**: CVE-2026-1709 | **Severity**: critical (CVSS 9.4)

**CWE**: CWE-295, CWE-306

**Affected Packages**:
- **keylime** (pip): >= 7.12.0, < 7.12.2
- **keylime** (pip): = 7.13.0

## Description

### Impact

The Keylime registrar does not enforce mutual TLS (mTLS) client certificate authentication since version 7.12.0. The registrar's TLS context is configured with `ssl.CERT_OPTIONAL` instead of `ssl.CERT_REQUIRED`, allowing any client to connect to protected API endpoints without presenting a valid client certificate.

**Who is impacted:**
  - All Keylime deployments running versions 7.12.0 through 7.13.0
  - Environments where the registrar HTTPS port (default 8891) is network-accessible to untrusted clients

**What an attacker can do:**
  - **List all registered agents** (`GET /v2/agents/`) - enumerate the entire agent inventory
  - **Retrieve agent details** (`GET /v2/agents/{uuid}`) - obtain public TPM keys, certificates, and network locations (IP/port) of any agent
  - **Delete any agent** (`DELETE /v2/agents/{uuid}`) - remove agents from the registry, disrupting attestation services

Note: The exposed TPM data (EK, AK, certificates) consists of public keys and certificates. Private keys remain protected within TPM hardware. The HMAC secret used for challenge-response validation is stored in the database but is not exposed via the API.

**Affected versions:** >= 7.12.0, <= 7.13.0

**Fixed versions:** 7.12.2, >= 7.13.1

### Patches

A patch for the affected released versions is available. It removes the line that override the configuration of `ssl.verify_mode`, leaving the `CERT_REQUIRED` value set by `web_util.init_mtls()`:

```diff
diff --git a/keylime/web/base/server.py b/keylime/web/base/server.py
index 1d9a9c2..859b23a 100644
--- a/keylime/web/base/server.py
+++ b/keylime/web/base/server.py
@@ -2,7 +2,6 @@ import asyncio
 import multiprocessing
 from abc import ABC, abstractmethod
 from functools import wraps
-from ssl import CERT_OPTIONAL
 from typing import TYPE_CHECKING, Any, Callable, Optional

 import tornado
@@ -252,7 +251,6 @@ class Server(ABC):
         self._https_port = config.getint(component, "tls_port", fallback=0)
         self._max_upload_size = config.getint(component, "max_upload_size", fallback=104857600)
         self._ssl_ctx = web_util.init_mtls(component)
-        self._ssl_ctx.verify_mode = CERT_OPTIONAL

     def _get(self, pattern: str, controller: type["Controller"], action: str, allow_insecure: bool = False) -> None:
         """Creates a new route to handle incoming GET requests issued for paths which match the given
```

Users should upgrade to the patched version once it is released.

### Workarounds

If upgrading is not immediately possible, apply one of the following mitigations:

#### 1. Network isolation (Recommended)

Restrict access to the registrar HTTPS port (default 8891) using firewall rules
to allow only trusted hosts (verifier, tenant):

##### Example using iptables
```
iptables -A INPUT -p tcp --dport 8891 -s <verifier_ip> -j ACCEPT
iptables -A INPUT -p tcp --dport 8891 -s <tenant_ip> -j ACCEPT
iptables -A INPUT -p tcp --dport 8891 -j DROP
```

#### 2. Reverse proxy with mTLS enforcement

Deploy a reverse proxy (nginx, HAProxy) in front of the registrar that enforces client certificate authentication:

##### Example nginx configuration
```
server {
    listen 8891 ssl;
    ssl_certificate /path/to/server.crt;
    ssl_certificate_key /path/to/server.key;
    ssl_client_certificate /path/to/ca.crt;
    ssl_verify_client on;  # Enforce client certificates

    location / {
        proxy_pass https://localhost:8892;  # Internal registrar port
    }
}
```
