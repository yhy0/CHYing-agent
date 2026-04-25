# PinchTab has SSRF with Full Response Exfiltration via Download Handler

**GHSA**: GHSA-rw8p-c6hf-q3pg | **CVE**: CVE-2026-30834 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-918

**Affected Packages**:
- **github.com/pinchtab/pinchtab/cmd/pinchtab** (go): <= 0.7.6

## Description

# SSRF with Full Response Exfiltration via Download Handler

### Summary
A Server-Side Request Forgery (SSRF) vulnerability in the `/download` endpoint allows any user with API access to induce the PinchTab server to make requests to arbitrary URLs, including internal network services and local system files, and exfiltrate the full response content.

### Details
The `GET /download?url=<url>` handler in [download.go](file:///Users/quan.m.le/Workspaces/pinchtab/internal/handlers/download.go#L78) accepts a user-controlled `url` parameter and passes it directly to `chromedp.Navigate(dlURL)` without any validation or sanitization.

```go
// internal/handlers/download.go:78
if err := chromedp.Run(ctx, chromedp.Navigate(dlURL)); err != nil {
    return fmt.Errorf("navigate to %s: %w", dlURL, err)
}
```

Since the request is performed by the headless Chrome browser instance managed by PinchTab, it can access:
1.  **Local Files**: Using the `file://` scheme (e.g., `file:///etc/passwd`).
2.  **Internal Services**: Accessing services bound to `localhost` or internal network IPs that are not reachable from the outside.
3.  **Cloud Metadata**: Accessing cloud provider metadata endpoints (e.g., `169.254.169.254`).

The server then returns the captured response body directly to the attacker, enabling full exfiltration of sensitive data.

### PoC
To reproduce the vulnerability, ensure the PinchTab server is running and accessible.

1.  **Local File Read**:
    Execute the following curl command to read `/etc/passwd`:
    ```bash
    curl -X GET "http://localhost:9867/download?url=file:///etc/passwd"
    ```

2.  **Internal Service Access**:
    If a service is running on `localhost:8080`, access it via:
    ```bash
    curl -X GET "http://localhost:9867/download?url=http://localhost:8080/internal-admin"
    ```

The response will contain the content of the targeted file or service.


PoC video:

https://github.com/user-attachments/assets/b15776ea-13cc-4534-ba7b-6d5c4e0ee74f

### Impact
This is a high-severity SSRF vulnerability. It impacts the confidentiality and security of the host system and the internal network where PinchTab is deployed. Attackers can exfiltrate sensitive system files, probe internal network infrastructure, and potentially gain access to internal management interfaces or cloud credentials. While PinchTab is often used in local environments, any deployment where the API is exposed (even with authentication) allows a compromised or malicious client to pivot into the internal network.
