# WeKnora has DNS Rebinding Vulnerability in web_fetch Tool that Allows SSRF to Internal Resources

**GHSA**: GHSA-h6gw-8f77-mmmp | **CVE**: CVE-2026-30858 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-918

**Affected Packages**:
- **github.com/Tencent/WeKnora** (go): <= 0.2.14

## Description

### Summary

A DNS rebinding vulnerability in the `web_fetch` tool allows an unauthenticated attacker to bypass URL validation and access internal resources on the server, including private IP addresses (e.g., 127.0.0.1, 192.168.x.x). By crafting a malicious domain that resolves to a public IP during validation and subsequently resolves to a private IP during execution, an attacker can access sensitive local services and potentially exfiltrate data.

### Details

The vulnerability exists because the `web_fetch` tool lacks complete DNS pinning. The application performs URL validation only once via `validateParams()`, but the URL is then passed unchanged to the `fetchHTMLContent()` function, which eventually reaches `fetchWithChromedp()`. The headless browser (Chromedp) resolves the hostname independently without DNS pinning, allowing a time-of-check-time-of-use (TOCTOU) attack.

**Validation phase (first DNS resolution):**
```go
if err := t.validateParams(p); err != nil {
    // Returns error for private IPs
    results[index] = &webFetchItemResult{
        err: err,
        // ...
    }
    return
}
```

**Execution phase (second DNS resolution):**
The original URL (not the resolved IP) is passed through the execution chain:
```go
output, data, err := t.executeFetch(ctx, p)
// Calls fetchHTMLContent(ctx, targetURL) where targetURL is the original hostname
```

**Chromedp execution (vulnerable DNS resolution):**
```go
func (t *WebFetchTool) fetchWithChromedp(ctx context.Context, targetURL string) (string, error) {
    // targetURL is not DNS-pinned; browser resolves it independently
    err := chromedp.Run(ctx,
        chromedp.Navigate(targetURL),  // Third DNS lookup occurs here
        chromedp.WaitReady("body", chromedp.ByQuery),
        chromedp.OuterHTML("html", &html),
    )
}
```

The attacker controls a domain that can be configured to return different DNS responses to different queries, enabling them to bypass the initial private IP check and access restricted resources during the actual fetch.

### PoC

**Setup:**
1. Deploy the DNS rebinding server (attached Python file) with the following systemd configuration:

```systemd
[Unit]
Description=DNS Rebinding Test Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/Repos/dns-rebinding-server
ExecStart=/root/.proto/shims/python -u /root/Repos/dns-rebinding-server/server.py --token aleister1102 --domain aleister.ninja --port 53 --global-tracking --ip1 1.1.1.1 --ip2 0.0.0.0 --first-response-count 1 --reset-time 0
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
 ```
 
 This configures the DNS server to:
 - Return `1.1.1.1` (a public IP) for the first DNS query
 - Return `127.0.0.1` (localhost) for all subsequent queries
 - TTL is set to 0 to prevent caching
 
 The sequence can also be reset via reset.domain.com (reset to 1.1.1.1).
 
 > Note: We may need to reset the sequence as the TOCTOU attack is not truly reliable and needs to be triggered multiple times.

2. Set up a simple HTTP server on the localhost of the backend service:

 ```bash
 python -m http.server 8888
 ```

3. Configure the malicious domain to point to the DNS rebinding server

**Execution:**
1. Enable web search on an agent.
2. Prompt the agent to fetch content from the attacker-controlled domain (e.g., `http://attacker.example.com`)
3. The sequence of events:
   - **First DNS query** (validation phase): `attacker.example.com` → `1.1.1.1` ✓ Passes validation
   - **Second DNS query** (execution phase): `attacker.example.com` → `127.0.0.1` ✗ Bypass achieved
   - The `web_fetch` tool successfully connects to `127.0.0.1:8080` and returns the local server's content

**Result:**
The attacker gains access to the local HTTP server and can read its content, demonstrating that internal resources are now accessible through the rebinding attack.

<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/897e8494-f39e-49ce-a02a-5832bb84a73f" />

PoC video:

https://github.com/user-attachments/assets/68daaa87-4b9b-4b6e-b6f6-ee123f5fcda9

### Impact
**Vulnerability Type:** DNS Rebinding / Server-Side Request Forgery (SSRF)

**Who is impacted:**
- Any user or agent with web search capability can exploit this vulnerability
- The vulnerability grants access to internal services, configuration files, metadata services, and other sensitive resources normally restricted to the internal network
- In cloud environments, this could allow access to metadata endpoints (e.g., AWS IMDSv1) to obtain credentials and secrets\
