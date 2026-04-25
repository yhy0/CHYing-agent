# Pydantic AI has Server-Side Request Forgery (SSRF) in URL Download Handling

**GHSA**: GHSA-2jrp-274c-jhv3 | **CVE**: CVE-2026-25580 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-918

**Affected Packages**:
- **pydantic-ai** (pip): >= 0.0.26, < 1.56.0
- **pydantic-ai-slim** (pip): >= 0.0.26, < 1.56.0

## Description

## Summary

A Server-Side Request Forgery (SSRF) vulnerability exists in Pydantic AI's URL download functionality. When applications accept message history from untrusted sources, attackers can include malicious URLs that cause the server to make HTTP requests to internal network resources, potentially accessing internal services or cloud credentials.

**This vulnerability only affects applications that accept message history from external users**, such as those using:
- **`Agent.to_web`** or **`clai web`** to serve a chat interface
- **`VercelAIAdapter`** for Vercel AI SDK integration
- **`AGUIAdapter`** or **`Agent.to_ag_ui`** for AG-UI protocol integration
- Custom APIs that accept message history from user input

Applications that only use hardcoded or developer-controlled URLs are not affected.

### Description

The `download_item()` helper function downloads content from URLs without validating that the target is a public internet address. When user-supplied message history contains URLs, attackers can:

1. **Access internal services**: Request `http://127.0.0.1`, `localhost`, or private IP ranges (`10.x.x.x`, `172.16.x.x`, `192.168.x.x`)
2. **Steal cloud credentials**: Access cloud metadata endpoints (AWS IMDSv1 at `169.254.169.254`, GCP, Azure, Alibaba Cloud)
3. **Scan internal networks**: Enumerate internal hosts and ports

### Who Is Affected

You are affected if your application:

1. **Uses `Agent.to_web` or `clai web`** - The web interface accepts file attachments via the Vercel AI Data Stream Protocol, where users can provide arbitrary URLs through chat messages.

2. **Uses `VercelAIAdapter`** - Chat interfaces built with Vercel AI SDK allow users to submit messages containing URLs that are processed server-side.

3. **Uses `AGUIAdapter` or `Agent.to_ag_ui`** - The AG-UI protocol allows users to provide file references with URLs as part of agent interactions.

4. **Exposes a custom API accepting message history** - Any endpoint that accepts message history or `ImageUrl`, `AudioUrl`, `VideoUrl`, `DocumentUrl` objects from user input.

### Attack Scenario

Via chat interface, an attacker submits a message with a file attachment pointing to an internal resource:
```json
{
  "role": "user",
  "parts": [
    {"type": "file", "mediaType": "image/png", "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
  ]
}
```

### Affected Model Integrations

Multiple model integrations download URL content in certain conditions:

| Provider | Downloaded Types |
|----------|------------------|
| `OpenAIChatModel` | `AudioUrl`, `DocumentUrl` |
| `AnthropicModel` | `DocumentUrl` (`text/plain`) |
| `GoogleModel` (GLA) | All URL types (except YouTube and Files API URLs) |
| `XaiModel` | `DocumentUrl` |
| `BedrockConverseModel` | `ImageUrl`, `DocumentUrl`, `VideoUrl` (non-S3 URLs) |
| `OpenRouterModel` | `AudioUrl` |

## Remediation

### Upgrade to Patched Version

**Upgrade** to the patched version or later. The fix adds comprehensive SSRF protection:

- Blocks private/internal IP addresses by default
- Always blocks cloud metadata endpoints (even with `allow-local`)
- Only allows `http://` and `https://` protocols
- Resolves hostnames before requests to prevent DNS rebinding
- Validates each redirect target

### New `force_download='allow-local'` Option

If an application legitimately needs to access local/private network resources (e.g., in a fully trusted internal environment), it can explicitly opt in:

```python
from pydantic_ai import ImageUrl

# Default behavior: private IPs are blocked
ImageUrl(url="http://internal-service/image.png")  # Raises ValueError

# Opt-in to allow local access (use with caution)
ImageUrl(url="http://internal-service/image.png", force_download='allow-local')
```

**Important**: Cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`) are **always blocked**, even with `allow-local`.

### Workaround for Older Versions

If a project cannot upgrade immediately, use a [history processor](https://ai.pydantic.dev/message-history/#processing-message-history) to filter out URLs targeting local/private addresses:

```python
import ipaddress
import socket
from urllib.parse import urlparse

from pydantic_ai import Agent, ModelMessage, ModelRequest
from pydantic_ai.messages import AudioUrl, DocumentUrl, ImageUrl, VideoUrl

def is_private_url(url: str) -> bool:
    """Check if a URL targets a private/internal IP address."""
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
        if not hostname:
            return True  # Invalid URL, block it

        # Resolve hostname to IP
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)

        # Block private, loopback, and link-local addresses
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except (socket.gaierror, ValueError):
        return True  # DNS resolution failed, block it

def filter_private_urls(messages: list[ModelMessage]) -> list[ModelMessage]:
    """Remove URL parts that target private/internal addresses."""
    url_types = (ImageUrl, AudioUrl, VideoUrl, DocumentUrl)
    filtered = []
    for msg in messages:
        if isinstance(msg, ModelRequest):
            safe_parts = [
                part for part in msg.parts
                if not (isinstance(part, url_types) and is_private_url(part.url))
            ]
            if safe_parts:
                filtered.append(ModelRequest(parts=safe_parts))
        else:
            filtered.append(msg)
    return filtered

# Apply the filter to your agent
agent = Agent('openai:gpt-5', history_processors=[filter_private_urls])
```

## Technical Details of the Fix

The fix introduces a new `_ssrf.py` module with comprehensive protection:

1. **Protocol validation**: Only `http://` and `https://` allowed
2. **DNS resolution before request**: Prevents DNS rebinding attacks
3. **Private IP blocking** (by default):
   - `127.0.0.0/8`, `::1/128` (loopback)
   - `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` (private)
   - `169.254.0.0/16`, `fe80::/10` (link-local)
   - `100.64.0.0/10` (CGNAT)
   - `fc00::/7` (unique local)
   - `2002::/16` (6to4, can embed private IPv4)
4. **Cloud metadata always blocked**: `169.254.169.254`, `fd00:ec2::254`, `100.100.100.200`
5. **Safe redirect handling**: Each redirect validated before following (max 10)
