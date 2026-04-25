# Browser Use allows bypassing `allowed_domains` by putting a decoy domain in http auth username portion of a URL

**GHSA**: GHSA-x39x-9qw5-ghrf | **CVE**: CVE-2025-47241 | **Severity**: critical (CVSS 9.3)

**CWE**: CWE-647

**Affected Packages**:
- **browser-use** (pip): <= 0.1.44

## Description

### Summary  
During a manual source code review, [**ARIMLABS.AI**](https://arimlabs.ai) researchers identified that the `browser_use` module includes an embedded whitelist functionality to restrict URLs that can be visited. This restriction is enforced during agent initialization. However, it was discovered that these measures can be bypassed, leading to severe security implications.  

### Details  
**File:** `browser_use/browser/context.py`  

The `BrowserContextConfig` class defines an `allowed_domains` list, which is intended to limit accessible domains. This list is checked in the `_is_url_allowed()` method before navigation:

```python
@dataclass
class BrowserContextConfig:
    """
    [STRIPPED]
    """
    cookies_file: str | None = None
    minimum_wait_page_load_time: float = 0.5
    wait_for_network_idle_page_load_time: float = 1
    maximum_wait_page_load_time: float = 5
    wait_between_actions: float = 1

    disable_security: bool = True

    browser_window_size: BrowserContextWindowSize = field(default_factory=lambda: {'width': 1280, 'height': 1100})
    no_viewport: Optional[bool] = None

    save_recording_path: str | None = None
    save_downloads_path: str | None = None
    trace_path: str | None = None
    locale: str | None = None
    user_agent: str = (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.102 Safari/537.36'
    )

    highlight_elements: bool = True
    viewport_expansion: int = 500
    allowed_domains: list[str] | None = None
    include_dynamic_attributes: bool = True

    _force_keep_context_alive: bool = False
```
The _is_url_allowed() method is responsible for checking whether a given URL is permitted:
```python
def _is_url_allowed(self, url: str) -> bool:
    """Check if a URL is allowed based on the whitelist configuration."""
    if not self.config.allowed_domains:
        return True

    try:
        from urllib.parse import urlparse

        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()

        # Remove port number if present
        if ':' in domain:
            domain = domain.split(':')[0]

        # Check if domain matches any allowed domain pattern
        return any(
            domain == allowed_domain.lower() or domain.endswith('.' + allowed_domain.lower())
            for allowed_domain in self.config.allowed_domains
        )
    except Exception as e:
        logger.error(f'Error checking URL allowlist: {str(e)}')
        return False
```
The core issue stems from the line `domain = domain.split(':')[0]`, which allows an attacker to manipulate basic authentication credentials by providing a username:password pair. By replacing the username with a whitelisted domain, the check can be bypassed, even though the actual domain remains different.
### Proof of Concept (PoC)

Set allowed_domains to ['example.com'] and use the following URL:

https://example.com:pass@localhost:8080

This allows bypassing all whitelist controls and accessing restricted internal services.
### Impact

- Affected all users relying on this functionality for security.
- Potential for unauthorized enumeration of localhost services and internal networks.
- Ability to bypass domain whitelisting, leading to unauthorized browsing.
