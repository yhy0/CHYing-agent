# SiYuan: Unauthenticated Reflected XSS via SVG Injection in /api/icon/getDynamicIcon Endpoint

**GHSA**: GHSA-6865-qjcf-286f | **CVE**: CVE-2026-29183 | **Severity**: critical (CVSS 9.3)

**CWE**: CWE-79

**Affected Packages**:
- **github.com/siyuan-note/siyuan/kernel** (go): < 0.0.0-20260304034809-d68bd5a79391

## Description

### Summary
An unauthenticated reflected XSS vulnerability exists in the dynamic icon API endpoint:

- `GET /api/icon/getDynamicIcon`

When `type=8`, attacker-controlled `content` is embedded into SVG output without escaping. Because the endpoint is unauthenticated and returns `image/svg+xml`, a crafted URL can inject executable SVG/HTML event handlers (for example `onerror`) and run JavaScript in the SiYuan web origin.

This can be chained to perform authenticated API actions and exfiltrate sensitive data when a logged-in user opens the malicious link.

### Details
The issue is caused by unsafe output construction and incomplete sanitization:

1. **Endpoint is exposed without auth middleware**
   - Source: https://github.com/siyuan-note/siyuan/blob/master/kernel/api/router.go#L27-L37
   - `GET /api/icon/getDynamicIcon` is registered in the unauthenticated section.

2. **User input is inserted into SVG via string formatting**
   - Source: https://github.com/siyuan-note/siyuan/blob/master/kernel/api/icon.go#L115-L175
   - Source: https://github.com/siyuan-note/siyuan/blob/master/kernel/api/icon.go#L537-L585
   - In `generateTypeEightSVG`, `%s` directly injects `content` into `<text>...</text>` without XML/HTML escaping.

3. **Sanitizer only removes `<script>` tags**
   - Source: https://github.com/siyuan-note/siyuan/blob/master/kernel/util/misc.go#L235-L281
   - `RemoveScriptsInSVG` removes `<script>` nodes, but does not remove dangerous attributes (`onerror`, `onload`, etc.) or unsafe elements.

As a result, payloads such as `</text><image ... onerror=...><text>` survive and execute.

### PoC

#### Minimal browser execution PoC
Open this URL in a browser:

```http
GET /api/icon/getDynamicIcon?type=8&content=%3C%2Ftext%3E%3Cimage%20href%3Dx%20onerror%3Dalert(document.domain)%3E%3C%2Fimage%3E%3Ctext%3E
```

Example full URL:

```text
http://127.0.0.1:6806/api/icon/getDynamicIcon?type=8&content=%3C%2Ftext%3E%3Cimage%20href%3Dx%20onerror%3Dalert(document.domain)%3E%3C%2Fimage%3E%3Ctext%3E
```

Expected result:

- JavaScript executes (`alert(document.domain)`), confirming reflected XSS.

#### Authenticated impact demonstration
If a victim is authenticated in the same browser session, JavaScript running in origin can call privileged APIs and exfiltrate returned data.

### Impact
This is a reflected XSS in an unauthenticated endpoint, with realistic account/data compromise impact:

- Arbitrary JavaScript execution in SiYuan web origin.
- Authenticated action abuse via same-origin API calls.
- Sensitive data exposure (notes/config/API responses) from victim context.
- Potential chained server-impact actions depending on victim privileges and deployment mode.
