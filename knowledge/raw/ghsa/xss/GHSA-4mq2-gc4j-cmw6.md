# Django Template Engine Vulnerable to XSS

**GHSA**: GHSA-4mq2-gc4j-cmw6 | **CVE**: CVE-2024-22199 | **Severity**: critical (CVSS 9.3)

**CWE**: CWE-20, CWE-79, CWE-116

**Affected Packages**:
- **github.com/gofiber/template/django/v3** (go): < 3.1.9

## Description

### Impact

**Vulnerability Type:** Cross-Site Scripting (XSS)  
**Affected Users:** All users of the Django template engine for Fiber prior to the patch. This vulnerability specifically impacts web applications that render user-supplied data through this template engine, potentially leading to the execution of malicious scripts in users' browsers when visiting affected web pages.

### Patches

The vulnerability has been addressed. The template engine now defaults to having autoescape set to `true`, effectively mitigating the risk of XSS attacks. Users are advised to upgrade to the latest version of the Django template engine for Fiber, where this security update is implemented. Ensure that the version of the template engine being used is the latest, post-patch version.

### Workarounds

For users unable to upgrade immediately to the patched version, a workaround involves manually implementing autoescaping within individual Django templates. This method includes adding specific tags in the template to control autoescape behavior:
```django
{% autoescape on %}
{{ "<script>alert('xss');</script>" }}
{% endautoescape %}
```

### References

- Official documentation of the Django template engine for Fiber: https://docs.gofiber.io/template/django/
- Django built-in template tags: https://docs.djangoproject.com/en/5.0/ref/templates/builtins/

