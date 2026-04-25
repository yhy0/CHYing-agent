# OpenRefine has a reflected cross-site scripting vulnerability (XSS) in GData extension (authorized.vt)

**GHSA**: GHSA-pw3x-c5vp-mfc3 | **CVE**: CVE-2024-47878 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-79

**Affected Packages**:
- **org.openrefine:extensions** (maven): < 3.8.3

## Description

### Summary

The `/extension/gdata/authorized` endpoint includes the `state` GET parameter verbatim in a `<script>` tag in the output, so without escaping.

An attacker could lead or redirect a user to a crafted URL containing JavaScript code, which would then cause that code to be executed in the victim's browser as if it was part of OpenRefine.

### Details

The `state` GET parameter is read from:

* extensions/gdata/module/MOD-INF/controller.js:105

It is used (as `$state`) in:

* extensions/gdata/module/authorized.vt:43

There is no check that the state has the expected format (base64-encoded JSON with values like "openrefine123..." and "cb123..."), or that the page was indeed opened as part of the authorization flow.

### PoC

Navigate to:

    http://localhost:3333/extension/gdata/authorized?state=%22,alert(1),%22&error=

An alert box pops up.

The gdata extension needs to be present. No other configuration is needed; specifically, it is not required to have a client ID or client secret set.

### Impact

Execution of arbitrary JavaScript in the user's browser. The attacker-provided code can do anything the user can do, including deleting projects, retrieving database passwords, or executing arbitrary Jython or Closure expressions, if those extensions are also present.
