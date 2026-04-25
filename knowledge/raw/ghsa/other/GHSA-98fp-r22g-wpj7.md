# Jenkins CSRF protection bypass vulnerability

**GHSA**: GHSA-98fp-r22g-wpj7 | **CVE**: CVE-2023-35141 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-352

**Affected Packages**:
- **org.jenkins-ci.main:jenkins-core** (maven): < 2.400

## Description

Jenkins provides context menus for various UI elements, like links to jobs and builds, or breadcrumbs.

In Jenkins 2.399 and earlier, LTS 2.387.3 and earlier, POST requests are sent in order to load the list of context actions. If part of the URL includes insufficiently escaped user-provided values, a victim may be tricked into sending a POST request to an unexpected endpoint (e.g., the Script Console) by opening a context menu.

As of publication of this advisory, we are aware of insufficiently escaped context menu URLs for label expressions, allowing attackers with Item/Configure permissions to exploit this vulnerability.

Jenkins 2.400, LTS 2.401.1 sends GET requests to load the list of context actions.
