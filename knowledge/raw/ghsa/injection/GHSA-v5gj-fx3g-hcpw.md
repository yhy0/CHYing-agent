# SQL injection in Apache Submarine

**GHSA**: GHSA-v5gj-fx3g-hcpw | **CVE**: CVE-2023-37924 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-89

**Affected Packages**:
- **apache-submarine** (pip): >= 0.7.0, < 0.8.0

## Description

Apache Software Foundation Apache Submarine has an SQL injection vulnerability when a user logs in. This issue can result in unauthorized login.

Now we have fixed this issue and now user must have the correct login to access workbench. This issue affects Apache Submarine: from 0.7.0 before 0.8.0. We recommend that all submarine users with 0.7.0 upgrade to 0.8.0, which not only fixes the issue, supports the oidc authentication mode, but also removes the case of unauthenticated logins.

If using the version lower than 0.8.0 and not want to upgrade, you can try cherry-pick PR  https://github.com/apache/submarine/pull/1037 https://github.com/apache/submarine/pull/1054  and rebuild the submarine-server image to fix this.
