# Grafana vulnerable to authenticated users bypassing dashboard, folder permissions

**GHSA**: GHSA-3px7-c4j3-576r | **CVE**: CVE-2025-3260 | **Severity**: high (CVSS 8.3)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/grafana/grafana** (go): >= 0.0.0-20250114093457-36d6fad421fb, < 0.0.0-20250521183405-c7a690348df7

## Description

A security vulnerability in the /apis/dashboard.grafana.app/* endpoints allows authenticated users to bypass dashboard and folder permissions. The vulnerability affects all API versions (v0alpha1, v1alpha1, v2alpha1).

Impact:

- Viewers can view all dashboards/folders regardless of permissions

- Editors can view/edit/delete all dashboards/folders regardless of permissions

- Editors can create dashboards in any folder regardless of permissions

- Anonymous users with viewer/editor roles are similarly affected

Organization isolation boundaries remain intact. The vulnerability only affects dashboard access and does not grant access to datasources.
