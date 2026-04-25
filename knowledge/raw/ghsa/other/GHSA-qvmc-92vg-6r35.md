# Mattermost with Jira plugin enabled has Incorrect Implementation of Authentication Algorithm

**GHSA**: GHSA-qvmc-92vg-6r35 | **CVE**: CVE-2025-14273 | **Severity**: high (CVSS 7.2)

**CWE**: CWE-303

**Affected Packages**:
- **github.com/mattermost/mattermost/server/v8** (go): < 8.0.0-20251121122154-b57c297c6d7a
- **github.com/mattermost/mattermost-plugin-jira** (go): < 4.4.1

## Description

Mattermost versions 11.1.x <= 11.1.0, 11.0.x <= 11.0.5, 10.12.x <= 10.12.3, 10.11.x <= 10.11.7 with the Jira plugin enabled and Mattermost Jira plugin versions <=4.4.0 fail to enforce authentication and issue-key path restrictions in the Jira plugin, which allows an unauthenticated attacker who knows a valid user ID to issue authenticated GET and POST requests to the Jira server via crafted plugin payloads that spoof the user ID and inject arbitrary issue key paths. Mattermost Advisory ID: MMSA-2025-00555
