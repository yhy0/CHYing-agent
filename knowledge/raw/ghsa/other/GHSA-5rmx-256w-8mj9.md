# WireGuard Portal is Vulnerable to Privilege Escalation via User Self-Update to Admin Level

**GHSA**: GHSA-5rmx-256w-8mj9 | **CVE**: CVE-2026-27899 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-269, CWE-863

**Affected Packages**:
- **github.com/h44z/wg-portal** (go): <= 2.1.2

## Description

# Privilege Escalation to Admin via User Self-Update in wg-portal

## Summary

Any authenticated non-admin user can become a full administrator by sending a single PUT request to their own user profile endpoint with `"IsAdmin": true` in the JSON body. After logging out and back in, the session picks up admin privileges from the database.

Tested against wg-portal v2.1.2 (Docker image `wgportal/wg-portal:v2`).

## Root Cause

When a user updates their own profile, the server parses the full JSON body into the user model, including the `IsAdmin` boolean field. A function responsible for preserving calculated or protected attributes pins certain fields to their database values (such as base model data, linked peer count, and authentication data), but it does not do this for `IsAdmin`. As a result, whatever value the client sends for `IsAdmin` is written directly to the database.

## Impact

After the exploit, the attacker has full admin access to the WireGuard VPN management portal. They can:

- Read and modify every user account
- Create, modify, and delete WireGuard peers on any interface
- View WireGuard interface configurations
- Disable or lock other user accounts
- Access the full user list and their API tokens

## Patches
The problem was fixed in the latest release, [v2.1.3](https://github.com/h44z/wg-portal/releases/tag/v2.1.3). The [docker images](https://hub.docker.com/r/wgportal/wg-portal) for the tag 'latest' built from the master branch also include the fix.
