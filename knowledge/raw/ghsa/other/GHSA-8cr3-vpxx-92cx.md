# Keycloak SAML Broken has Authentication Bypass by Primary Weakness

**GHSA**: GHSA-8cr3-vpxx-92cx | **CVE**: CVE-2026-3047 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-305

**Affected Packages**:
- **org.keycloak:keycloak-broker-saml** (maven): <= 1.8.1.Final

## Description

A flaw was found in org.keycloak.broker.saml. When a disabled Security Assertion Markup Language (SAML) client is configured as an Identity Provider (IdP)-initiated broker landing target, it can still complete the login process and establish a Single Sign-On (SSO) session. This allows a remote attacker to gain unauthorized access to other enabled clients without re-authentication, effectively bypassing security restrictions.

A fix is available at https://github.com/keycloak/keycloak/releases/tag/26.5.5.
