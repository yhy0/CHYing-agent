# ZITADEL's Service Users Deactivation not Working 

**GHSA**: GHSA-qr2h-7pwm-h393 | **CVE**: CVE-2024-47000 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-269, CWE-672

**Affected Packages**:
- **github.com/zitadel/zitadel/v2** (go): >= 2.62.0, < 2.62.1
- **github.com/zitadel/zitadel/v2** (go): >= 2.61.0, < 2.61.1
- **github.com/zitadel/zitadel/v2** (go): >= 2.60.0, < 2.60.2
- **github.com/zitadel/zitadel/v2** (go): >= 2.59.0, < 2.59.3
- **github.com/zitadel/zitadel/v2** (go): >= 2.58.0, < 2.58.5
- **github.com/zitadel/zitadel/v2** (go): >= 2.57.0, < 2.57.5
- **github.com/zitadel/zitadel/v2** (go): >= 2.56.0, < 2.56.6
- **github.com/zitadel/zitadel/v2** (go): >= 2.55.0, < 2.55.8
- **github.com/zitadel/zitadel/v2** (go): < 2.54.10

## Description

### Impact
ZITADEL's user account deactivation mechanism did not work correctly with service accounts. Deactivated service accounts retained the ability to request tokens, which could lead to unauthorized access to applications and resources.

### Patches

2.x versions are fixed on >= [2.62.1](https://github.com/zitadel/zitadel/releases/tag/v2.62.1)
2.61.x versions are fixed on >= [2.61.1](https://github.com/zitadel/zitadel/releases/tag/v2.61.1)
2.60.x versions are fixed on >= [2.60.2](https://github.com/zitadel/zitadel/releases/tag/v2.60.2)
2.59.x versions are fixed on >= [2.59.3](https://github.com/zitadel/zitadel/releases/tag/v2.59.3)
2.58.x versions are fixed on >= [2.58.5](https://github.com/zitadel/zitadel/releases/tag/v2.58.5)
2.57.x versions are fixed on >= [2.57.5](https://github.com/zitadel/zitadel/releases/tag/v2.57.5)
2.56.x versions are fixed on >= [2.56.6](https://github.com/zitadel/zitadel/releases/tag/v2.56.6)
2.55.x versions are fixed on >= [2.55.8](https://github.com/zitadel/zitadel/releases/tag/v2.55.8)
2.54.x versions are fixed on >= [2.54.10](https://github.com/zitadel/zitadel/releases/tag/v2.54.10)

### Workarounds
Instead of deactivating the service account, consider creating new credentials and replacing the old ones wherever they are used. This effectively prevents the deactivated service account from being utilized.

- Revoke all existing authentication keys associated with the service account
- Rotate the service account's password

### Questions
If you have any questions or comments about this advisory, please email us at 

[security@zitadel.com](mailto:security@zitadel.com)
