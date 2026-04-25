# ZITADEL's User Grant Deactivation not Working

**GHSA**: GHSA-2w5j-qfvw-2hf5 | **CVE**: CVE-2024-46999 | **Severity**: high (CVSS 7.3)

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

ZITADEL's user grants deactivation mechanism did not work correctly. Deactivated user grants were still provided in token, which could lead to unauthorized access to applications and resources.
Additionally, the management and auth API always returned the state as active or did not provide any information about the state.

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

Unpatched versions can explicitly remove the user grants to make sure the user does not get access anymore.

### Questions

If you have any questions or comments about this advisory, please email us at [security@zitadel.com](mailto:security@zitadel.com)

