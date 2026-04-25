# OpenCloud Affected by Public Link Exploit

**GHSA**: GHSA-vf5j-r2hw-2hrw | **CVE**: N/A | **Severity**: high (CVSS 8.2)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/opencloud-eu/opencloud** (go): >= 4.0.0, < 4.0.3
- **github.com/opencloud-eu/opencloud** (go): >= 5.0.0, < 5.0.2

## Description

### Impact

A security issue was discovered in [Reva](https://github.com/opencloud-eu/reva) that enables a malicious user to bypass the scope validation of a public link. That allows it to access resources outside the scope of a public link.

OpenCloud uses Reva as one of its core components and thus it is affected.

### Patches

Update to OpenCloud version >= 4.0.3 (stable release)
Update to OpenCloud version >= 5.0.2 (rolling release)

### Workarounds

If projects are unable to update immediately, please implement the following security configuration to disable public link shares temporarily until the final solution for this problem is rolled out.

#### Configuration Adjustment

* Docker Compose: Edit the docker-compose.yml and add `GATEWAY_STORAGE_PUBLIC_LINK_ENDPOINT=“”` (empty string value) in the `environment` section of the `opencloud` container.


#### Verification of Mitigation

Execute the following test: 
- Create a public link for testing. 
- Open the link url in a private (no active login) browser tab. 
- An error page with “unknown error” will be displayed.

This configuration provides immediate protection and should be implemented immediately. Configuration mitigation is available. It mitigates the problem completely.

### For more information

If there are questions or comments about this advisory:

- Security Support: [security@opencloud.eu](mailto:security@opencloud.eu)
- Technical Support: [support@opencloud.eu](mailto:support@opencloud.eu)
