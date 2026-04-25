# KubePi allows malicious actor to login with a forged JWT token via Hardcoded Jwtsigkeys

**GHSA**: GHSA-vjhf-8vqx-vqpq | **CVE**: CVE-2023-22463 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-798

**Affected Packages**:
- **github.com/KubeOperator/kubepi** (go): <= 1.6.2

## Description

### Summary
The jwt authentication function of kubepi <= v1.6.2 uses hard-coded Jwtsigkeys, resulting in the same Jwtsigkeys for all online projects. This means that an attacker can forge any jwt token to take over the administrator account of any online project. 

### Details
[`session.go`](https://github.com/KubeOperator/KubePi/blob/da784f5532ea2495b92708cacb32703bff3a45a3/internal/api/v1/session/session.go#L35), the use of hard-coded JwtSigKey allows an attacker to use this value to forge jwt tokens arbitrarily. The JwtSigKey is confidential and should not be hard-coded in the code.

```golang
var JwtSigKey = []byte("signature_hmac_secret_shared_key")
var jwtMaxAge = 10 * time.Minute

type Handler struct {
	userService        user.Service
	roleService        role.Service
	clusterService     cluster.Service
	rolebindingService rolebinding.Service
	ldapService        ldap.Service
	jwtSigner          *jwt.Signer
}
```
### Affected Version
<= v1.6.2

### Patches
The vulnerability has been fixed in [v1.6.3](https://github.com/KubeOperator/KubePi/releases/tag/v1.6.3).

https://github.com/KubeOperator/KubePi/commit/3be58b8df5bc05d2343c30371dd5fcf6a9fbbf8b : JWT key can be specified in app.yml, if leave it blank a random key will be used.

### Workarounds
It is recommended to upgrade the version to [v1.6.3](https://github.com/KubeOperator/KubePi/releases/tag/v1.6.3).

### For more information
If you have any questions or comments about this advisory, please [open an issue](https://github.com/KubeOperator/KubePi/issues).
