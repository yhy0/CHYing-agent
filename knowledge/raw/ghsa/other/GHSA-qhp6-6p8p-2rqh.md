# Wildfly Elytron integration susceptible to brute force attacks via CLI

**GHSA**: GHSA-qhp6-6p8p-2rqh | **CVE**: CVE-2025-23368 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-307

**Affected Packages**:
- **org.wildfly.core:wildfly-elytron-integration** (maven): >= 32.0.0.Beta1, < 32.0.0.Beta3
- **org.wildfly.core:wildfly-elytron-integration** (maven): < 31.0.3.Final

## Description

### Impact

A flaw was found in Wildfly Elytron integration. The component does not implement sufficient measures to prevent multiple failed authentication attempts within a short time frame, making it more susceptible to brute force attacks via CLI.

### Patches

The default behaviour has been changed in WildFly Core 31.0.3.Final, and 32.0.0.Beta3 - the first version is used by WildFly 39.0.1.Final and the second will be included in WildFly 40.

### Workarounds

No direct workaround.
Monitoring network traffic / blocking suspicious traffic may help.

### References

https://www.cve.org/CVERecord?id=CVE-2025-23368
https://issues.redhat.com/browse/WFCORE-7192

### Acknowledgements

We would like to thank Claudia Bartolini (TIM S.p.A), Marco Ventura (TIM S.p.A), and Massimiliano Brolli (TIM S.p.A) for reporting this issue.
