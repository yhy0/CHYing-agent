# Privilege Escalation in kubevirt

**GHSA**: GHSA-828r-r2c8-rfw3 | **CVE**: CVE-2020-14316 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-269

**Affected Packages**:
- **kubevirt.io/kubevirt** (go): < 0.30.0

## Description

A flaw was found in kubevirt 0.29 and earlier. Virtual Machine Instances (VMIs) can be used to gain access to the host's filesystem. Successful exploitation allows an attacker to assume the privileges of the VM process on the host system. In worst-case scenarios an attacker can read and modify any file on the system where the VMI is running. The highest threat from this vulnerability is to data confidentiality and integrity as well as system availability.
