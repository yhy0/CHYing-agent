# Mesop Class Pollution vulnerability leads to DoS and Jailbreak attacks

**GHSA**: GHSA-f3mf-hm6v-jfhh | **CVE**: CVE-2025-30358 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-915

**Affected Packages**:
- **mesop** (pip): < 0.14.1

## Description

From @jackfromeast and @superboy-zjc:
We have identified a class pollution vulnerability in Mesop (<= [0.14.0](https://github.com/mesop-dev/mesop/releases/tag/v0.14.0)) application that allows attackers to overwrite global variables and class attributes in certain Mesop modules during runtime. This vulnerability could directly lead to a denial of service (DoS) attack against the server. Additionally, it could also result in other severe consequences given the application's implementation, such as identity confusion, where an attacker could impersonate an assistant or system role within conversations. This impersonation could potentially enable jailbreak attacks when interacting with large language models (LLMs).

Just like the Javascript's prototype pollution, this vulnerability could leave a way for attackers to manipulate the intended data-flow or control-flow of the application at runtime and lead to severe consequnces like RCE when gadgets are available.
