# rabbitmq-connector plugin module in Apache EventMesh platforms allows attackers to send controlled message

**GHSA**: GHSA-fj8f-56wc-q36r | **CVE**: CVE-2023-26512 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **org.apache.eventmesh:eventmesh-connector-rabbitmq** (maven): >= 1.7.0, <= 1.8.0

## Description

CWE-502 Deserialization of Untrusted Data at the rabbitmq-connector plugin module in Apache EventMesh (incubating) V1.7.0\V1.8.0 on windows\linux\mac os e.g. platforms allows attackers to send controlled message and 

remote code execute via rabbitmq messages. Users can use the code under the master branch in project repo to fix this issue,  the new version is set to be released as soon as possible.
