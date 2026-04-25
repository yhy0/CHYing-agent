# Golang Facebook Thrift servers vulnerable to denial of service

**GHSA**: GHSA-w3r9-r9w7-8h48 | **CVE**: CVE-2019-11939 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-770

**Affected Packages**:
- **github.com/facebook/fbthrift** (go): < 0.31.1-0.20200311080807-483ed864d69f

## Description

Golang Facebook Thrift servers would not error upon receiving messages declaring containers of sizes larger than the payload. As a result, malicious clients could send short messages which would result in a large memory allocation, potentially leading to denial of service. This issue affects Facebook Thrift prior to v2020.03.16.00.

### Specific Go Packages Affected
github.com/facebook/fbthrift/thrift/lib/go/thrift
