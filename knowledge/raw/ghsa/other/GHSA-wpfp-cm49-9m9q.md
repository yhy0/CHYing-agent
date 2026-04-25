# HashiCorp go-slug Vulnerable to Zip Slip Attack

**GHSA**: GHSA-wpfp-cm49-9m9q | **CVE**: CVE-2025-0377 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-59

**Affected Packages**:
- **github.com/hashicorp/go-slug** (go): < 0.16.3

## Description

## Summary
HashiCorp’s go-slug library is vulnerable to a zip-slip style attack when a non-existing user-provided path is extracted from the tar entry. This vulnerability, identified as CVE-2025-0377, is fixed in go-slug 0.16.3.

## Background
HashiCorp’s go-slug shared library offers functions for packing and unpacking Terraform Enterprise compatible slugs. Slugs are gzip compressed tar files containing Terraform configuration files.

## Details
When go-slug performs an extraction, the filename/extraction path is taken from the tar entry via the header.Name. It was discovered that the unpacking step improperly validated paths, potentially leading to path traversal, allowing an attacker to write an arbitrary file during extraction.

## Remediation
Consumers of the go-slug shared library should evaluate the risk associated with this issue in the context of their go-slug usage and upgrade go-slug to 0.16.3 or later.
