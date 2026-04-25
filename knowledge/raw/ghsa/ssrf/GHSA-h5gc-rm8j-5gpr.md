# LangChain Community SSRF vulnerability exists in RequestsToolkit component 

**GHSA**: GHSA-h5gc-rm8j-5gpr | **CVE**: CVE-2025-2828 | **Severity**: high (CVSS 8.4)

**CWE**: CWE-918

**Affected Packages**:
- **langchain-community** (pip): < 0.0.28

## Description

A Server-Side Request Forgery (SSRF) vulnerability exists in the RequestsToolkit component of the langchain-community package (specifically, langchain_community.agent_toolkits.openapi.toolkit.RequestsToolkit) in langchain-ai/langchain version 0.0.27. This vulnerability occurs because the toolkit does not enforce restrictions on requests to remote internet addresses, allowing it to also access local addresses. As a result, an attacker could exploit this flaw to perform port scans, access local services, retrieve instance metadata from cloud environments (e.g., Azure, AWS), and interact with servers on the local network. This issue has been fixed in version 0.0.28.
