# langchain-experimental vulnerable to Arbitrary Code Execution

**GHSA**: GHSA-cgcg-p68q-3w7v | **CVE**: CVE-2024-21513 | **Severity**: critical (CVSS 8.6)

**CWE**: CWE-94

**Affected Packages**:
- **langchain-experimental** (pip): >= 0, < 0.0.21

## Description

Versions of the package langchain-experimental from 0.0.15 and before 0.0.21 are vulnerable to Arbitrary Code Execution when retrieving values from the database, the code will attempt to call 'eval' on all values. An attacker can exploit this vulnerability and execute arbitrary python code if they can control the input prompt and the server is configured with VectorSQLDatabaseChain.

**Notes:**

Impact on the Confidentiality, Integrity and Availability of the vulnerable component:

Confidentiality: Code execution happens within the impacted component, in this case langchain-experimental, so all resources are necessarily accessible.

Integrity: There is nothing protected by the impacted component inherently. Although anything returned from the component counts as 'information' for which the trustworthiness can be compromised.

Availability: The loss of availability isn't caused by the attack itself, but it happens as a result during the attacker's post-exploitation steps.


Impact on the Confidentiality, Integrity and Availability of the subsequent system:

As a legitimate low-privileged user of the package (PR:L) the attacker does not have more access to data owned by the package as a result of this vulnerability than they did with normal usage (e.g. can query the DB). The unintended action that one can perform by breaking out of the app environment and exfiltrating files, making remote connections etc. happens during the post exploitation phase in the subsequent system - in this case, the OS.

AT:P: An attacker needs to be able to influence the input prompt, whilst the server is configured with the VectorSQLDatabaseChain plugin.
