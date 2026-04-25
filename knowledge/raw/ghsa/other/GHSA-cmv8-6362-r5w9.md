# Malicious HTML+XHR Artifact Privilege Escalation in Argo Workflows

**GHSA**: GHSA-cmv8-6362-r5w9 | **CVE**: CVE-2022-29164 | **Severity**: high (CVSS 7.1)

**CWE**: CWE-269

**Affected Packages**:
- **github.com/argoproj/argo-workflows/v3** (go): >= 2.6.0, < 3.2.11
- **github.com/argoproj/argo-workflows/v3** (go): >= 3.3.0, < 3.3.5

## Description

Argo Workflows is an open source container-native workflow engine for orchestrating parallel jobs on Kubernetes.

* The attacker creates a workflow that produces a HTML artifact that contains a HTML file that contains a script which uses XHR calls to interact with the Argo Server API.
* The attacker emails the deep-link to the artifact to their victim. The victim opens the link, the script starts running.

As the script has access to the Argo Server API (as the victim), so may do the following (if the victim may):

* Read information about the victim’s workflows.
* Create or delete workflows.

Notes:

* The attacker must be an insider: they must have access to the same cluster as the victim and must already be able to run their own workflows. 
* The attacker must have an understanding of the victim’s system. They won’t be able to repeatedly probe due to the social engineering  aspect.
* The attacker is likely leave an audit trail.

We have seen no evidence of this in the wild. While the impact is high, it is very hard to exploit. 

We urge all users to upgrade to the fixed versions. Disabling the Argo Server is the only known workaround. Note version 2.12 has been out of support for sometime. No fix is currently planned.
