# Withdrawn Advisory: Gradio was discovered to contain a code injection vulnerability via the component /gradio/component_meta.py

**GHSA**: GHSA-9v2f-6vcg-3hgv | **CVE**: CVE-2024-39236 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **Gradio** (pip): = 4.36.1

## Description

### Withdrawn Advisory
This advisory has been withdrawn because the it only affects a user who runs specifically crafted code that happens to use gradio library. More information can be found [here](https://github.com/gradio-app/gradio/issues/8853).

### Original Description
Gradio v4.36.1 was discovered to contain a code injection vulnerability via the component /gradio/component_meta.py. This vulnerability is triggered via a crafted input.
