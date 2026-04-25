# H2O has an External Control of File Name or Path vulnerability

**GHSA**: GHSA-wj3h-wx8g-x699 | **CVE**: CVE-2024-5986 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-73

**Affected Packages**:
- **ai.h2o:h2o-core** (maven): <= 3.46.0.1
- **h2o** (pip): <= 3.46.0.1

## Description

A vulnerability in h2oai/h2o-3 version 3.46.0.1 allows remote attackers to write arbitrary data to any file on the server. This is achieved by exploiting the `/3/Parse` endpoint to inject attacker-controlled data as the header of an empty file, which is then exported using the `/3/Frames/framename/export` endpoint. The impact of this vulnerability includes the potential for remote code execution and complete access to the system running h2o-3, as attackers can overwrite critical files such as private SSH keys or script files.
