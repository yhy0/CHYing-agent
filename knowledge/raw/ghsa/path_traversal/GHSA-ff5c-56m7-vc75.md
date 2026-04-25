# Open WebUI allows Remote Code Execution via Arbitrary File Upload to /audio/api/v1/transcriptions

**GHSA**: GHSA-ff5c-56m7-vc75 | **CVE**: CVE-2024-8060 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-22, CWE-434

**Affected Packages**:
- **open-webui** (pip): < 0.5.17

## Description

OpenWebUI version 0.3.0 contains a vulnerability in the audio API endpoint `/audio/api/v1/transcriptions` that allows for arbitrary file upload. The application performs insufficient validation on the `file.content_type` and allows user-controlled filenames, leading to a path traversal vulnerability. This can be exploited by an authenticated user to overwrite critical files within the Docker container, potentially leading to remote code execution as the root user.
