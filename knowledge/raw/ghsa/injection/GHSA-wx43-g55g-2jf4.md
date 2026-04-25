# LocalAI Command Injection in audioToWav

**GHSA**: GHSA-wx43-g55g-2jf4 | **CVE**: CVE-2024-2029 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-78

**Affected Packages**:
- **github.com/go-skynet/LocalAI** (go): < 2.10.0

## Description

A command injection vulnerability exists in the `TranscriptEndpoint` of mudler/localai, specifically within the `audioToWav` function used for converting audio files to WAV format for transcription. The vulnerability arises due to the lack of sanitization of user-supplied filenames before passing them to ffmpeg via a shell command, allowing an attacker to execute arbitrary commands on the host system. Successful exploitation could lead to unauthorized access, data breaches, or other detrimental impacts, depending on the privileges of the process executing the code.
