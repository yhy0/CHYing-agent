# Mattermost allows authenticated users to write files to arbitrary locations

**GHSA**: GHSA-qh58-9v3j-wcjc | **CVE**: CVE-2025-4981 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-427

**Affected Packages**:
- **github.com/mattermost/mattermost-server** (go): < 0.0.0-20250519205859-65aec10162f6
- **github.com/mattermost/mattermost/server/v8** (go): < 8.0.0-20250519205859-65aec10162f6
- **github.com/mattermost/mattermost/server/v8** (go): >= 10.5.0, <= 10.5.5
- **github.com/mattermost/mattermost/server/v8** (go): >= 9.11.0, <= 9.11.15
- **github.com/mattermost/mattermost/server/v8** (go): = 10.8.0
- **github.com/mattermost/mattermost/server/v8** (go): >= 10.7.0, <= 10.7.2
- **github.com/mattermost/mattermost/server/v8** (go): >= 10.6.0, <= 10.6.5

## Description

Mattermost versions 10.5.x <= 10.5.5, 9.11.x <= 9.11.15, 10.8.x <= 10.8.0, 10.7.x <= 10.7.2, 10.6.x <= 10.6.5 fail to sanitize filenames in the archive extractor which allows authenticated users to write files to arbitrary locations on the filesystem via uploading archives with path traversal sequences in filenames, potentially leading to remote code execution. The vulnerability impacts instances where file uploads and document search by content is enabled (FileSettings.EnableFileAttachments = true and FileSettings.ExtractContent = true). These configuration settings are enabled by default.
