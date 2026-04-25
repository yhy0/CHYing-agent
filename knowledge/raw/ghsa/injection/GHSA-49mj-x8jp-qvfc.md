# OctoPrint is Vulnerable to RCE Attacks via Unsanitized Filename in File Upload

**GHSA**: GHSA-49mj-x8jp-qvfc | **CVE**: CVE-2025-58180 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-78

**Affected Packages**:
- **octoprint** (pip): < 1.11.3

## Description

### Impact

OctoPrint versions up until and including 1.11.2 contain a vulnerability that allows an **authenticated** attacker to upload a file under a specially crafted filename that will allow arbitrary command execution if said filename becomes included in a command defined in a system event handler and said event gets triggered.

If no event handlers executing system commands with uploaded filenames as parameters have been configured, this vulnerability does not have an impact.

### Patches

The vulnerability will be patched in version 1.11.3.

### Workaround

Until the patch has been applied, OctoPrint administrators who have event handlers configured that include any kind of filename based placeholders (i.e. `{__filename}`, `{__filepath}`, `{filename}`, `{path}`, etc -- refer to [the events documentation](https://docs.octoprint.org/en/master/events/index.html#placeholders) for a full list) should disable those by setting their `enabled` property to `False` or unchecking the "Enabled" checkbox in the GUI based Event Manager.

Alternatively, OctoPrint administrators should set `feature.enforceReallyUniversalFilenames` to `true` in `config.yaml` and restart OctoPrint, then vet the existing uploads and make sure to delete any suspicious looking files (e.g. those that contain a `;` in their name followed by a command).

As always, OctoPrint administrators are advised to not expose OctoPrint on hostile networks like the public internet, and to vet who has access to their instance.

### Credits

This vulnerability was discovered and responsibly disclosed to OctoPrint by @prabhatverma47.
