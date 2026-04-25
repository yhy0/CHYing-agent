# Run Shell Command allows Cross-Site Request Forgery

**GHSA**: GHSA-8jpr-ff92-hpf9 | **CVE**: CVE-2023-48292 | **Severity**: critical (CVSS 9.7)

**CWE**: CWE-352

**Affected Packages**:
- **org.xwiki.contrib:xwiki-application-admintools** (maven): >= 4.4, < 4.5.1

## Description

### Impact
A cross site request forgery vulnerability in the admin tool for executing shell commands on the server allows an attacker to execute arbitrary shell commands by tricking an admin into loading the URL with the shell command. A very simple possibility for an attack are comments. When the attacker can leave a comment on any page in the wiki it is sufficient to include an image with an URL like  `/xwiki/bin/view/Admin/RunShellCommand?command=touch%20/tmp/attacked` in the comment. When an admin views the comment, the file `/tmp/attacked` will be created on the server. The output of the command is also vulnerable to XWiki syntax injection which offers a simple way to execute Groovy in the context of the XWiki installation and thus an even easier way to compromise the integrity and confidentiality of the whole XWiki installation.

### Patches
This has been patched by adding a form token check in version 4.5.1 of the admin tools.

### Workarounds
The [patch](https://github.com/xwiki-contrib/application-admintools/commit/03815c505c9f37006a0c56495e862dc549a39da8) can be applied manually to the affected wiki pages. Alternatively, the document `Admin.RunShellCommand` can also be deleted if the possibility to run shell commands isn't needed.

### References
* https://jira.xwiki.org/browse/ADMINTOOL-91
* https://github.com/xwiki-contrib/application-admintools/commit/03815c505c9f37006a0c56495e862dc549a39da8

