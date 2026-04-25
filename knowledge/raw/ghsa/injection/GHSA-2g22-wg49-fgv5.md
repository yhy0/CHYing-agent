# XWiki Full Calendar Macro vulnerable to SQL injection through Calendar.JSONService

**GHSA**: GHSA-2g22-wg49-fgv5 | **CVE**: CVE-2025-65091 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-89

**Affected Packages**:
- **org.xwiki.contrib:macro-fullcalendar-pom** (maven): <= 2.4.3

## Description

### Impact

Anyone who has view rights on the `Calendar.JSONService` page, including guest users can exploit this vulnerability by accessing database info or starting a DoS attack.

### Workarounds

Remove the `Calendar.JSONService` page. This will however break some functionalities.

### References

Jira issue: 
* [FULLCAL-80: SQL injection through Calendar.JSONService](https://jira.xwiki.org/browse/FULLCAL-80)
* [FULLCAL-81: SQL injection through Calendar.JSONService still exists](https://jira.xwiki.org/browse/FULLCAL-81)

### For more information

If there are any questions or comments about this advisory:
* Open an issue in [Jira XWiki.org](https://jira.xwiki.org/)
* Email [Security Mailing List](mailto:security@xwiki.org)
