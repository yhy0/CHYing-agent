# filebrowser allows Stored Cross-Site Scripting through the Markdown preview function

**GHSA**: GHSA-4wx8-5gm2-2j97 | **CVE**: CVE-2025-52902 | **Severity**: high (CVSS 7.6)

**CWE**: CWE-79

**Affected Packages**:
- **github.com/filebrowser/filebrowser/v2** (go): < 2.33.7
- **github.com/filebrowser/filebrowser** (go): <= 1.11.0

## Description

## Summary ##

The Markdown preview function of File Browser v2.32.0 is vulnerable to *Stored Cross-Site-Scripting (XSS)*. Any JavaScript code that is part of a Markdown file uploaded by a user will be executed by the browser

## Impact ##

A user can upload a malicious Markdown file to the application which can contain arbitrary HTML code. If another user within the same scope clicks on that file, a rendered preview is opened. JavaScript code that has been included will be executed.

 Malicious actions that are possible include:
 
  * Obtaining a user's session token
  * Elevating the attacker's privileges, if the victim is an administrator (e.g., gaining command execution rights)

## Vulnerability Description ##

Most Markdown parsers accept arbitrary HTML in a document and try rendering it accordingly. For instance, if one creates a file called `xss.md` with the following content:

```markdown
# Hallo

<b>foo</b>

<img src="xx" onerror=alert(9)>
<i>bar</i>
```

Bold and italic text will be rendered. Also, the renderer used in File Browser will try to display the image and execute the code in the `onerror` event handler.

## Proof of Concept ##

The screenshot shows that the code from the file mentioned above has actually been executed in the victim's browser:

![JavaScript code being executed in the Markdown Preview](https://github.com/user-attachments/assets/3a3b9920-fbd8-433f-a016-ea77f5f68851)

## Recommended Countermeasures ##

The most thorough fix would be to reconfigure the application's Markdown parser to ignore all HTML elements and only render rich text which is part of the Markdown specification. If HTML rendering is considered to be a required feature, an HTML sanitizer like DOMPurify should be used, preferably in conjunction with a *Content Security Policy* (CSP).

## Timeline ##

* `2025-03-25` Identified the vulnerability in version 2.32.0
* `2025-04-11` Contacted the project
* `2025-04-18` Vulnerability disclosed to the project
* `2025-06-25` Uploaded advisories to the project's GitHub repository
* `2025-06-26` CVE ID assigned by GitHub
* `2025-06-26` Fix released with version 2.33.7

## References ##

* [DOMPurify](https://github.com/cure53/DOMPurify)
* [Original Advisory](https://github.com/sbaresearch/advisories/tree/public/2025/SBA-ADV-20250325-04_Filebrowser_Stored_XSS)

## Credits ##

* Mathias Tausig ([SBA Research](https://www.sba-research.org/))
