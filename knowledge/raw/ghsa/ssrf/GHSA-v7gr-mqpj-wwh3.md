# CometVisu Backend for openHAB affected by SSRF/XSS

**GHSA**: GHSA-v7gr-mqpj-wwh3 | **CVE**: CVE-2024-42467 | **Severity**: high (CVSS 10.0)

**CWE**: CWE-918

**Affected Packages**:
- **org.openhab.ui.bundles:org.openhab.ui.cometvisu** (maven): <= 4.2.0

## Description

The [proxy endpoint](https://github.com/openhab/openhab-webui/blob/1c03c60f84388b9d7da0231df2d4ebb1e17d3fcf/bundles/org.openhab.ui.cometvisu/src/main/java/org/openhab/ui/cometvisu/internal/backend/rest/ProxyResource.java#L83) of openHAB's CometVisu add-on can be accessed without authentication. This proxy-feature can be exploited as Server-Side Request Forgery (SSRF) to induce GET HTTP requests to internal-only servers, in case openHAB is exposed in a non-private network.

Furthermore, this proxy-feature can also be exploited as a Cross-Site Scripting (XSS) vulnerability, as an attacker is able to re-route a request to their server and return a page with malicious JavaScript code. Since the browser receives this data directly from the openHAB CometVisu UI, this JavaScript code will be executed with the origin of the CometVisu UI. This allows an attacker to exploit call endpoints on an openHAB server even if the openHAB server is located in a private network. (e.g. by sending an openHAB admin a link that proxies malicious JavaScript.)

This vulnerability was discovered with the help of CodeQL's [Server-side request forgery](https://codeql.github.com/codeql-query-help/java/java-ssrf/) query.

## Impact

This issue may lead up to Remote Code Execution (RCE) when chained with other vulnerabilities (see: GHSL-2024-007).
