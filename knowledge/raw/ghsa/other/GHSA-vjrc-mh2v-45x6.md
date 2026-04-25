# OAuth2-Proxy is vulnerable to header smuggling via underscore leading to potential privilege escalation

**GHSA**: GHSA-vjrc-mh2v-45x6 | **CVE**: CVE-2025-64484 | **Severity**: high (CVSS 8.5)

**CWE**: CWE-644

**Affected Packages**:
- **github.com/oauth2-proxy/oauth2-proxy/v7** (go): < 7.13.0

## Description

### Impact
All deployments of OAuth2 Proxy in front of applications that normalize underscores to dashes in HTTP headers (e.g., WSGI-based frameworks such as Django, Flask, FastAPI, and PHP applications).

Authenticated users can inject underscore variants of X-Forwarded-* headers that bypass the proxy’s filtering logic, potentially escalating privileges in the upstream app. OAuth2 Proxy authentication/authorization itself is not compromised.

### Patches

This change mitigates a request header smuggling vulnerability where an attacker could bypass header stripping by using different capitalization or replacing dashes with underscores. The problem has been patched with v7.13.0.

By default all specified headers will now be normalized, meaning that both capitalization and the use of underscores (_) versus dashes (-) will be ignored when matching headers to be stripped. For example, both `X-Forwarded-For` and `X_Forwarded-for` will now be treated as equivalent and stripped away.

However, if users have a rationale for keeping a similar-looking header and don't want to strip it, a new configuration field for headers managed through AlphaConfig called InsecureSkipHeaderNormalization has been introduced :

```golang
// Header represents an individual header that will be added to a request or
// response header.
type Header struct {
	// Name is the header name to be used for this set of values.
	// Names should be unique within a list of Headers.
	Name string `json:"name,omitempty"`

	// PreserveRequestValue determines whether any values for this header
	// should be preserved for the request to the upstream server.
	// This option only applies to injected request headers.
	// Defaults to false (headers that match this header will be stripped).
	PreserveRequestValue bool `json:"preserveRequestValue,omitempty"`

	// InsecureSkipHeaderNormalization disables normalizing the header name
	// According to RFC 7230 Section 3.2 there aren't any rules about
	// capitalization of header names, but the standard practice is to use
	// Title-Case (e.g. X-Forwarded-For). By default, header names will be
	// normalized to Title-Case and any incoming headers that match will be
	// treated as the same header. Additionally underscores (_) in header names
	// will be converted to dashes (-) when normalizing.
	// Defaults to false (header names will be normalized).
	InsecureSkipHeaderNormalization bool `json:"InsecureSkipHeaderNormalization,omitempty"`

	// Values contains the desired values for this header
	Values []HeaderValue `json:"values,omitempty"`
}
```

### Workarounds
Ensure filtering and processing logic in upstream services don't treat underscores and hyphens in Headers the same way.
