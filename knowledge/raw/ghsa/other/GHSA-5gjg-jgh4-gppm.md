# Websocket requests did not call AuthenticateMethod

**GHSA**: GHSA-5gjg-jgh4-gppm | **CVE**: CVE-2021-4236 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-304, CWE-400, CWE-476

**Affected Packages**:
- **github.com/ecnepsnai/web** (go): >= 1.4.0, < 1.5.2

## Description

### Impact

Depending on implementation, a denial-of-service or privilege escalation vulnerability may occur in software that uses the `github.com/ecnepsnai/web` package with Web Sockets that have an AuthenticateMethod.

The `AuthenticateMethod` is not called, and `UserData` will be nil in request methods. Attempts to read the `UserData` may result in a panic.

This issue only affects web sockets where an `AuthenticateMethod` is supplied to the handle options. Users who do not use web sockets, or users who do not require authentication are not at risk.

#### Example

In the example below, one would expect that the `AuthenticateMethod` function would be called for each request to `/example`

```go
handleOptions := web.HandleOptions{
	AuthenticateMethod: func(request *http.Request) interface{} {
		// Assume there is logic here to check for an active sessions, look at cookies or headers, etc...
		var session Session{} // Example

		return session
	},
}

server.Socket("/example", handle, handleOptions)
```

However, the method is not called, and therefor the `UserData` parameter of the request object in the handle will be nil, when it would have been expected to be the `session` object we returned.

### Patches

Release v1.5.2 fixes this vulnerability. The authenticate method is now called for websocket requests.

All users of the web package should update to v1.5.2 or later.

### Workarounds

You may work around this issue by making the authenticate method a named function, then calling that function at the start of the handle method for the websocket. Reject connections when the return value of the method is nil.
