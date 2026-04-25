# Authorization Bypass Through User-Controlled Key in go-zero

**GHSA**: GHSA-fgxv-gw55-r5fq | **CVE**: CVE-2024-27302 | **Severity**: critical (CVSS 9.1)

**CWE**: N/A

**Affected Packages**:
- **github.com/zeromicro/go-zero** (go): < 1.4.4

## Description

### Summary
Hello go-zero maintainer team, I would like to report a security concerning your CORS Filter feature. 

### Details
Go-zero allows user to specify a [CORS Filter](https://github.com/zeromicro/go-zero/blob/master/rest/internal/cors/handlers.go) with a configurable allows param - which is an array of domains allowed in CORS policy.

However, the `isOriginAllowed` uses `strings.HasSuffix` to check the origin, which leads to bypass via domain like `evil-victim.com`
```go
func isOriginAllowed(allows []string, origin string) bool {
	for _, o := range allows {
		if o == allOrigins {
			return true
		}

		if strings.HasSuffix(origin, o) {
			return true
		}
	}

	return false
}
```

### PoC
Use code below as a PoC. Only requests from `safe.com` should bypass the CORS Filter
```go
package main

import (
	"errors"
	"net/http"

	"github.com/zeromicro/go-zero/rest"
)

func main() {
	svr := rest.MustNewServer(rest.RestConf{Port: 8888}, rest.WithRouter(mockedRouter{}), rest.WithCors("safe.com"))
	svr.Start()
}

type mockedRouter struct{}

// some sensitive path
func (m mockedRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// check user's cookie
	// ...
	// return sensitive data
	w.Write([]byte("social_id: 420101198008292930"))
}

func (m mockedRouter) Handle(_, _ string, handler http.Handler) error {
	return errors.New("foo")
}

func (m mockedRouter) SetNotFoundHandler(_ http.Handler) {
}

func (m mockedRouter) SetNotAllowedHandler(_ http.Handler) {
}
```
Send a request to localhost:8888 with `Origin:not-safe.com`
You can see the origin reflected in response, which bypass the CORS Filter
![image](https://user-images.githubusercontent.com/70683161/221365842-9d76a3a4-a79d-413a-85b7-06b50b0a7807.png)

### Impact
This vulnerability is capable of breaking CORS policy and thus allowing any page to make requests, retrieve data on behalf of other users.

