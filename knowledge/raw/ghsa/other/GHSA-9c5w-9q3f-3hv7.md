# Minder's GitHub Webhook Handler vulnerable to DoS from un-validated requests

**GHSA**: GHSA-9c5w-9q3f-3hv7 | **CVE**: CVE-2024-34084 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **github.com/stacklok/minder** (go): < 0.0.48

## Description

Minder's `HandleGithubWebhook` is susceptible to a denial of service attack from an untrusted HTTP request. The vulnerability exists before the request has been validated, and as such the request is still untrusted at the point of failure. This allows an attacker with the ability to send requests to `HandleGithubWebhook` to crash the Minder controlplane and deny other users from using it.

One of the first things that `HandleGithubWebhook` does is to validate the payload signature. This is done by way of the internal helper `validatePayloadSignature`:

https://github.com/stacklok/minder/blob/ee66f6c0763212503c898cfefb65ce1450c7f5ac/internal/controlplane/handlers_githubwebhooks.go#L213-L218

`validatePayloadSignature` generates a reader from the incoming request by way of the internal helper `readerFromRequest`:

https://github.com/stacklok/minder/blob/ee66f6c0763212503c898cfefb65ce1450c7f5ac/internal/controlplane/handlers_githubwebhooks.go#L337-L342

To create a reader from the incoming request, `readerFromRequest` first reads the request body entirely into memory on line 368:

https://github.com/stacklok/minder/blob/ee66f6c0763212503c898cfefb65ce1450c7f5ac/internal/controlplane/handlers_githubwebhooks.go#L367-L377

This is a vulnerability, since an HTTP request with a large body can exhaust the memory of the machine running Minder and cause the Go runtime to crash Minder.

Note that this occurs before Minder has validated the request, and as such, the request is still untrusted.

To test this out, we can use the existing `TestHandleWebHookRepository` unit test and modify the HTTP request body to be large. 

To do that, change these lines:

https://github.com/stacklok/minder/blob/ee66f6c0763212503c898cfefb65ce1450c7f5ac/internal/controlplane/handlers_githubwebhooks_test.go#L278-L283

... to these lines:
```go
	packageJson, err := json.Marshal(event)
	require.NoError(t, err, "failed to marshal package event")

        maliciousBody := strings.NewReader(strings.Repeat("1337", 1000000000))
        maliciousBodyReader := io.MultiReader(maliciousBody, maliciousBody, maliciousBody, maliciousBody, maliciousBody)
        _ = packageJson

	client := &http.Client{}
	req, err := http.NewRequest("POST", fmt.Sprintf("http://%s", addr), maliciousBodyReader)
	require.NoError(t, err, "failed to create request")
```

Then run the unit test again. WARNING, SAVE ALL WORK BEFORE DOING THIS.

On my local machine, this causes the machine to freeze, and Go finally performs a sigkill: 

```
signal: killed
FAIL      github.com/stacklok/minder/internal/controlplane          30.759s
FAIL
```
