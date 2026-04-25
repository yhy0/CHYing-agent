# Users with any cluster secret update access may update out-of-bounds cluster secrets

**GHSA**: GHSA-3jfq-742w-xg8j | **CVE**: CVE-2023-23947 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/argoproj/argo-cd** (go): >= 2.3.0, < 2.3.17
- **github.com/argoproj/argo-cd** (go): >= 2.4.0, < 2.4.23
- **github.com/argoproj/argo-cd** (go): >= 2.5.0, < 2.5.11
- **github.com/argoproj/argo-cd** (go): >= 2.6.0, < 2.6.2

## Description

### Impact

All Argo CD versions starting with v2.3.0-rc1 are vulnerable to an improper authorization bug which allows users who have the ability to update at least one cluster secret to update any cluster secret.

The attacker could use this access to escalate privileges (potentially controlling Kubernetes resources) or to break Argo CD functionality (by preventing connections to external clusters).

#### How the Attack Works

Argo CD stores [cluster access configurations](https://argo-cd.readthedocs.io/en/stable/operator-manual/declarative-setup/#clusters) as Kubernetes Secrets. To take advantage of the vulnerability, an attacker must know the server URL for the cluster secret they want to modify. 

The attacker must be authenticated with the Argo CD API server, and they must be authorized to update at least one ([non project-scoped](https://argo-cd.readthedocs.io/en/stable/user-guide/projects/#project-scoped-repositories-and-clusters)) cluster. Then they must craft a malicious request to the Argo CD API server.

#### Removing Deployment Restrictions

A cluster Secret's `clusterResources` field determines whether Argo CD users may deploy cluster-scoped resources to that cluster. The `namespaces` field determines the namespaces to which Argo CD users may deploy resources.

You can use this command to determine whether any of your cluster configurations employ these restrictions (replace `argocd` with the namespace of your Argo CD installation):

```shell
kubectl get secret -n argocd -l 'argocd.argoproj.io/secret-type=cluster' -ojson | jq '.items |
  map(.data |= with_entries(.value |= @base64d)) |  # base64-decode secrets
  map(select(.data | (
    (.clusterResources != null and .clusterResources == "false") or # we deny cluster-scoped resource management
    (.namespaces != null and .namespaces != "")                     # we are only managing certain clusters
  )) | .metadata.name)'
```

The `clusterResources` and `namespaces` fields are one line of defense against unauthorized management of Kubernetes resources. Users should also have AppProject and RBAC restrictions in place.

If `clusterResources: "false"` or `namespaces: "some,namespaces"` are the _only_ mechanisms preventing an attacker from maliciously managing certain resources via Argo CD, then this vulnerability could allow that attacker to manage out-of-bounds resources via Argo CD (create, get, update, delete).

#### Modifying Connection Parameters

Cluster secrets also hold client configuration for connecting to the remote cluster. One option is to skip TLS certificate verification. An attacker could disable certificate verification in an effort to achieve a malicious-in-the-middle (MITM) attack.

Alternatively, an attacker could apply an invalid configuration (for example, by setting an invalid bearer token) and achieve a denial-of-service by preventing Argo CD from managing the target cluster.

#### Changing Unscoped Clusters to be Scoped

The vulnerability also allows an attacker to modify a previously-unscoped cluster and make it [scoped](https://argo-cd.readthedocs.io/en/stable/user-guide/projects/#project-scoped-repositories-and-clusters). This is important if you are using `permitOnlyProjectScopedClusters: true` in a project under which the attacker can deploy. By scoping a previously-unscoped cluster under that project, they can grant themselves the ability to manage resources on the target cluster.

### Patches

A patch for this vulnerability has been released in the following Argo CD versions:

* v2.6.2
* v2.5.11
* v2.4.23
* v2.3.17

### Workarounds

The best way to mitigate the vulnerability is to upgrade. The following two sections explain other ways to mitigate the vulnerability if you are currently unable to upgrade.

#### Limit Users with Cluster Update Access

The only complete mitigation besides upgrading is to modify your RBAC configuration to completely revoke all `clusters, update` access.

To exploit this vulnerability, an attacker must have access to update at least one cluster configuration. Check your [RBAC configuration](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/), for lines like this:

```
p, role:developers, clusters, update, *, allow
p, role:developers, clusters, *, *, allow
p, role:developers, *, update, *, allow
```

Revoke `clusters, update` access for any users who do not absolutely need that access.

#### Restrict Resource Management via AppProjects and RBAC

[AppProjects](https://argo-cd.readthedocs.io/en/stable/user-guide/projects/#projects) are a primary tool to restrict what resources may be managed via Argo CD.

You can use the `destinations` and `clusterResourceWhitelist` fields to apply similar restrictions as the `namespaces` and `clusterResources` fields described above.

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AppProject
spec:
  destinations:
  # Only allow Applications managed by this AppProject to manage to the `allowed-namespace` namespace.
  - namespace: 'allowed-namespace'
    server: 'https://your-server'
  # Do not allow Applications managed by this AppProject to manage any cluster-scoped resources.
  clusterResourceWhitelist: []
```

Along with adding AppProject restrictions, make sure that your RBAC restrictions are strict enough.

For example, limit `projects, update` access to Argo CD administrators only. Also use the `{project}` field in `applications, *, {project}/{application}` field to limit users' access to certain, restricted, AppProjects. 

AppProject restrictions can only prevent Applications from managing out-of-bounds resources. It cannot prevent an attacker from maliciously changing cluster connection TLS configuration.

### For more information

* Open an issue in [the Argo CD issue tracker](https://github.com/argoproj/argo-cd/issues) or [discussions](https://github.com/argoproj/argo-cd/discussions)
* Join us on [Slack](https://argoproj.github.io/community/join-slack) in channel #argo-cd

