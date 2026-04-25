# Controller reconciles apps outside configured namespaces when sharding is enabled

**GHSA**: GHSA-6p4m-hw2h-6gmw | **CVE**: CVE-2023-22736 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-862

**Affected Packages**:
- **github.com/argoproj/argo-cd/v2** (go): >= 2.5.0-rc1, < 2.5.8
- **github.com/argoproj/argo-cd/v2** (go): = 2.6.0-rc4

## Description

### Impact

All Argo CD versions starting with 2.5.0-rc1 are vulnerable to an authorization bypass bug which allows a malicious Argo CD user to deploy Applications outside the configured allowed namespaces. 

#### Description of exploit

Reconciled Application namespaces are specified as a comma-delimited list of glob patterns. When sharding is enabled on the Application controller, it does not enforce that list of patterns when reconciling Applications. For example, if Application namespaces are configured to be `argocd-*`, the Application controller may reconcile an Application installed in a namespace called `other`, even though it does not start with `argocd-`.

Reconciliation of the out-of-bounds Application is only triggered when the Application is updated, so the attacker must be able to cause an update operation on the Application resource.

#### Limitations

This bug only applies to users who have explicitly enabled the "apps-in-any-namespace" feature by setting `application.namespaces` in the argocd-cmd-params-cm ConfigMap or otherwise setting the `--application-namespaces` flags on the Application controller and API server components. The apps-in-any-namespace feature is in beta as of this Security Advisory's publish date.

The bug is also limited to Argo CD instances where sharding is enabled by increasing the `replicas` count for the Application controller.

Finally, the AppProjects' `sourceNamespaces` field acts as a secondary check against this exploit. To cause reconciliation of an Application in an out-of-bounds namespace, an AppProject must be available which permits Applications in the out-of-bounds namespace.

### Patches

A patch for this vulnerability has been released in the following Argo CD versions:

* v2.5.8
* v2.6.0-rc5

### Workarounds

Running only one replica of the Application controller will prevent exploitation of this bug.

Making sure all AppProjects' `sourceNamespaces` are restricted within the confines of the configured Application namespaces will also prevent exploitation of this bug.

### Credits

Thanks to ChangZhuo Chen (@czchen) for finding the issue and for contributing the fix!

### References

* [Documentation for apps-in-any-namespace](https://argo-cd--10678.org.readthedocs.build/en/10678/operator-manual/app-any-namespace/)

### For more information

* Open an issue in [the Argo CD issue tracker](https://github.com/argoproj/argo-cd/issues) or [discussions](https://github.com/argoproj/argo-cd/discussions)
* Join us on [Slack](https://argoproj.github.io/community/join-slack) in channel #argo-cd
