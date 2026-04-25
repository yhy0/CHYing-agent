# Argo CD will blindly trust JWT claims if anonymous access is enabled

**GHSA**: GHSA-r642-gv9p-2wjj | **CVE**: CVE-2022-29165 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-200, CWE-287, CWE-290

**Affected Packages**:
- **github.com/argoproj/argo-cd/v2** (go): >= 2.3.0, < 2.3.4
- **github.com/argoproj/argo-cd/v2** (go): >= 2.2.0, < 2.2.9
- **github.com/argoproj/argo-cd/v2** (go): < 2.1.15
- **github.com/argoproj/argo-cd** (go): <= 1.8.7

## Description

### Impact

A critical vulnerability has been discovered in Argo CD which would allow unauthenticated users to impersonate as any Argo CD user or role, including the `admin` user, by sending a specifically crafted JSON Web Token (JWT) along with the request. In order for this vulnerability to be exploited, [anonymous access](https://argo-cd.readthedocs.io/en/stable/operator-manual/rbac/#anonymous-access) to the Argo CD instance must have been enabled. 

In a default Argo CD installation, anonymous access is disabled. To find out if anonymous access is enabled in your instance, please see the *Workarounds* section of this advisory below.

The vulnerability can be exploited to impersonate as any user or role, including the built-in `admin` account regardless of whether that account is enabled or disabled. Also, the attacker does not need an account on the Argo CD instance in order to exploit this.

If anonymous access to the instance is enabled, an attacker can:

* Escalate their privileges, effectively allowing them to gain the same privileges on the cluster as the Argo CD instance, which is cluster admin in a default installation. This will allow the attacker to create, manipulate and delete any resource on the cluster.

* Exfiltrate data by deploying malicious workloads with elevated privileges, thus bypassing any redaction of sensitive data otherwise enforced by the Argo CD API

We **strongly recommend** that all users of Argo CD update to a version containing this patch as soon as possible, regardless of whether or not anonymous access is enabled in your instance.

Please see below for a list of versions containing a fix for this vulnerability and any possible workarounds existing for this issue.

### Patches

A patch for this vulnerability has been released in the following Argo CD versions:

* v2.3.4
* v2.2.9
* v2.1.15

### Workarounds

#### Disable anonymous access

If you are not able to upgrade to a patched version quickly, we highly suggest disabling anonymous access if it is enabled. 

To find out whether anonymous access is enabled for your Argo CD instance, you can query the `argocd-cm` ConfigMap in the Argo CD's installation namespace. The below example assumes you have installed Argo CD to the `argocd` namespace:

```shell
$ kubectl get -n argocd cm argocd-cm -o jsonpath='{.data.users\.anonymous\.enabled}'
```

If the result of this command is either empty or `"false"`, anonymous access to that instance is not enabled. If the result is `"true"`, your instance is vulnerable.

To disable anonymous access, patch the `argocd-cm` ConfigMap to either remove the `users.anonymous.enabled` field or set this field to `"false"`. 

To set the field to `"false"`:

```shell
$ kubectl patch -n argocd cm argocd-cm --type=json -p='[{"op":"add", "path":"/data/users.anonymous.enabled", "value":"false"}]'
```
Or you can remove the field completely, thus disabling anonymous access because the default is `false`:

```shell
$ kubectl patch -n argocd cm argocd-cm --type=json -p='[{"op":"remove", "path":"/data/users.anonymous.enabled"}]'
```

### Credits

The Argo CD team would like to thank Mark Pim and Andrzej Hajto, who discovered this vulnerability and reported it in a responsible way to us.

### For more information

* Open an issue in [the Argo CD issue tracker](https://github.com/argoproj/argo-cd/issues) or [discussions](https://github.com/argoproj/argo-cd/discussions)
* Join us on [Slack](https://argoproj.github.io/community/join-slack) in channel #argo-cd
