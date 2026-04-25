# RBAC Roles for `etcd` created by Kamaji are not disjunct

**GHSA**: GHSA-6r4j-4rjc-8vw5 | **CVE**: CVE-2024-42480 | **Severity**: critical (CVSS 8.1)

**CWE**: CWE-284

**Affected Packages**:
- **github.com/clastix/kamaji** (go): <= 1.0.0

## Description

### Summary
_Using an "open at the top" range definition in RBAC for etcd roles leads to some TCPs API servers being able to read, write and delete the data of other control planes._

### Details

The problematic code is this: https://github.com/clastix/kamaji/blob/8cdc6191242f80d120c46b166e2102d27568225a/internal/datastore/etcd.go#L19-L24

The range created by this RBAC setup code looks like this:

```
etcdctl role get example
Role example
KV Read:
	[/example/, \0)
KV Write:
	[/example/, \0)
```

The range end `\0` means "everything that comes after" in etcd, so potentially all the key prefixes of controlplanes with a name that comes after "example" when sorting lexically (e.g. `example1`, `examplf`, all the way to `zzzzzzz` if you will).

### PoC

1. Create two TCP in the same Namespace
2. Scale Kamaji to zero to avoid reconciliations
3. change the Kubernetes API Server `--etcd-prefix` flag value  to point to the other TCP datastore key
4. wait it for get it up and running
5. use `kubectl` and will notice you're reading and writing data of another Tenant

### Impact

Full control over other TCPs data, if you are able to obtain the name of other TCPs that use the same datastore and are able to obtain the user certificates used by your control plane (or you are able to configure the kube-apiserver Deployment, as shown in the PoC).

