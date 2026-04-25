# Rancher Webhook is misconfigured during upgrade process

**GHSA**: GHSA-6m9f-pj6w-w87g | **CVE**: CVE-2023-22651 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-269, CWE-276

**Affected Packages**:
- **github.com/rancher/rancher** (go): = 2.7.2
- **github.com/rancher/rancher** (go): >= 0.0.0-20220922131902-ec6d6d3a7616, < 0.0.0-20230424183121-6d9a175954c6

## Description

### Impact

A failure in the update logic of Rancher's admission Webhook may lead to the misconfiguration of the Webhook. This component enforces validation rules and security checks before resources are admitted into the Kubernetes cluster.

When the Webhook is operating in a degraded state, it no longer validates any resources, which may result in severe privilege escalations and data corruption.

The issue only affects users that upgrade from `2.6.x` or `2.7.x` to `2.7.2`. Users that did a fresh install of 2.7.2 (and did not follow an upgrade path) are not affected.

The command below can be executed on the `local` cluster to determine whether the cluster is affected by this issue:

```sh
$ kubectl get validatingwebhookconfigurations.admissionregistration.k8s.io rancher.cattle.io

NAME                WEBHOOKS   AGE
rancher.cattle.io   0         19h
```

If the resulting webhook quantity is `0`, the Rancher instance is affected.

### Patches

Patched versions include release `2.7.3` and later versions.

### Workarounds

If you are affected and cannot update to a patched Rancher version, the recommended workaround is to manually reconfigure the Webhook with the script below. Please note that the script must be run from inside the `local` cluster or with a kubeconfig pointing to the `local` cluster which has admin permissions.

```yaml
#!/bin/bash

set -euo pipefail

function prereqs() {
    if ! [ -x "$(command -v kubectl)" ]; then
      echo "error: kubectl is not installed." >&2
      exit 1
    fi

    if [[ -z "$(kubectl config view -o jsonpath='{.clusters[].cluster.server}')" ]]; then
        echo "error: No kubernetes cluster found on kubeconfig." >&2
        exit 1
    fi
}

function restart_deployment(){
    kubectl rollout restart deployment rancher-webhook -n cattle-system
    kubectl rollout status deployment rancher-webhook -n cattle-system --timeout=30s
}

function workaround() {
    echo "Cluster: $(kubectl config view -o jsonpath='{.clusters[].cluster.server}')"

    if ! kubectl get validatingwebhookconfigurations.admissionregistration.k8s.io rancher.cattle.io > /dev/null 2>&1; then
        echo "webhook rancher.cattle.io not found, restarting deployment:"
        restart_deployment

        echo "waiting for webhook configuration"
        sleep 15s
    fi

    local -i webhooks
    webhooks="$(kubectl get validatingwebhookconfigurations.admissionregistration.k8s.io rancher.cattle.io --no-headers | awk '{ print $2 }')"

    if [ "${webhooks}" == "0" ]; then
        echo "Webhook misconfiguration status: Cluster is affected by CVE-2023-22651"
        
        echo "Running workaround:"
        kubectl delete validatingwebhookconfiguration rancher.cattle.io
        restart_deployment

        ret=$?
        if [ $ret -eq 0 ]; then
            echo "Webhook restored, CVE-2023-22651 is fixed"
        else
            echo "error trying to restart deployment. try again in a few seconds."
        fi
    else
        echo "Webhook misconfiguration status: not present (skipping)"
    fi

    echo "Done"
}

function main() {
    prereqs
    workaround
}

main
```

### References
- https://github.com/rancher/webhook/pull/216/commits/a4a498613b43a3ee93c5ab06742a3bc8adace45d

### For more information
If you have any questions or comments about this advisory:

- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
