# Rancher users who can create Projects can gain access to arbitrary projects

**GHSA**: GHSA-8h6m-wv39-239m | **CVE**: CVE-2024-22031 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-863

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.8.0, < 2.9.9
- **github.com/rancher/rancher** (go): >= 2.10.0, < 2.10.5
- **github.com/rancher/rancher** (go): >= 2.11.0, < 2.11.1

## Description

### Impact
A vulnerability has been identified within Rancher where a user with the ability to create a project, on a certain cluster, can create a project with the same name as an existing project in a different cluster. This results in the user gaining access to the other project in the different cluster, resulting in a privilege escalation. This happens because the namespace used on the local cluster to store related resources (PRTBs and secrets) is the name of the project.

Please consult the associated  [MITRE ATT&CK - Technique - Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) for further information about this category of attack.

### Patches
Patched versions include releases `v2.11.1`, `v2.10.5`, `v2.9.9`.

The fix involves the following changes:

**Rancher:**
- Instead of using the project name as the namespace, Rancher will instead be using a new field on the project spec called backingNamespace. If that field exists, use that for the project namespace going forward. However, if the project does not have that field filled out (likely because it existed before this change), Rancher will continue using the name for the namespace.

**Rancher Webhook:**
- New mutation on create `project.Status.BackingNamespace` to be `SafeConcatName(project.Spec.ClusterName, project.Name)`;
- Generate the name manually within the mutating webhook, because normally, name generation happens after the mutating webhooks;
- Removed a validation where `projectName` and `Namespace` had to be the same for PRTBs, since PRTBs now go in `project.BackingNamespace`;
- On update, if `BackingNamespace` isn't set, set it to `project.Name`. For existing objects after update this will help unify them to the new projects.
- The `BackingNamespace` can't be edited after it's set.

**Note: Rancher v2.8 release line does not have the fix for this CVE. The fix for v2.8 was considered too complex and with the risk of introducing instabilities right before this version goes into end-of-life (EOL), as documented in [SUSE’s Product Support Lifecycle](https://www.suse.com/lifecycle/#suse-rancher-prime) page. Please see the section below for workarounds or consider upgrading to a newer and patched version of Rancher.**

### Workarounds
If you can't upgrade to a fixed version, please make sure that:
- Users are not allowed to create projects with the same object names from another cluster.

To identify if this security issue could have been abused within your system, you need to find if there are any projects with the same name but on different clusters. To do that, run the following command in the local cluster as an administrator:
```
kubectl get projects -A -o=custom-columns='NAME:metadata.name' | sort | uniq -c
```

That command will list all project names, and show the instances of each name. Any project with more than 1 instance is affected by this security issue. To remedy the situation, the projects will need to be deleted and re-created to ensure no namespace collisions happen. While it would be possible to delete all but 1 of the projects with the same name, this is unadvisable because a user could have given themselves access to the wrong project.

### References
If you have any questions or comments about this advisory:
- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
