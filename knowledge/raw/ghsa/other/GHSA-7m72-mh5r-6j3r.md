# Privilege escalation in project role template binding (PRTB) and -promoted roles

**GHSA**: GHSA-7m72-mh5r-6j3r | **CVE**: CVE-2022-43759 | **Severity**: high (CVSS 7.2)

**CWE**: CWE-269, CWE-284

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.5.0, < 2.5.17
- **github.com/rancher/rancher** (go): >= 2.6.0, < 2.6.10

## Description

### Impact

An issue was discovered in Rancher versions from 2.5.0 up to and including 2.5.16 and from 2.6.0 up to and including 2.6.9, where an authorization logic flaw allows privilege escalation via project role template binding (PRTB) and `-promoted` roles. This issue is not present in Rancher 2.7 releases.

Note: Consult Rancher [documentation](https://ranchermanager.docs.rancher.com/how-to-guides/new-user-guides/authentication-permissions-and-global-configuration/manage-role-based-access-control-rbac/cluster-and-project-roles) for more information about cluster and project roles and [KB 000020097](https://www.suse.com/support/kb/doc/?id=000020097) for information about `-promoted` roles.

This privilege escalation is possible for users with access to the `escalate` verb on PRTBs (`projectroletemplatebindings.management.cattle.io`), including users with `*` verbs on PRTBs (see notes below for more information). These users can escalate permissions for any `-promoted` resource (see the table below for a full enumeration) in any cluster where they have a PRTB granting such permissions in at least one project in the cluster.

On a default Rancher setup, only the following roles have such permissions:

1. Project Owner
2. Manage Project Members

These roles have permissions to affect the following resources:

| Resource | API Group | Affected Rancher version |
| - | - | - |
| navlinks | ui.cattle.io | 2.6 |
| nodes | "" | 2.6 |
| persistentvolumes | "" | 2.5, 2.6 |
| persistentvolumes | core | 2.5, 2.6 |
| storageclasses | storage.k8s.io | 2.5, 2.6 |
| apiservices | apiregistration.k8s.io | 2.5, 2.6 |
| clusterrepos | catalog.cattle.io | 2.5, 2.6 |
| clusters (`local` only) | management.cattle.io | 2.5, 2.6 |

Notes:

1. During the calculation of the CVSS score, `privileges required` was considered  as `high` because, by default, `standard user` and `user-base` users in Rancher do not have  `create`, `patch` and `update` permissions on `roletemplates`.
2. If a role template with access to those objects was already created by another user in the cluster, then this issue can be exploited by users without the mentioned permissions from point 1.

### Workarounds

If updating Rancher to a patched version is not possible, then the following workarounds must be observed to mitigate this issue:

1. Only grant Project Owner and Manage Project Members roles to trusted users.
5. Minimize the creation of custom roles that contain the `escalate`, `*` or write verbs (`create`, `delete`, `patch`, `update`) on `projectroletemplatebindings` resource, and only grant such custom roles to trusted users.
6. Minimize the number of users that have permissions to `create`, `patch` and `update` `roletemplates`.

### Patches

Patched versions include releases 2.5.17 and 2.6.10 and later versions. This issue is not present in Rancher 2.7 releases.

### Detection

The following script was developed to list role template bindings that give written access to the affected resources listed above. It is highly recommended to run the script in your environment and review the list of identified roles and role template bindings for possible signs of exploitation of this issue. The script requires `jq` installed and a `kubeconfig` with access to Rancher local cluster; it can also be executed in Rancher's kubectl shell.

```shell
#!/bin/bash

help="
Usage: bash find_promoted_resource.sh \n \n

Requires: \n
- jq installed and on path \n
- A kubeconfig pointing at rancher's local cluster (can also run from rancher's kubectl shell) \n \n

Outputs a list of roletemplates and roletemplate bindings which give write access to promoted resources.
"

if [[ $1 == "-h" || $1 == "--help" ]]
then
	echo -e $help
	exit 0
fi

# first, get the current roletemplates so that we only issue a get once
kubectl get roletemplates.management.cattle.io -o json >> script_templates.json

# find roles which have write access to a promoted resource. Filter on roleTemplates which fulfill all requirements:
# Have a project context
# Have some rules
# Have one/more of the target api groups, or a * in the api groups
# Have one/more of the target resources, or a * in the resources
# Have a verb that is not read access (i.e. a verb that is not get/list/watch)
roles=$(jq --argjson apiGroups '["", "ui.cattle.io", "core", "storage.k8s.io", "apiregistration.k8s.io", "catalog.cattle.io", "management.cattle.io"]' --argjson resources '["navlinks", "persistentvolumes", "nodes", "storageclasses", "apiservices", "clusterrepos", "clusters"]' --argjson verbs '["get", "list", "watch"]' '.items[] | select(.context=="project" and (.rules | length >= 1)) | select( .rules[] | select( (($apiGroups - .apiGroups | length < 7) or (.apiGroups | index("*"))) and (($resources - .resources | length < 7) or (.resources | index("*"))) and (.verbs - $verbs  | length > 0)) | length >= 1 ) | .metadata.name' script_templates.json | jq -s )

# log promoted roles which give direct write access so they can be easily fixed
echo "The following role templates give direct write access to a promoted resource:"
echo $roles
echo -e ""

# find any roles which inherit first-level roles. Mostly a BFS which radiates outward from the known bad roles 
old_roles="[]"
new_roles="$roles"
old_length=$(echo $old_roles | jq 'length')
new_length=$(echo $new_roles | jq 'length')
# if our last loop found nothing new, it's safe to stop
while [[ $old_length != $new_length ]];
do
	# set old values to what we currently know about
	old_roles=$new_roles
	old_length=$new_length
	# update new values with anything that inherits a "bad" role we know about
	new_roles=$(jq --argjson roles "$old_roles" --argjson roleLen "$old_length" '.items[] | .metadata.name as $NAME | select (( $roles | index($NAME)) or ((.roleTemplateNames | length > 0 ) and ($roles - .roleTemplateNames | length < $roleLen))) | .metadata.name ' script_templates.json | jq -s)
	new_length=$(echo $new_roles | jq 'length')
done

roles=$new_roles

# log all roles which can give write access, even if it's not first level
echo -e "The following role templates give write access to a promoted resource directly or through inheritance:"
echo $roles
echo -e ""

kubectl get projectroletemplatebindings.management.cattle.io -A -o json >> script_bindings.json
role_template_bindings=$(jq --argjson roleTemplates "$roles" '.items[] | .roleTemplateName as $TemplateName | select($roleTemplates | index($TemplateName)) | .metadata.name' script_bindings.json | jq -s)

# since these bindings could be for users or groups, we need to include all fields which could help identify the subject. But they won't all be present, which makes the list look less pretty
echo -e "The following is a list of bindings which give access to promoted resource, with the format of: bindingName, projectName, userName, userPrincipalName, groupName, groupPrincipalName: "
echo $(jq --argjson bindings "$role_template_bindings" '.items[] | .metadata.name as $BindingName | select ( $bindings | index($BindingName)) | .metadata.name, .projectName, .userName?, .userPrincipalName?, .groupName?, .groupPrincipalName?' script_bindings.json | jq -s)

unset old_roles
unset new_roles
unset roles
unset role_template_bindings
rm script_templates.json
rm script_bindings.json
```

### For more information

If you have any questions or comments about this advisory:

* Reach out to [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
* Open an issue in [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
* Verify our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/)
