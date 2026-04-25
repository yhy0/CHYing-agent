# Rancher does not properly specify ApiGroup when creating Kubernetes RBAC resources

**GHSA**: GHSA-f9xf-jq4j-vqw4 | **CVE**: CVE-2021-25318 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-732

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.0.0, < 2.4.16
- **github.com/rancher/rancher** (go): >= 2.5.0, < 2.5.9

## Description

A vulnerability was discovered in Rancher versions 2.0 through the aforementioned fixed versions, where users were granted access to resources regardless of the resource's API group. For example Rancher should have allowed users access to `apps.catalog.cattle.io`, but instead incorrectly gave access to `apps.*`. Resource affected include: 

**Downstream clusters:**
apiservices
clusters
clusterrepos
persistentvolumes
storageclasses

**Rancher management cluster**
apprevisions
apps
catalogtemplates
catalogtemplateversions
clusteralertgroups
clusteralertrules
clustercatalogs
clusterloggings
clustermonitorgraphs
clusterregistrationtokens
clusterroletemplatebindings
clusterscans
etcdbackups
nodepools
nodes
notifiers
pipelineexecutions
pipelines
pipelinesettings
podsecuritypolicytemplateprojectbindings
projectalertgroups
projectalertrules
projectcatalogs
projectloggings
projectmonitorgraphs
projectroletemplatebindings
projects
secrets
sourcecodeproviderconfigs

There is not a direct mitigation besides upgrading to the patched Rancher versions.
