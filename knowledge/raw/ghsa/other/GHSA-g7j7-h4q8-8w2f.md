# Rancher API and cluster.management.cattle.io object vulnerable to plaintext storage and exposure of credentials

**GHSA**: GHSA-g7j7-h4q8-8w2f | **CVE**: CVE-2021-36782 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-312

**Affected Packages**:
- **github.com/rancher/rancher** (go): >= 2.5.0, < 2.5.16
- **github.com/rancher/rancher** (go): >= 2.6.0, < 2.6.7

## Description

### Impact
An issue was discovered in Rancher versions up to and including 2.5.15 and 2.6.6 where sensitive fields, like passwords, API keys and Rancher's service account token (used to provision clusters), were stored in plaintext directly on Kubernetes objects like `Clusters`, for example `cluster.management.cattle.io`. Anyone with read access to those objects in the Kubernetes API could retrieve the plaintext version of those sensitive data.

The exposed credentials are visible in Rancher to authenticated `Cluster Owners`, `Cluster Members`, `Project Owners`, `Project Members` and `User Base` on the endpoints:
- `/v1/management.cattle.io.catalogs`
- `/v1/management.cattle.io.cluster`
- `/v1/management.cattle.io.clustertemplates`
- `/v1/management.cattle.io.notifiers`
- `/v1/project.cattle.io.sourcecodeproviderconfig`
- `/k8s/clusters/local/apis/management.cattle.io/v3/catalogs`
- `/k8s/clusters/local/apis/management.cattle.io/v3/clusters`
-  `/k8s/clusters/local/apis/management.cattle.io/v3/clustertemplates`
- `/k8s/clusters/local/apis/management.cattle.io/v3/notifiers`
- `/k8s/clusters/local/apis/project.cattle.io/v3/sourcecodeproviderconfigs`

Sensitive fields are now stripped from `Clusters` and other objects and moved to a `Secret` before the object is stored. The `Secret` is retrieved when the credential is needed. For objects that existed before this security fix, a one-time migration happens on startup.

**Important:**
- The exposure of Rancher's `serviceAccountToken` allows any standard user to escalate its privileges to cluster administrator in Rancher.
- For the exposure of credentials not related to Rancher, the final impact severity for confidentiality, integrity and availability is dependent on the permissions that the leaked credentials have on their own services.

The fields that have been addressed by this security fix are:

- `Notifier.SMTPConfig.Password`
- `Notifier.WechatConfig.Secret`
- `Notifier.DingtalkConfig.Secret`
- `Catalog.Spec.Password`
- `SourceCodeProviderConfig.GithubPipelineConfig.ClientSecret`
- `SourceCodeProviderConfig.GitlabPipelineConfig.ClientSecret`
- `SourceCodeProviderConfig.BitbucketCloudPipelineConfig.ClientSecret`
- `SourceCodeProviderConfig.BitbucketServerPipelineConfig.PrivateKey`
- `Cluster.Spec.RancherKubernetesEngineConfig.BackupConfig.S3BackupConfig.SecretKey`
- `Cluster.Spec.RancherKubernetesEngineConfig.PrivateRegistries.Password`
- `Cluster.Spec.RancherKubernetesEngineConfig.Network.WeaveNetworkProvider.Password`
- `Cluster.Spec.RancherKubernetesEngineConfig.CloudProvider.VsphereCloudProvider.Global.Password`
- `Cluster.Spec.RancherKubernetesEngineConfig.CloudProvider.VsphereCloudProvider.VirtualCenter.Password`
- `Cluster.Spec.RancherKubernetesEngineConfig.CloudProvider.OpenstackCloudProvider.Global.Password`
- `Cluster.Spec.RancherKubernetesEngineConfig.CloudProvider.AzureCloudProvider.AADClientSecret`
- `Cluster.Spec.RancherKubernetesEngineConfig.CloudProvider.AzureCloudProvider.AADClientCertPassword`
- `Cluster.Status.ServiceAccountToken`
- `ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.PrivateRegistries.Password`
- `ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.Network.WeaveNetworkProvider.Password`
- `ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.CloudProvider.VsphereCloudProvider.Global.Password`
- `ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.CloudProvider.VsphereCloudProvider.VirtualCenter.Password`
- `ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.CloudProvider.OpenstackCloudProvider.Global.Password`
- `ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.CloudProvider.AzureCloudProvider.AADClientSecret`
- `ClusterTemplate.Spec.ClusterConfig.RancherKubernetesEngineConfig.CloudProvider.AzureCloudProvider.AADClientCertPassword`

### Patches
Patched versions include releases 2.5.16, 2.6.7 and later versions.

After upgrading to a patched version, it is important to check for the `SecretsMigrated` condition on `Clusters`, `ClusterTemplates`, and `Catalogs` to confirm when secrets have been fully migrated off of those objects and the objects scoped within them (`Notifiers` and `SourceCodeProviderConfigs`).

### Workarounds
Limit access in Rancher to trusted users. There is not a direct mitigation besides upgrading to the patched Rancher versions.

**Important:**
- It is highly advised to rotate Rancher's `serviceAccountToken`. This rotation is not done by the version upgrade. Please see the helper script below.
- The local and downstream clusters should be checked for potential unrecognized services (pods), users and API keys.
- It is recommended to review for potential leaked credentials in this scenario, that are not directly related to Rancher, and to change them if deemed necessary.

The script available in [rancherlabs/support-tools/rotate-tokens](https://github.com/rancherlabs/support-tools/blob/master/rotate-tokens) repository can be used as a helper to rotate the service account token (used to provision clusters). The script requires a valid Rancher API token, `kubectl` access to the `local` cluster and the `jq` command.

### Credits
We would like to recognize and appreciate Florian Struck (from [Continum AG](https://www.continum.net/)) and [Marco Stuurman](https://github.com/fe-ax) (from [Shock Media B.V.](https://www.shockmedia.nl)) for the responsible disclosure of this security issue.

### For more information
If you have any questions or comments about this advisory:
* Reach out to [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
* Open an issue in [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
* Verify our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
