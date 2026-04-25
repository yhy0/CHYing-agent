# rke's credentials are stored in the RKE1 Cluster state ConfigMap

**GHSA**: GHSA-6gr4-52w6-vmqx | **CVE**: CVE-2023-32191 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-922

**Affected Packages**:
- **github.com/rancher/rke** (go): >= 1.4.18, < 1.4.19
- **github.com/rancher/rke** (go): >= 1.5.9, < 1.5.10

## Description

### Impact

When RKE provisions a cluster, it stores the cluster state in a configmap called `full-cluster-state` inside the `kube-system` namespace of the cluster itself. This cluster state object contains information used to set up the K8s cluster, which may include the following sensitive data:

- RancherKubernetesEngineConfig
   - RKENodeConfig
       - SSH username
       - SSH private key
       - SSH private key path
   - RKEConfigServices
       - ETCDService
           - External client key
           - BackupConfig
               - S3BackupConfig
                   - AWS access key
                   - AWS secret key
       - KubeAPIService
           - SecretsEncryptionConfig
               - K8s encryption configuration (contains encryption keys)
   - PrivateRegistries
       - User
       - Password
       - ECRCredentialPlugin
           - AWS access key
           - AWS secret key
           - AWS session token
   - CloudProvider
       - AzureCloudProvider
           - AAD client ID
           - AAD client secret
           - AAD client cert password
       - OpenstackCloudProvider
           - Username
           - User ID
           - Password
       - VsphereCloudProvider
           - GlobalVsphereOpts
               - User
               - Password
           - VirtualCenterConfig
               - User
               - Password
       - HarvesterCloudProvider
           - CloudConfig
       - CustomCloudProvider
   - BastionHost
       - User
       - SSH key
- CertificatesBundle
   - Private key
- EncryptionConfig
   - Private key


The `State` type that contains the above info and more can viewed [here](https://github.com/rancher/rke/blob/8714c3c06e0bad55c61684fd5d94f1481128c58d/cluster/state.go#L37).

While the `full-cluster-state` configmap is not publicly available (reading it requires access to the RKE cluster), it being a configmap makes it available to non-administrators of the cluster. Because this configmap contains essentially all the information and credentials required to administer the cluster, anyone with permission to read it thereby achieves admin-level access to the cluster (please consult the [MITRE ATT&CK - Technique - Unsecured Credentials : Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) for further information about the associated technique of attack).


**Important:**
For the exposure of credentials not related to Rancher and RKE, the final impact severity for confidentiality, integrity and availability is dependent on the permissions the leaked credentials have on their services. 


It is recommended to review for potentially leaked credentials in this scenario and to change them if deemed necessary.


### Patches

This vulnerability is being fixed in RKE versions `1.4.19` and `1.5.10` which are included in Rancher versions `2.7.14` and `2.8.5`.


The patches include changes that will cause RKE to automatically migrate the cluster state configmap to a `full-cluster-state` secret in the `kube-system` namespace. The migrated secret will only be accessible to those who have read access to the `kube-system` namespace in the downstream RKE cluster. In Rancher, only admin and cluster-owner roles can access the secret. The old configmap will be removed after successful migration.


All downstream clusters provisioned using RKE via Rancher will be migrated automatically on Rancher upgrade. Note that any downstream clusters that are unavailable or otherwise non migratable on Rancher upgrade will still be migrated automatically as soon as they become available.


Clusters provisioned using RKE outside of Rancher will be migrated automatically upon the next invocation of `rke up` (i.e. the next cluster reconciliation) after upgrading RKE.


If a rollback needs to be performed after an upgrade to a patched Rancher or RKE version, downstream RKE clusters that were migrated need to have their migrations manually reversed using this script: https://github.com/rancherlabs/support-tools/tree/master/reverse-rke-state-migrations. 
**Please be sure to back up downstream clusters before performing the reverse migration**.


### Workarounds

There are no workarounds for this issue. Users are recommended to upgrade, as soon as possible, to a version of RKE/Rancher Manager which contains the fixes.


Users should not attempt to perform this migration manually without upgrading their RKE/Rancher versions as only post-patch versions of RKE are capable of reading the cluster state from a secret instead of a configmap. In other words, migrating the cluster state to a secret without upgrading RKE/Rancher would cause RKE to be unable to read the cluster state, making it incapable of managing the cluster until an RKE/Rancher upgrade is performed.


### For more information

If you have any questions or comments about this advisory:


- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rancher/security/policy) for security related inquiries.
- Open an issue in the [Rancher](https://github.com/rancher/rancher/issues/new/choose) repository.
- Verify our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support life cycle](https://www.suse.com/lifecycle/).

