# RKE2 supervisor port is vulnerable to unauthenticated remote denial-of-service (DoS) attack via TLS SAN stuffing attack

**GHSA**: GHSA-p45j-vfv5-wprq | **CVE**: CVE-2023-32186 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-770

**Affected Packages**:
- **github.com/rancher/rke2** (go): < 1.24.17
- **github.com/rancher/rke2** (go): >= 1.25.0, < 1.25.13
- **github.com/rancher/rke2** (go): >= 1.26.0, < 1.26.8
- **github.com/rancher/rke2** (go): >= 1.27.0, < 1.27.5
- **github.com/rancher/rke2** (go): >= 1.28.0, < 1.28.1

## Description

### Impact

An issue was found in RKE2 where an attacker with network access to RKE2 servers' supervisor port (TCP 9345) can force the TLS server to add entries to the certificate's Subject Alternative Name (SAN) list, through a stuffing attack, until the certificate grows so large that it exceeds the maximum size allowed by TLS client implementations. OpenSSL for example will raise an `excessive message size` error when this occurs. No authentication is necessary to perform this attack, only the ability to perform a TLS handshake against the supervisor port (TCP 9345).

Affected servers will continue to operate, but clients (server or agent nodes) will fail to establish new connections when joining or rejoining the cluster, thus leading to a denial of service (DoS) attack.

### Remediation

Upgrade to a fixed release:
- v1.28.1+rke2r1
- v1.27.5+rke2r1
- v1.26.8+rke2r1
- v1.25.13+rke2r1
- 1.24.17+rke2r1

If you are using RKE2 1.27 or earlier, you must also add the parameter `tls-san-security: true` to the RKE2 configuration to enable enhanced security for the supervisor's TLS SAN list. This option defaults to `true` starting with RKE2 1.28.

Note that this flag changes the behavior of RKE2's supervisor listener. You should ensure that you configure `node-external-ip` on servers that will be connected to via an external IP, and add `tls-san` entries for any load-balancers or VIP addresses that will be associated with the supervisor port. External IPs and load-balancer/VIP addresses will no longer be added to the supervisor certificate's SAN list unless explicitly configured.

### Mitigation

If you cannot upgrade to a fixed release, the certificate can be "frozen" by running the following command against the cluster:

```shell
kubectl annotate secret -n kube-system rke2-serving listener.cattle.io/static=true
```

**⚠️ IMPORTANT CAUTION:** Note that this mitigation will prevent the certificate from adding new SAN entries when servers join the cluster, and automatically renewing itself when it is about to expire. If you do this, you should delete the annotation when adding new servers to the cluster, or when the certificate is within 90 days of expiring, so that it can be updated. Once that is done, you can freeze it again.

Affected certificates can be reset by performing the following steps:
* Run `kubectl delete secret -n kube-system rke2-serving`
* Delete `/var/lib/rancher/rke2/server/tls/dynamic-cert.json` from all servers, and restart the `rke2-server` service.

### Background

The RKE2 supervisor listens on port TCP 9345 and uses the `rancher/dynamiclistener` library to dynamically generate TLS certificates that contain TLS Subject Alternative Names (SAN) for any host name or IP address requested by a client. This is done to allow servers and external load-balancers to be added to the cluster without the administrator having to explicitly know and configure in advance a fixed list of endpoints that the supervisor may be hosted at.

The library allows the embedding application to configure a callback that is used to filter addresses requested by clients; but this was not previously implemented in RKE2.

### For more information

If you have any questions or comments about this advisory:

- Reach out to the [SUSE Rancher Security team](https://github.com/rancher/rke2/security/policy) for security related inquiries.
- Open an issue in the [RKE2](https://github.com/rancher/rke2/issues/new/choose) repository.
- Verify with our [support matrix](https://www.suse.com/suse-rancher/support-matrix/all-supported-versions/) and [product support lifecycle](https://www.suse.com/lifecycle/).
