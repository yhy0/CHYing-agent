# Remote Code Execution Vulnerability in vLLM Multi-Node Cluster Configuration

**GHSA**: GHSA-9pcc-gvx5-r5wm | **CVE**: CVE-2025-30165 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-502

**Affected Packages**:
- **vllm** (pip): >= 0.5.2, < 0.10.0

## Description

### Affected Environments

Note that this issue only affects the V0 engine, which has been off by default since v0.8.0. Further, the issue only applies to a deployment using tensor parallelism across multiple hosts, which we do not expect to be a common deployment pattern.

Since V0 is has been off by default since v0.8.0 and the fix is fairly invasive, we have decided not to fix this issue. Instead we recommend that users ensure their environment is on a secure network in case this pattern is in use.

The V1 engine is not affected by this issue.

### Impact

In a multi-node vLLM deployment using the V0 engine, vLLM uses ZeroMQ for some multi-node communication purposes. The secondary vLLM hosts open a `SUB` ZeroMQ socket and connect to an `XPUB` socket on the primary vLLM host.

https://github.com/vllm-project/vllm/blob/c21b99b91241409c2fdf9f3f8c542e8748b317be/vllm/distributed/device_communicators/shm_broadcast.py#L295-L301

When data is received on this `SUB` socket, it is deserialized with `pickle`. This is unsafe, as it can be abused to execute code on a remote machine.

https://github.com/vllm-project/vllm/blob/c21b99b91241409c2fdf9f3f8c542e8748b317be/vllm/distributed/device_communicators/shm_broadcast.py#L468-L470

Since the vulnerability exists in a client that connects to the primary vLLM host, this vulnerability serves as an escalation point. If the primary vLLM host is compromised, this vulnerability could be used to compromise the rest of the hosts in the vLLM deployment.

Attackers could also use other means to exploit the vulnerability without requiring access to the primary vLLM host. One example would be the use of ARP cache poisoning to redirect traffic to a malicious endpoint used to deliver a payload with arbitrary code to execute on the target machine.
