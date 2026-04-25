# vLLM Allows Remote Code Execution via Mooncake Integration

**GHSA**: GHSA-x3m8-f7g5-qhm7 | **CVE**: CVE-2025-29783 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-502

**Affected Packages**:
- **vllm** (pip): >= 0.6.5, < 0.8.0

## Description

### Summary
When vLLM is configured to use Mooncake, unsafe deserialization exposed directly over ZMQ/TCP will allow attackers to execute remote code on distributed hosts.

### Details
1. Pickle deserialization vulnerabilities are [well documented](https://docs.python.org/3/library/pickle.html).
2. The [mooncake pipe](https://github.com/vllm-project/vllm/blob/9bebc9512f9340e94579b9bd69cfdc452c4d5bb0/vllm/distributed/kv_transfer/kv_pipe/mooncake_pipe.py#L206) is exposed over the network (by design to enable disaggregated prefilling across distributed environments) using ZMQ over TCP, greatly increasing exploitability. ~~Further, the mooncake integration opens these sockets listening on all interfaces on the host, meaning it can not be configured to only use a private, trusted network.~~

Only `sender_socket` and `receiver_ack` are allowed to be accessed publicly, while the data actually decompressed by `pickle.loads()` comes from [recv_bytes](https://github.com/vllm-project/vllm/blob/9bebc9512f9340e94579b9bd69cfdc452c4d5bb0/vllm/distributed/kv_transfer/kv_pipe/mooncake_pipe.py#L257). Its interface is defined as `self.receiver_socket.connect(f\"tcp://{d_host}:{d_rank_offset + 1}\")`, where `d_host` is `decode_host`, a locally defined address 192.168.0.139,from mooncake.json (https://github.com/kvcache-ai/Mooncake/blob/main/doc/en/vllm-integration-v0.2.md?plain=1#L36).

3. The root problem is [`recv_tensor()`](https://github.com/vllm-project/vllm/blob/9bebc9512f9340e94579b9bd69cfdc452c4d5bb0/vllm/distributed/kv_transfer/kv_pipe/mooncake_pipe.py#L257) calls [`_recv_impl`](https://github.com/vllm-project/vllm/blob/9bebc9512f9340e94579b9bd69cfdc452c4d5bb0/vllm/distributed/kv_transfer/kv_pipe/mooncake_pipe.py#L244) which passes the raw network bytes to `pickle.loads()`. Additionally, it does not appear that there are any controls (network, authentication, etc) to prevent arbitrary users from sending this payload to the affected service.



### Impact
This is a remote code execution vulnerability impacting any deployments using Mooncake to distribute KV across distributed hosts.

### Remediation
This issue is resolved by https://github.com/vllm-project/vllm/pull/14228
