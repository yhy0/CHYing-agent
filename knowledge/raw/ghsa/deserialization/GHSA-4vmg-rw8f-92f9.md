# Withdrawn Advisory: PyTorch deserialization vulnerability

**GHSA**: GHSA-4vmg-rw8f-92f9 | **CVE**: CVE-2024-7804 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **torch** (pip): <= 2.3.1

## Description

## Withdrawn Advisory
This advisory has been withdrawn because it describes known functionality of PyTorch. This link is maintained to preserve external references.

## Original Description
A deserialization vulnerability exists in the Pytorch RPC framework (torch.distributed.rpc) in pytorch/pytorch versions <=2.3.1. The vulnerability arises from the lack of security verification during the deserialization process of PythonUDF objects in pytorch/torch/distributed/rpc/internal.py. This flaw allows an attacker to execute arbitrary code remotely by sending a malicious serialized PythonUDF object, leading to remote code execution (RCE) on the master node.
