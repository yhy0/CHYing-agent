# LLaMA-Factory allows Code Injection through improper vhead_file safeguards

**GHSA**: GHSA-xj56-p8mm-qmxj | **CVE**: CVE-2025-53002 | **Severity**: high (CVSS 8.3)

**CWE**: CWE-94

**Affected Packages**:
- **llamafactory** (pip): <= 0.9.3

## Description

### Summary
A critical remote code execution vulnerability was discovered during the Llama Factory training process. This vulnerability arises because the `vhead_file` is loaded without proper safeguards, allowing malicious attackers to execute arbitrary malicious code on the host system simply by passing a malicious `Checkpoint path` parameter through the `WebUI` interface. The attack is stealthy, as the victim remains unaware of the exploitation. The root cause is that the `vhead_file` argument is loaded without the secure parameter `weights_only=True`.

Note: In torch versions <2.6, the default setting is `weights_only=False`, and Llama Factory's `setup.py` only requires `torch>=2.0.0`.

### Affected Version

Llama Factory versions <=0.9.3 are affected by this vulnerability.

### Details

1. In LLaMA Factory's WebUI, when a user sets the `Checkpoint path`, it modifies the `adapter_name_or_path` parameter passed to the training process.
code in src/llamafactory/webui/runner.py
<img width="1040" alt="image-1" src="https://github.com/user-attachments/assets/c8bc79e4-ce7d-43c9-b0fd-e37c235e6585" />

2. The `adapter_name_or_path` passed to the training process is then used in `src/llamafactory/model/model_utils/valuehead.py` to fetch the corresponding `value_head.bin` file from Hugging Face. This file is subsequently loaded via `torch.load()` without the security parameter `weights_only=True` being set, resulting in remote code execution.
code in src/llamafactory/model/model_utils/valuehead.py
<img width="1181" alt="image-2" src="https://github.com/user-attachments/assets/6edbe694-0c60-4a54-bfb3-5e1042c9230d" />

### PoC

#### Steps to Reproduce

1. Deploy llama factory.
2. Remote attack through the WebUI interface
    1. Configure `Model name` and `Model path`  correctly. For demonstration purposes, we'll use a small model `llamafactory/tiny-random-Llama-3` to accelerate model loading.
    2. Set `Finetuning method` to `LoRA` and `Train Stage` to `Reward Modeling`. The vulnerability is specifically triggered during the Reward Modeling training stage.
    3. Input a malicious Hugging Face path in `Checkpoint path` – here we use `paulinsider/llamafactory-hack`. This repository(https://huggingface.co/paulinsider/llamafactory-hack/tree/main ) contains a malicious `value_head.bin` file. The generation method for this file is as follows (it can execute arbitrary attack commands; for demonstration, we configured it to create a `HACKED!` folder).
    4. Click `Start` to begin training. After a brief wait, a `HACKED!` folder will be created on the server. Note that arbitrary malicious code could be executed through this method.

**The video demonstration of the vulnerability exploitation is available at the** [Google Drive Link](https://drive.google.com/file/d/1AddKm2mllsXfuvL4Tvbn_WJdjEOYXx4y/view?usp=sharing) 

### Impact
Exploitation of this vulnerability allows remote attackers to:
 - Execute arbitrary malicious code / OS commands on the server.
 - Potentially compromise sensitive data or escalate privileges.
 - Deploy malware or create persistent backdoors in the system.
This significantly increases the risk of data breaches and operational disruption.
