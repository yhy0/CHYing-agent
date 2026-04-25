# pyquokka is Vulnerable to Remote Code Execution by Pickle Deserialization via FlightServer 

**GHSA**: GHSA-f74j-gffq-vm9p | **CVE**: CVE-2025-62515 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-502

**Affected Packages**:
- **pyquokka** (pip): <= 0.3.1

## Description

### Description

In the FlightServer class of the pyquokka framework, the do_action() method directly uses pickle.loads() to deserialize action bodies received from Flight clients without any sanitization or validation, which results in a remote code execution vulnerability. The vulnerable code is located in pyquokka/flight.py at line 283, where arbitrary data from Flight clients is directly passed to pickle.loads().

Even more concerning, when FlightServer is configured to listen on 0.0.0.0 (as shown in the provided server example at line 339), this allows attackers across the entire network to perform arbitrary remote code execution by sending malicious pickled payloads through the set_configs action.

In addition, the functions cache_garbage_collect, do_put, and do_get also contain vulnerability points where pickle.loads is used to deserialize untrusted remote data. Please review and fix these issues accordingly. This report uses the set_configs action as an example.


### Proof of Concept

* Step 1:
The victim user starts a FlightServer that binds to the network interface, e.g.:
```
server = FlightServer("0.0.0.0", location = "grpc+tcp://0.0.0.0:5005")
server.serve()
````
* Step 2:
The attacker can then send malicious pickle dump data through the Flight client connection. The provided PoC demonstrates how an attacker can execute "ls -l" command:

```python
class RCE:
def __reduce__(self):
import os
return (os.system, ('ls -l',))

import pickle
action_body = pickle.dumps(RCE())
action = pyarrow.flight.Action("set_configs", action_body)
```

When the server receives this payload, the FlightServer.do_action() method calls pickle.loads(action.body.to_pybytes()) on line 283, which triggers the execution of the malicious code through Python's pickle deserialization mechanism. The provided flight_client.py demonstrates a complete PoC that connects to the vulnerable server and executes arbitrary commands through the pickle deserialization vulnerability.

When the vulnerability is reproduced, python flight.py can be run to init the server and then run flight_client.py. There is an attack demo in the attachment.

### Impact

Remote code execution on the victim's machine over the network. Once the victim starts the FlightServer with network binding (especially 0.0.0.0), an attacker on the network can gain arbitrary code execution by connecting to the Flight endpoint and sending crafted pickle payloads through the set_configs action. This vulnerability allows for:

- Complete system compromise
- Data exfiltration
- Lateral movement within the network
- Denial of service attacks
- Installation of persistent backdoors

### Mitigation

1. **Replace unsafe deserialization**: Replace `pickle.loads()` with safer alternatives such as:
   - JSON serialization for simple data structures
   - Protocol Buffers or MessagePack for complex data
   - If pickle must be used, implement a custom `Unpickler` with a restricted `find_class()` method that only allows whitelisted classes

2. **Network security**: 
   - If the service is intended for internal use only, bind to localhost (`127.0.0.1`) instead of `0.0.0.0`
   - Implement authentication and authorization mechanisms

3. **Security warnings**: When starting the service on public interfaces, display clear security warnings to inform users about the risks.
