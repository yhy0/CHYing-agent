# Fugue is Vulnerable to Remote Code Execution by Pickle Deserialization via FlaskRPCServer

**GHSA**: GHSA-xv5p-fjw5-vrj6 | **CVE**: CVE-2025-62703 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-78, CWE-502

**Affected Packages**:
- **fugue** (pip): <= 0.9.2

## Description

### Summary
The Fugue framework implements an RPC server system for distributed computing operations. In the core functionality of the RPC server implementation, I found that the _decode() function in fugue/rpc/flask.py directly uses cloudpickle.loads() to deserialize data without any sanitization. This creates a remote code execution vulnerability when malicious pickle data is processed by the RPC server.The vulnerability exists in the RPC communication mechanism where the client can send arbitrary serialized Python objects that will be deserialized on the server side, allowing attackers to execute arbitrary code on the victim's machine.

### Details
_decode() function in fugue/rpc/flask.py directly uses cloudpickle.loads() to deserialize data without any sanitization.

### PoC
* Step1:
The victim user starts an RPC server binding to open network using the Fugue framework. Here, I use the official RPC server code to initialize the server. 

* Step2:
The attacker modifies the _encode() function in fugue/rpc/flask.py to inject malicious pickle data:

<img width="740" height="260" alt="image" src="https://github.com/user-attachments/assets/6064516b-e1a6-45fa-a91c-8e276bc4a106" />

In this example, attacker modifies _encode to let the victim execute command “ls -l”

* Step 3:
The attacker then uses the RPC client to send the malicious request

Fugue gives a demo video and the PoC in the attachment, along with modified flask.py. When users reproduce this issue, in the server side (as an victim), users can run python rpc_server.py.  In the client side (as an attacker), users can first replace fugue/rpc/flask.py in pip site-packages with provided flask.py in the attachment and then run rpc_client.py.


### Impact
Remote code execution in the victim's machine. Once the victim starts the RPCServer with network binding (especially 0.0.0.0), an attacker on the network can gain arbitrary code execution by connecting to the RPCServer and sending crafted pickle payloads. This vulnerability allows for:

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

Attachment: https://drive.google.com/file/d/1y8bBBp7dnWoT_WHBtdB0Fts4NRUIfdWi/view?usp=sharing
