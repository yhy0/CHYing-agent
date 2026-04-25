# Silver vulnerable to MitM attack against implants due to a cryptography vulnerability

**GHSA**: GHSA-8jxm-xp43-qh3q | **CVE**: CVE-2023-34758 | **Severity**: critical (CVSS 8.1)

**CWE**: CWE-327

**Affected Packages**:
- **github.com/bishopfox/sliver** (go): >= 1.5.0, < 1.5.40

## Description

### Summary
The current cryptography implementation in Sliver up to version 1.5.39 allows a MitM with access to the corresponding implant binary to execute arbitrary codes on implanted devices via intercepted and crafted responses. (Reserved CVE ID: CVE-2023-34758)

### Details
Please see [the PoC repo](https://github.com/tangent65536/Slivjacker).

### PoC
Please also see [the PoC repo](https://github.com/tangent65536/Slivjacker).
To setup a simple PoC environment,  
 1. Generate an implant with its C2 set to the PoC server's address and copy the embedded private implant key and public server key into the config json.  
 2. Run the implant on a separate VM and a `notepad.exe` window should pop up on the implanted VM.  

### Impact
A successful attack grants the attacker permission to execute arbitrary code on the implanted device.  
  
### References
https://github.com/BishopFox/sliver/blob/master/implant/sliver/cryptography/implant.go  
https://github.com/BishopFox/sliver/blob/master/implant/sliver/cryptography/crypto.go  
https://github.com/tangent65536/Slivjacker  

### Credits
[Ting-Wei Hsieh](https://github.com/tangent65536) from [CHT Security Co. Ltd.](https://www.chtsecurity.com/?lang=en)
