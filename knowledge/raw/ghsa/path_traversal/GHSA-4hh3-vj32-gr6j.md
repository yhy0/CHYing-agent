# Mobile Security Framework (MobSF) has a Zip Slip Vulnerability in .a Static Library Files

**GHSA**: GHSA-4hh3-vj32-gr6j | **CVE**: CVE-2024-43399 | **Severity**: high (CVSS 8.0)

**CWE**: CWE-22, CWE-23

**Affected Packages**:
- **mobsf** (pip): <= 4.0.6

## Description

### Summary
Upon reviewing the MobSF source code, I identified a flaw in the Static Libraries analysis section. Specifically, during the extraction of .a extension files, the measure intended to prevent Zip Slip attacks is improperly implemented.

Since the implemented measure can be bypassed, the vulnerability allows an attacker to extract files to any desired location within the server running MobSF.

### Details

Upon examining lines 183-192 of the `mobsf/StaticAnalyzer/views/common/shared_func.py` file, it is observed that there is a mitigation against Zip Slip attacks implemented as `a.decode('utf-8', 'ignore').replace('../', '').replace('..\\', '')`. However, this measure can be bypassed using sequences like `....//....//....//`. Since the replace operation is not recursive, this sequence is transformed into `../../../` after the replace operation, allowing files to be written to upper directories.

<img width="448" alt="image" src="https://github.com/user-attachments/assets/fadf4bcc-1a92-4655-b66a-5349278ad9c5">


For the proof of concept, I created an .a archive file that renders MobSF unusable by writing an empty file with the same name over the database located at `/home/mobsf/.MobSF/db.sqlite3`.

<img width="300" alt="poc a_1" src="https://github.com/user-attachments/assets/54acf101-3931-401f-9970-a0934265eecb">


I am including the binary used for the POC named `poc.VULN`. To test it, you need to rename this binary to `poc.a`.

 **Warning:** As soon as you scan this file with MobSF, the database will be deleted, rendering MobSF unusable.

PoC Binary File ([poc.VULN](https://drive.google.com/file/d/1K2eHYIZ1hUbs-Vi5zhKAKecnd0nDB8lO/view?usp=share_link))

### PoC


https://github.com/user-attachments/assets/3225ccb0-cb00-47a5-8305-37a40ca1ae7f



### Impact

When a malicious .a file is scanned with MobSF, a critical vulnerability is present as it allows files to be extracted to any location on the server where MobSF is running. In this POC, I deleted the database, but it is also possible to achieve RCE by overwriting binaries of certain tools or by overwriting the /etc/passwd file.

