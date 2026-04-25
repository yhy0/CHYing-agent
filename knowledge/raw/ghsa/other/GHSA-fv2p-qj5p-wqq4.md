# LF Edge eKuiper vulnerable to File Path Traversal leading to file replacement

**GHSA**: GHSA-fv2p-qj5p-wqq4 | **CVE**: N/A | **Severity**: high (CVSS 8.5)

**CWE**: CWE-24

**Affected Packages**:
- **github.com/lf-edge/ekuiper/v2** (go): < 2.2.0
- **github.com/lf-edge/ekuiper** (go): <= 1.14.7

## Description

### Summary
Path traversal is also known as directory traversal. These vulnerabilities enable an attacker to read arbitrary files on the server that is running an application. In this case, an attacker might be able to write to arbitrary files on the server, allowing them to modify application data or behavior, and ultimately take full control of the server.

### Details
The file handler function trusts the filename provided by the user. This includes the cases when the user uses a path instead of the filename. This makes possible to write arbitrary files to the system and **replace** the files owned by _kuiper_ user on the filesystem. The vulnerable function is `fileUploadHandler` which is shown below:

https://github.com/lf-edge/ekuiper/blob/1e6b6b6601445eb05316532f5fbef7f0a863ecfe/internal/server/rest.go#L329-L359

Exploitation of this vulnerability allows an attacker to rewrite the files owned by ekuiper including the main kuiper binaries as they are owned by _kuiper_ user:

![kuiper binaries](https://github.com/user-attachments/assets/58cf0dc9-20aa-4976-b199-d052a8f5a676)


### PoC
0.  The files should be uploaded to `/kuiper/data/uploads` directory. So let's move to the `/kuiper/data`, examine the existing files and create an empty `traversal-poc` file owned by  _kuiper_:

![Preparation](https://github.com/user-attachments/assets/c1010cfe-ca3e-481d-b895-820a96f2af60)

1. Now, we can go to _Services > Configuration > File Management_ and try to upload file with name `../test`:

![GUI](https://github.com/user-attachments/assets/31402874-d8a1-450b-91d6-025533c7be33)

![Request in Burp](https://github.com/user-attachments/assets/a4b01f57-5ce0-4791-8a6e-69eb47bca40b)

In the response we can see the path of the uploaded file and can assume that the traversal worked.

2. Now we can try to change the `traversal-poc` file that we know exists on the server. It can be made with the following request:

![traversal-poc change](https://github.com/user-attachments/assets/164a7088-9152-4a6d-bef4-de8b4637ed51)

3. Now, if we look at the server, we can see the file created in the traversed directory and the replaced poc-file:

![Changed files](https://github.com/user-attachments/assets/1be0bb36-66b7-4552-9b5d-6298c15d59bb)

### Impact
- Possibility to upload files to external directories;
- Possibility to rewrite any file owned by _kuiper_ user on the filesystem.

Reported by Alexey Kosmachev, Lead Pentester from Bi.Zone
