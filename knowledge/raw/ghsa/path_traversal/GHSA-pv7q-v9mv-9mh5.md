# 1Panel O&M management panel has a background arbitrary file reading vulnerability

**GHSA**: GHSA-pv7q-v9mv-9mh5 | **CVE**: CVE-2023-39964 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/1Panel-dev/1Panel** (go): = 1.4.3

## Description

### Summary
Arbitrary file reads allow an attacker to read arbitrary important configuration files on the server.

### Details
In the api/v1/file.go file, there is a function called LoadFromFile, which directly reads the file by obtaining the requested path parameter[path]. The request parameters are not filtered, resulting in a background arbitrary file reading vulnerability
![picture1](https://user-images.githubusercontent.com/136411443/257109786-1b0af1e7-346f-4e92-9da2-d977f2f7fe6a.jpg)

### PoC
Request /api/v1/files/loadfile, carry /etc/passwd data to read, as shown below:
![微信图片_20230731112833](https://user-images.githubusercontent.com/136411443/257109931-108fc16f-e180-4d1e-996c-d9da5f76559f.png)


### Impact
1Panel v1.4.3

