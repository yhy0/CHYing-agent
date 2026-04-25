# 1Panel arbitrary file write vulnerability

**GHSA**: GHSA-hf7j-xj3w-87g4 | **CVE**: CVE-2023-39966 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-862

**Affected Packages**:
- **github.com/1Panel-dev/1Panel** (go): = 1.4.3

## Description

# Summary
An arbitrary file write vulnerability could lead to direct control of the server
# Details
## Arbitrary file creation
In the api/v1/file.go file, there is a function called SaveContentthat,It recieves JSON data sent by users in the form of a POST request. And the lack of parameter filtering allows for arbitrary file write operations.It looks like this:

- Vulnerable Code

![微信图片_20230801092544](https://user-images.githubusercontent.com/136411443/257381095-4d7c014b-b699-4152-8b9d-2cc9399dfd85.png)

# PoC

- We can write the SSH public key into the /etc/.root/authorized_keys configuration file on the server.

![微信图片_20230801093243](https://user-images.githubusercontent.com/136411443/257381907-38784fab-77b9-47b9-a598-44ef7ad0b65c.png)

- The server was successfully written to the public key
![微信图片_20230801093610](https://user-images.githubusercontent.com/136411443/257382468-b4836eee-f751-4b43-93ff-cb39fdc6c809.png)

- Successfully connected to the target server using an SSH private key.
![微信图片_20230801093933](https://user-images.githubusercontent.com/136411443/257383031-53f1e5de-2743-48ed-a1cf-9a5ea0c0f90b.png)
![微信图片_20230801094037](https://user-images.githubusercontent.com/136411443/257383041-d9f64647-95d9-4711-8b9f-e152966537c9.png)

As a result, the server is directly controlled, causing serious **harm**


# Impact
1Panel v1.4.3

