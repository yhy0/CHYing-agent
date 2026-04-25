# 1Panel agent certificate verification bypass leading to arbitrary command execution

**GHSA**: GHSA-8j63-96wh-wh3j | **CVE**: CVE-2025-54424 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-77, CWE-295

**Affected Packages**:
- **github.com/1Panel-dev/1Panel/core** (go): >= 1.0.0, < 2.0.6
- **github.com/1Panel-dev/1Panel/core** (go): < 0.0.0-20250730021757-04b9cbd87a15

## Description

### Project Address: Project Address [1Panel](https://github.com/1Panel-dev/1Panel)
### Official website: https://www.1panel.cn/
### Time: 2025 07 26
### Version: 1panel V2.0.5
### Vulnerability Summary
 - First, we introduce the concepts of 1panel v2 Core and Agent. After the new version is released, 1panel adds the node management function, which allows you to control other hosts by adding nodes.
 - The HTTPS protocol used for communication between the Core and Agent sides did not fully verify the authenticity of the certificate during certificate verification, resulting in unauthorized interfaces. The presence of a large number of command execution or high-privilege interfaces in the 1panel led to RCE.

![](https://github.com/user-attachments/assets/ebd0b388-d6c0-4678-98ee-47646e69ebe9)

### Code audit process

1. First we go to the Agent HTTP routing fileagent/init/router/router.go

![](https://github.com/user-attachments/assets/dd9152a9-6677-4674-b75f-3b67dcedb321)

2. It was found that the Routersreference function in the function Certificatewas globally checked.agent/middleware/certificate.go

![](https://github.com/user-attachments/assets/5585f251-61e0-4603-8e9e-f50465f265ae)

3. The discovery Certificatefunction determines c.Request.TLS.HandshakeCompletewhether certificate communication has been performed

![](https://github.com/user-attachments/assets/5a50bdec-cc4d-4439-9b7b-98991ca4ff9c)

4. Since c.Request.TLS.HandshakeCompletethe true or false judgment is determined by agent/server/server.gothe code Startfunctiontls.RequireAnyClientCert

![](https://github.com/user-attachments/assets/3785b245-6e1f-44ff-9760-708b3e76560b)

Note:：`Here due to the use of tls.RequireAnyClientCert instead of tls.RequireAndVerifyClientCert，RequireAnyClientCert Only require the client to provide a certificate，Does not verify the issuance of certificates CA，So any self assigned certificate will pass TLS handshake。`

5. The subsequent Certificatefunction only verified that the CN field of the certificate was panel_client, without verifying the certificate issuer. Finally, it was discovered that the WebSocket connection could bypass Proxy-ID verification.

![](https://github.com/user-attachments/assets/f521d75a-cd72-41b8-b90f-f10ffb923484)

6. Process WebSocket interface (based on the above questions, all processes and other sensitive information can be obtained)
routing address: /process/ws
the request format is as follows
```
{
  "type": "ps",           // 数据类型: ps(进程), ssh(SSH会话), net(网络连接), wget(下载进度)
  "pid": 123,             // 可选，指定进程ID进行筛选
  "name": "process_name", // 可选，根据进程名筛选
  "username": "user"      // 可选，根据用户名筛选
}
```
![](https://github.com/user-attachments/assets/011dc303-9316-4160-ad98-165c032f6e49)

 - Terminal SSH WebSocket interface (according to the above problem, any command can be executed)
routing address: /hosts/terminal
the request format is as follows
```
{
  "type": "cmd",
  "data": "d2hvYW1pCg=="  // "whoami" 的base64编码，记住不要忘记回车。
}
```
![](https://github.com/user-attachments/assets/6f2ac997-8b32-4cb6-a64c-be33db845a76)

 - Container Terminal WebSocket interface (container execution command interface)
routing address:/containers/terminal
    
 - File Download Process WebSocket interface (automatically push download progress information)
routing address:/files/wget/process

### Attack process

1. First generate a fake certificate
openssl req -x509 -newkey rsa:2048 -keyout panel_client.key -out panel_client.crt -days 365 -nodes -subj "/CN=panel_client"

2. Then use the certificate to request verification. If the websocket interface is successfully connected, there is a vulnerability.

![](https://github.com/user-attachments/assets/9e3016f8-ebe0-4dc9-b797-405c6a4aec89)

![](https://github.com/user-attachments/assets/8076ad9c-da30-452f-9f42-83ae1d66f9ac)
