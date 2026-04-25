# CasaOS Improper Restriction of Excessive Authentication Attempts vulnerability

**GHSA**: GHSA-c69x-5xmw-v44x | **CVE**: CVE-2024-24767 | **Severity**: high (CVSS 7.3)

**CWE**: CWE-307

**Affected Packages**:
- **github.com/IceWhaleTech/CasaOS-UserService** (go): >= 0.4.4.3, < 0.4.7

## Description

### Summary
Here it is observed that the CasaOS doesn't defend against password brute force attacks, which leads to having full access to the server.

### Details
The web application lacks control over the login attempts i.e. why attacker can use a password brute force attack to find and get full access over the.

### PoC
1. Capture login request in proxy tool like Burp Suite and select password field.

![1](https://user-images.githubusercontent.com/63414468/297156515-0272bfd7-f386-4c22-b3bd-c4dbdc1298bf.PNG)

2. Here I have started attack with total number of 271 password tries where the last one is the correct password and as we can see in the following image we get a **400 Bad Request** status code with the message "**Invalid Password**" and response length **769** on 1st request which was sent at **_Tue, 16 Jan 2024 18:31:32 GMT_**

![2](https://user-images.githubusercontent.com/63414468/297157815-c158995b-7d46-4a5a-aef9-bcbbcf596b15.png)

**Note**:  _We have tested this vulnerability with more than 3400 tries. We have used 271 request counts just for demo purposes._


3. Here the attack is completed and we can see in the following image we get **200 OK** status code with the message "**Ok**" and response length **1509** on 271st request which was sent at **_Tue, 16 Jan 2024 18:32:01 GMT_**.

![3](https://user-images.githubusercontent.com/63414468/297159282-3f4788b5-6217-4f32-8be6-40ac117710e3.png)

This means attacker can try 271 requests in 56 seconds.

### Impact
This vulnerability allows attackers to get super user-level access over the server.


### Mitigation
It is recommended to implement a proper rate-limiting mechanism on the server side where the configuration might be like:
If a specific IP address fails to login more than 5 times concurrently then that IP address must be blocked for at least 30 seconds. This will reduce the possibility of password brute-forcing attacks.
