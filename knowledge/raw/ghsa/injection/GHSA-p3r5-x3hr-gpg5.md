# OpenRefine Remote Code execution in project import with mysql jdbc url attack

**GHSA**: GHSA-p3r5-x3hr-gpg5 | **CVE**: CVE-2023-41887 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-89

**Affected Packages**:
- **org.openrefine:database** (maven): <= 3.7.4

## Description

### Summary
An remote Code exec vulnerability allows any unauthenticated user to exec code on the server.

### Details
Hi,Team,
i find openrefine support to import data from database,When use mysql jdbc to connect to database,It is vulnerable to jdbc url attacks,for example,unauthenticated attacker can get rce on the server through the mysql userializable If the mysql-connector-java version used on the server side is less than 8.20.
In order for the server to enable deserialization we need to set the `autoDeserialize` and `queryInterceptors` parameters in the connection string,As same with https://github.com/OpenRefine/OpenRefine/security/advisories/GHSA-qqh2-wvmv-h72m, since the concatenation string is a direct concatenation, it is possible to inject the required parameters after the other parameters.
![image](https://user-images.githubusercontent.com/24366795/262581108-e98dfe16-ee67-463f-8c49-7c318bf0d6f3.png)

And there is a commons-beanutils dependency library on the server side, which contains an RCE-capable deserialization exploit chain

### PoC
env:
centos 7
openrefine 3.7.4
jdk11
mysql-connector-java version 8.14.0
you can use the tool https://github.com/4ra1n/mysql-fake-server to running a malicious mysql server.    
for example use the CB 1.9 Gadget to exec command `touch /tmp/hacked`.  
![image](https://user-images.githubusercontent.com/24366795/262583287-7351a00a-32bf-4cb3-8d86-65ff0a112360.png)  
set the `user` to `base64ZGVzZXJfQ0JfdG91Y2ggL3RtcC9oYWNrZWQ=`(`touch /tmp/hacked` base64 encode),`dataBaseName` to `test?autoDeserialize=true&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor#`.  
![image](https://user-images.githubusercontent.com/24366795/262583657-9cfb9caa-02ed-4f6b-b110-650108803172.png)
![image](https://user-images.githubusercontent.com/24366795/262583815-a17d5530-bae8-4b4f-9392-4ea41b328c7d.png)  
 command `touch /tmp/hacked` is executed.  
![image](https://user-images.githubusercontent.com/24366795/262583979-823d5843-578f-4af6-b84f-a1422aa1b863.png)

### Impact
An remote Code exec vulnerability allows any unauthenticated user to exec code on the server.
