# ESP-IDF web_server basic auth bypass using empty or incomplete Authorization header

**GHSA**: GHSA-mxh2-ccgj-8635 | **CVE**: CVE-2025-57808 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-187, CWE-303

**Affected Packages**:
- **esphome** (pip): <= 2025.8.0

## Description

### Summary
On the ESP-IDF platform, ESPHome's [`web_server` authentication](https://esphome.io/components/web_server.html#configuration-variables) check can pass incorrectly when the client-supplied base64-encoded `Authorization` value is empty or is a substring of the correct value (e.g., correct username with partial password). This allows access to `web_server` functionality (including OTA, if enabled) without knowing any information about the correct username or password.

### Details
The HTTP basic auth check in `web_server_idf`'s [`AsyncWebServerRequest::authenticate`](https://github.com/esphome/esphome/blob/ef2121a215890d46dc1d25ad363611ecadc9e25e/esphome/components/web_server_idf/web_server_idf.cpp#L256) only compares up to `auth.value().size() - auth_prefix_len` bytes of the base64-encoded `user:pass` string. This means a client-provided valuer like `dXNlcjpz` (`user:s`) will pass the check when the correct value is much longer, e.g., `dXNlcjpzb21lcmVhbGx5bG9uZ3Bhc3M=` (`user:somereallylongpass`).

Furthermore, the check will also pass when the supplied value is the empty string, which removes the need to know (or brute force) the username. A browser won't generally issue such a request, but it can easily be done by manually constructing the `Authorizaztion` request header (e.g., via `curl`).

### PoC
Configure ESPHome as follows:

```yaml
esp32:
  board: ...
  framework:
    type: esp-idf
web_server:
  auth:
    username: user
    password: somereallylongpass
```

In a browser, you can correctly log in by supplying username `user` and password `somereallylongpass`... but you can _also_ incorrectly log in by supplying _substrings_ of the password whose base64-encoded digest matches a _prefix_ of the correct digest. (For example, I was able to log into an ESPHome device so configured by supplying password `some`... or even just `s`.)

You can also use a tool like `curl` to manually set an `Authorization` request header that _always_ passes the check without any knowledge of the username:

```
$ curl -D- http://example.local/
HTTP/1.1 401 Unauthorized
...

$ curl -D- -H 'Authorization: Basic ' http://example.local/
HTTP/1.1 200 OK
...
```

### Impact
This vulnerability effectively nullifies basic auth support for the ESP-IDF `web_server`, allowing auth bypass from another device on the local network with no knowledge of the correct username or password required.

### Remediation
This vulnerability is fixed in 2025.8.1 and later.

For older versions, disabling the `web_server` component on ESP-IDF devices may be prudent, particularly if OTA updates through `web_server` are enabled.
