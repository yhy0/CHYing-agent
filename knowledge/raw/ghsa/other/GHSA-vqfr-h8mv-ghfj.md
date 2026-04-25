# h11 accepts some malformed Chunked-Encoding bodies

**GHSA**: GHSA-vqfr-h8mv-ghfj | **CVE**: CVE-2025-43859 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-444

**Affected Packages**:
- **h11** (pip): < 0.16.0

## Description

### Impact

A leniency in h11's parsing of line terminators in chunked-coding message bodies can lead to request smuggling vulnerabilities under certain conditions.

### Details

HTTP/1.1 Chunked-Encoding bodies are formatted as a sequence of "chunks", each of which consists of:

- chunk length
- `\r\n`
- `length` bytes of content
- `\r\n`

In versions of h11 up to 0.14.0, h11 instead parsed them as:

- chunk length
- `\r\n`
- `length` bytes of content
- any two bytes

i.e. it did not validate that the trailing `\r\n` bytes were correct, and if you put 2 bytes of garbage there it would be accepted, instead of correctly rejecting the body as malformed.

By itself this is harmless. However, suppose you have a proxy or reverse-proxy that tries to analyze HTTP requests, and your proxy has a _different_ bug in parsing Chunked-Encoding, acting as if the format is:

- chunk length
- `\r\n`
- `length` bytes of content
- more bytes of content, as many as it takes until you find a `\r\n`

For example, [pound](https://github.com/graygnuorg/pound/pull/43) had this bug -- it can happen if an implementer uses a generic "read until end of line" helper to consumes the trailing `\r\n`.

In this case, h11 and your proxy may both accept the same stream of bytes, but interpret them differently. For example, consider the following HTTP request(s) (assume all line breaks are `\r\n`):

```
GET /one HTTP/1.1
Host: localhost
Transfer-Encoding: chunked

5
AAAAAXX2
45
0

GET /two HTTP/1.1
Host: localhost
Transfer-Encoding: chunked

0
```

Here h11 will interpret it as two requests, one with body `AAAAA45` and one with an empty body, while our hypothetical buggy proxy will interpret it as a single request, with body `AAAAXX20\r\n\r\nGET /two ...`. And any time two HTTP processors both accept the same string of bytes but interpret them differently, you have the conditions for a "request smuggling" attack. For example, if `/two` is a dangerous endpoint and the job of the reverse proxy is to stop requests from getting there, then an attacker could use a bytestream like the above to circumvent this protection.

Even worse, if our buggy reverse proxy receives two requests from different users:

```
GET /one HTTP/1.1
Host: localhost
Transfer-Encoding: chunked

5
AAAAAXX999
0
```

```
GET /two HTTP/1.1
Host: localhost
Cookie: SESSION_KEY=abcdef...
```

...it will consider the first request to be complete and valid, and send both on to the h11-based web server over the same socket. The server will then see the two concatenated requests, and interpret them as _one_ request to `/one` whose body includes `/two`'s session key, potentially allowing one user to steal another's credentials.

### Patches

Fixed in h11 0.15.0.

### Workarounds

Since exploitation requires the combination of buggy h11 with a buggy (reverse) proxy, fixing either component is sufficient to mitigate this issue.

### Credits

Reported by Jeppe Bonde Weikop on 2025-01-09.
