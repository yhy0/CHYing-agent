# Vulnerability Scanning (httpx + nuclei)

## When to Use

- After basic recon identifies an HTTP target
- When you see a recognizable product/framework (Dify, GitLab, Jenkins, Spring, etc.) but don't know its CVEs
- Before spending time on manual fuzzing — check known vulns first
- When auto-recon returned HTTP 200 but you haven't identified the attack surface yet

## Tools

Both `httpx` and `nuclei` are pre-installed in the Docker container. Use via `docker_exec`.

## Phase 1: httpx Fingerprinting

```bash
# Full fingerprint scan (tech detection + title + status + CDN + favicon hash)
docker_exec("echo 'TARGET_URL' | httpx -silent -title -tech-detect -status-code -content-length -favicon -cdn -server -follow-redirects -o /tmp/httpx_result.txt && cat /tmp/httpx_result.txt")
```

**Parse the output for**:
- `tech:` field — identified technologies (e.g., `[Next.js,React,Dify]`)
- `server:` field — web server (nginx, Apache, etc.)
- `title:` field — page title (often reveals product name)
- `favicon-hash:` — match against known product hashes

**Record immediately** via `record_key_finding`:
```
record_key_finding(
    kind="info",
    title="httpx fingerprint: {product} {version}",
    evidence="httpx tech-detect: [{technologies}], title: {title}, server: {server}",
    source={"tool": "httpx", "url": "TARGET_URL"}
)
```

## Phase 2: Nuclei Targeted Scan

Based on httpx results, build the nuclei command. **NEVER run full template scan** — too slow.

### Tag Selection Strategy

| httpx Identifies | nuclei Tags | Example |
|-----------------|-------------|---------|
| Dify | `-tags dify,cve` | CVE-2024-55182 (SSRF) |
| GitLab | `-tags gitlab,cve` | CVE-2023-7028 (password reset) |
| Jenkins | `-tags jenkins,cve` | CVE-2024-23897 (file read) |
| Spring/Spring Boot | `-tags spring,springboot,cve` | CVE-2022-22965 (Spring4Shell) |
| Apache Tomcat | `-tags tomcat,cve` | CVE-2020-1938 (Ghostcat) |
| WordPress | `-tags wordpress,cve,wp-plugin` | thousands of CVEs |
| Drupal | `-tags drupal,cve` | CVE-2018-7600 (Drupalgeddon2) |
| Laravel | `-tags laravel,cve` | CVE-2021-3129 (debug RCE) |
| ThinkPHP | `-tags thinkphp,cve` | ThinkPHP 5.x RCE |
| Node.js/Express | `-tags nodejs,express,cve` | prototype pollution |
| Nginx | `-tags nginx,cve` | path traversal misconfigs |
| Redis | `-tags redis` | unauthorized access |
| Grafana | `-tags grafana,cve` | CVE-2021-43798 (path traversal) |
| Nacos | `-tags nacos,cve` | auth bypass |
| MinIO | `-tags minio,cve` | info disclosure |
| Ollama/vLLM | `-tags ollama,vllm,cve` | AI infra vulns |
| Unknown product | `-tags cve -severity critical,high` | broad CVE scan |

### Scan Commands

```bash
# Targeted scan (preferred, fast)
docker_exec("nuclei -u TARGET_URL -tags TAGS -severity critical,high,medium -o /tmp/nuclei_result.txt && cat /tmp/nuclei_result.txt")

# If targeted scan finds nothing, broaden slightly
docker_exec("nuclei -u TARGET_URL -tags cve -severity critical,high -o /tmp/nuclei_cve.txt && cat /tmp/nuclei_cve.txt")

# Technology-specific (e.g., exposed panels, default creds)
docker_exec("nuclei -u TARGET_URL -tags default-login,exposed-panels -o /tmp/nuclei_panels.txt && cat /tmp/nuclei_panels.txt")

# Misconfigurations
docker_exec("nuclei -u TARGET_URL -tags misconfig -severity critical,high -o /tmp/nuclei_misconfig.txt && cat /tmp/nuclei_misconfig.txt")
```

### Scan Time Budget

- Targeted tags scan: ~30-120 seconds (acceptable)
- Broad CVE scan: ~2-5 minutes (use only if targeted finds nothing)
- Full template scan: DO NOT USE (10+ minutes, wastes time)

## Phase 3: Record and Act

For each nuclei finding:

```
record_key_finding(
    kind="vulnerability",
    title="nuclei: {template-id} on {matched-url}",
    evidence="nuclei [{severity}] {template-id}: {matched-at} | info: {info-line}",
    next_action="Exploit {CVE-ID}: {brief description of the vulnerability}",
    status="confirmed",
    source={"tool": "nuclei", "url": "TARGET_URL"}
)
```

Then proceed to exploitation based on the CVE details.

## Complete Example Flow

```
1. httpx identifies: Next.js + Dify (self-hosted)
2. nuclei -u target -tags dify,cve -severity critical,high
3. nuclei finds: CVE-2024-55182 (SSRF in /console/api/xxx)
4. record_key_finding with CVE details
5. Exploit the SSRF manually or via rag_search for PoC
```

## Fallback: No nuclei Templates Match

If nuclei finds nothing and httpx identified a product:

1. `rag_search("{product} vulnerability exploit CVE")` — check local knowledge base
2. `WebSearch("{product} CVE exploit {year}")` — search the web
3. Manual enumeration of the product's API/admin interfaces

## Important Notes

- httpx and nuclei run in Docker container via `docker_exec`, NOT on the host
- Always use `-o` flag to save results to file, then `cat` the file
- nuclei templates update automatically but may miss very recent CVEs
- If target is behind WAF, add `-rl 10` (rate limit) to nuclei command
- For internal/non-public targets, nuclei's `-tags` is more reliable than technology detection
