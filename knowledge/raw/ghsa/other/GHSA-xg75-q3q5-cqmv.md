# Denial of Service in http-swagger

**GHSA**: GHSA-xg75-q3q5-cqmv | **CVE**: CVE-2022-24863 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400, CWE-755

**Affected Packages**:
- **github.com/swaggo/http-swagger** (go): < 1.2.6

## Description

### Impact
Allows an attacker to perform a DOS attack consisting of memory exhaustion on the host system.

### Patches
Yes. Please upgrade to v1.2.6.

### Workarounds
A workaround is to restrict the path prefix to the "GET" method. As shown below
```
func main() {
	r := mux.NewRouter()

	r.PathPrefix("/swagger/").Handler(httpSwagger.Handler(
		httpSwagger.URL("http://localhost:1323/swagger/doc.json"), //The url pointing to API definition
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("#swagger-ui"),
	)).Methods(http.MethodGet)
```

### References
Reporter dongguangli from https://www.huoxian.cn/ company

### For more information
If you have any questions or comments about this advisory:
* Open an issue in [http-swagger](https://github.com/swaggo/http-swagger/issues)


