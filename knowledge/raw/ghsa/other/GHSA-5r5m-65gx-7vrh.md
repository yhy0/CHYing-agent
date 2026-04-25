# otelhttp and otelbeego have DoS vulnerability for high cardinality metrics

**GHSA**: GHSA-5r5m-65gx-7vrh | **CVE**: CVE-2023-25151 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-400

**Affected Packages**:
- **go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp** (go): >= 0.38.0, < 0.39.0
- **go.opentelemetry.io/contrib/instrumentation/github.com/astaxie/beego/otelbeego** (go): >= 0.38.0, < 0.39.0

## Description

### Impact

The [v0.38.0](https://github.com/open-telemetry/opentelemetry-go-contrib/releases/tag/v1.13.0) release of [`go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp`](https://github.com/open-telemetry/opentelemetry-go-contrib/blob/463c2e7cd69d25f40b0a595b05394eeb26c68ae2/instrumentation/net/http/otelhttp/handler.go#L218) uses the [`httpconv.ServerRequest`](https://github.com/open-telemetry/opentelemetry-go/blob/v1.12.0/semconv/internal/v2/http.go#L159) function to annotate metric measurements for the `http.server.request_content_length`, `http.server.response_content_length`, and `http.server.duration` instruments.

The `ServerRequest` function sets the `http.target` attribute value to be the whole request URI (including the query string)[^1]. The metric instruments do not "forget" previous measurement attributes when `cumulative` temporality is used, this means the cardinality of the measurements allocated is directly correlated with the unique URIs handled. If the query string is constantly random, this will result in a constant increase in memory allocation that can be used in a denial-of-service attack.

Pseudo-attack:
```
for infinite loop {
  r := generate_random_string()
  do_http_request("/some/path?random="+r)
}
```

### Patches
- `go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp` - v0.39.0
- `go.opentelemetry.io/contrib/instrumentation/github.com/astaxie/beego/otelbeego` - v0.39.0

[^1]: https://github.com/open-telemetry/opentelemetry-go/blob/6cb5718eaaed5c408c3bf4ad1aecee5c20ccdaa9/semconv/internal/v2/http.go#L202-L208
