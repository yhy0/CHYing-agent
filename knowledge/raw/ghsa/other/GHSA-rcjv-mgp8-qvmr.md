# OpenTelemetry-Go Contrib vulnerable to denial of service in otelhttp due to unbound cardinality metrics

**GHSA**: GHSA-rcjv-mgp8-qvmr | **CVE**: CVE-2023-45142 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-770

**Affected Packages**:
- **go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp** (go): < 0.44.0
- **go.opentelemetry.io/contrib/instrumentation/github.com/emicklei/go-restful/otelrestful** (go): < 0.44.0
- **go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin** (go): < 0.44.0
- **go.opentelemetry.io/contrib/instrumentation/github.com/gorilla/mux/otelmux** (go): < 0.44.0
- **go.opentelemetry.io/contrib/instrumentation/github.com/labstack/echo/otelecho** (go): < 0.44.0
- **go.opentelemetry.io/contrib/instrumentation/gopkg.in/macaron.v1/otelmacaron** (go): < 0.44.0
- **go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace** (go): < 0.44.0

## Description

### Summary

This handler wrapper https://github.com/open-telemetry/opentelemetry-go-contrib/blob/5f7e6ad5a49b45df45f61a1deb29d7f1158032df/instrumentation/net/http/otelhttp/handler.go#L63-L65
out of the box adds labels

- `http.user_agent`
- `http.method`

that have unbound cardinality. It leads to the server's potential memory exhaustion when many malicious requests are sent to it.

### Details

HTTP header User-Agent or HTTP method for requests can be easily set by an attacker to be random and long. The library internally uses [httpconv.ServerRequest](https://github.com/open-telemetry/opentelemetry-go/blob/v1.12.0/semconv/internal/v2/http.go#L159) that records every value for HTTP [method](https://github.com/open-telemetry/opentelemetry-go/blob/38e1b499c3da3107694ad2660b3888eee9c8b896/semconv/internal/v2/http.go#L204) and [User-Agent](https://github.com/open-telemetry/opentelemetry-go/blob/38e1b499c3da3107694ad2660b3888eee9c8b896/semconv/internal/v2/http.go#L223).

### PoC

Send many requests with long randomly generated HTTP methods or/and User agents (e.g. a million) and observe how memory consumption increases during it.

### Impact

In order to be affected, the program has to configure a metrics pipeline, use [otelhttp.NewHandler](https://github.com/open-telemetry/opentelemetry-go-contrib/blob/5f7e6ad5a49b45df45f61a1deb29d7f1158032df/instrumentation/net/http/otelhttp/handler.go#L63-L65) wrapper, and does not filter any unknown HTTP methods or User agents on the level of CDN, LB, previous middleware, etc.

### Others

It is similar to already reported vulnerabilities
- https://github.com/open-telemetry/opentelemetry-go-contrib/security/advisories/GHSA-5r5m-65gx-7vrh ([open-telemetry/opentelemetry-go-contrib](https://github.com/open-telemetry/opentelemetry-go-contrib))
- https://github.com/advisories/GHSA-cg3q-j54f-5p7p ([prometheus/client_golang](https://github.com/prometheus/client_golang))

### Workaround for affected versions

As a workaround to stop being affected [otelhttp.WithFilter()](https://pkg.go.dev/go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp/filters) can be used, but it requires manual careful configuration to not log certain requests entirely.

For convenience and safe usage of this library, it should by default mark with the label `unknown` non-standard HTTP methods and User agents to show that such requests were made but do not increase cardinality. In case someone wants to stay with the current behavior, library API should allow to enable it.

The other possibility is to disable HTTP metrics instrumentation by passing [`otelhttp.WithMeterProvider`](https://pkg.go.dev/go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp#WithMeterProvider) option with [`noop.NewMeterProvider`](https://pkg.go.dev/go.opentelemetry.io/otel/metric/noop#NewMeterProvider).

### Solution provided by upgrading

In PR https://github.com/open-telemetry/opentelemetry-go-contrib/pull/4277, released with package version 0.44.0, the values collected for attribute `http.request.method` were changed to be restricted to a set of well-known values and other high cardinality attributes were removed.

### References

- https://github.com/open-telemetry/opentelemetry-go-contrib/pull/4277
- https://github.com/open-telemetry/opentelemetry-go-contrib/releases/tag/v1.19.0

