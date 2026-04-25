# otelgrpc DoS vulnerability due to unbound cardinality metrics 

**GHSA**: GHSA-8pgv-569h-w5rw | **CVE**: CVE-2023-47108 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-770

**Affected Packages**:
- **go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc** (go): >= 0.37.0, < 0.46.0

## Description

### Summary

The grpc Unary Server Interceptor [opentelemetry-go-contrib/instrumentation/google.golang.org/grpc/otelgrpc/interceptor.go](https://github.com/open-telemetry/opentelemetry-go-contrib/blob/9d4eb7e7706038b07d33f83f76afbe13f53d171d/instrumentation/google.golang.org/grpc/otelgrpc/interceptor.go#L327)

```
// UnaryServerInterceptor returns a grpc.UnaryServerInterceptor suitable
// for use in a grpc.NewServer call.
func UnaryServerInterceptor(opts ...Option) grpc.UnaryServerInterceptor {
```
  
out of the box adds labels

- `net.peer.sock.addr`
- `net.peer.sock.port`

that have unbound cardinality. It leads to the server's potential memory exhaustion when many malicious requests are sent.

### Details

An attacker can easily flood the peer address and port for requests.  

### PoC

Apply the attached patch to the example and run the client multiple times.  Observe how each request will create a unique histogram and how the memory consumption increases during it.
### Impact

In order to be affected, the program has to configure a metrics pipeline, use  [UnaryServerInterceptor](https://github.com/open-telemetry/opentelemetry-go-contrib/blob/9d4eb7e7706038b07d33f83f76afbe13f53d171d/instrumentation/google.golang.org/grpc/otelgrpc/interceptor.go#L327), and does not filter any client IP address and ports via middleware or proxies, etc.

### Others

It is similar to already reported vulnerabilities.

* [GHSA-rcjv-mgp8-qvmr](https://github.com/open-telemetry/opentelemetry-go-contrib/security/advisories/GHSA-rcjv-mgp8-qvmr) ([open-telemetry/opentelemetry-go-contrib](https://github.com/open-telemetry/opentelemetry-go-contrib))
- [GHSA-5r5m-65gx-7vrh](https://github.com/open-telemetry/opentelemetry-go-contrib/security/advisories/GHSA-5r5m-65gx-7vrh "GHSA-5r5m-65gx-7vrh") ([open-telemetry/opentelemetry-go-contrib](https://github.com/open-telemetry/opentelemetry-go-contrib))
- [GHSA-cg3q-j54f-5p7p](https://github.com/advisories/GHSA-cg3q-j54f-5p7p "GHSA-cg3q-j54f-5p7p") ([prometheus/client_golang](https://github.com/prometheus/client_golang))

### Workaround for affected versions

As a workaround to stop being affected, a view removing the attributes can be used.

The other possibility is to disable grpc metrics instrumentation by passing [`otelgrpc.WithMeterProvider`](https://github.com/open-telemetry/opentelemetry-go-contrib/blob/instrumentation/google.golang.org/grpc/otelgrpc/v0.45.0/instrumentation/google.golang.org/grpc/otelgrpc/config.go#L138) option with [`noop.NewMeterProvider`](https://pkg.go.dev/go.opentelemetry.io/otel/metric/noop#NewMeterProvider).

### Solution provided by upgrading

In PR [#4322](https://github.com/open-telemetry/opentelemetry-go-contrib/pull/4322), to be released with v0.46.0, the attributes were removed.

### References

- [#4322](https://github.com/open-telemetry/opentelemetry-go-contrib/pull/4322)
