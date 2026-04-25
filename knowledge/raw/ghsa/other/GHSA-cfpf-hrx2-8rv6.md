# Expr has Denial of Service via Unbounded Recursion in Builtin Functions

**GHSA**: GHSA-cfpf-hrx2-8rv6 | **CVE**: CVE-2025-68156 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-770

**Affected Packages**:
- **github.com/expr-lang/expr** (go): < 1.17.7

## Description

Several builtin functions in Expr, including `flatten`, `min`, `max`, `mean`, and `median`, perform
recursive traversal over user-provided data structures without enforcing a maximum recursion depth.

If the evaluation environment contains **deeply nested** or **cyclic** data structures, these functions may recurse
indefinitely until exceed the Go runtime stack limit. This results in a **stack overflow panic**, causing the host
application to crash.

While exploitability depends on whether an attacker can influence or inject cyclic or pathologically deep data into the
evaluation environment, this behavior represents a denial-of-service (DoS) risk and affects overall library robustness.
Instead of returning a recoverable evaluation error, the process may terminate unexpectedly.

### Impact

In affected versions, evaluation of expressions that invoke certain builtin functions on untrusted or insufficiently
validated data structures can lead to a **process-level crash** due to stack exhaustion.

This issue is most relevant in scenarios where:

* Expr is used to evaluate expressions against externally supplied or dynamically constructed environments.
* Cyclic references (directly or indirectly) can be introduced into arrays, maps, or structs.
* There are no application-level safeguards preventing deeply nested input data.

In typical use cases with controlled, acyclic data, the issue may not manifest. However, when present, the resulting
panic can be used to reliably crash the application, constituting a denial of service.

### Patches

The issue has been fixed in the v1.17.7 versions of Expr.

The patch introduces a **maximum recursion depth limit** for affected builtin functions. When this limit is exceeded,
evaluation aborts gracefully and returns a descriptive error instead of panicking.

Additionally, the maximum depth can be customized by users via `builtin.MaxDepth`, allowing applications with legitimate
deep structures to raise the limit in a controlled manner.

Users are strongly encouraged to upgrade to the patched release, which includes both the recursion guard and
comprehensive test coverage to prevent regressions.

### Workarounds

For users who cannot immediately upgrade, the following mitigations are recommended:

* Ensure that evaluation environments cannot contain cyclic references.
* Validate or sanitize externally supplied data structures before passing them to Expr.
* Wrap expression evaluation with panic recovery to prevent a full process crash (as a last-resort defensive measure).

These workarounds reduce risk but do not fully eliminate the issue without the patch.
