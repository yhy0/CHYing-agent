# Chisel's AUTH environment variable not respected in server entrypoint

**GHSA**: GHSA-38jh-8h67-m7mj | **CVE**: CVE-2024-43798 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-306, CWE-1068

**Affected Packages**:
- **github.com/jpillora/chisel** (go): < 1.10.0

## Description

### Summary
The Chisel server doesn't ever read the documented `AUTH` environment variable used to set credentials, which allows any unauthenticated user to connect, even if credentials were set. This advisory is a formalization of a report sent to the maintainer via email.

### Details
In the help page for the `chisel server` subcommand, it mentions an `AUTH` environment variable that can be set in order to provide credentials that the server should authenticate connections against: https://github.com/jpillora/chisel/blob/3de177432cd23db58e57f376b62ad497cc10840f/main.go#L138.

The issue is that the server entrypoint doesn't ever read the `AUTH` environment variable. The only place that this happens is in the client entrypoint: https://github.com/jpillora/chisel/blob/3de177432cd23db58e57f376b62ad497cc10840f/main.go#L452

This subverts the expectations set by the documentation, allowing unauthenticated users to connect to a Chisel server, even if auth is attempted to be set up in this manner.

### PoC
Run `chisel server`, first specifying credentials with the `AUTH` environment variable, then with the `--auth` argument. In the first case, the server allows connections without authentication, while in the second, the correct behavior is exhibited.

### Impact
Anyone who is running the Chisel server, and that is using the `AUTH` environment variable to specify credentials to authenticate against. Chisel is often used to provide an entrypoint to a private network, which means services that are gated by Chisel may be affected. Additionally, Chisel is often used for exposing services to the internet. An attacker could MITM requests by connecting to a Chisel server and requesting to forward traffic from a remote port. 
