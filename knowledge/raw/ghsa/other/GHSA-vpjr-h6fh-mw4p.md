# Duplicate Advisory: EVE Freely Allocates Buffer on The Stack With Data From Socket

**GHSA**: GHSA-vpjr-h6fh-mw4p | **CVE**: N/A | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-770, CWE-789

**Affected Packages**:
- **github.com/lf-edge/eve** (go): < 0.0.0-20230519072751-977f42b07fa9

## Description

### Duplicate Advisory
This advisory has been withdrawn because it is a duplicate of GHSA-phcg-h58r-gmcq. This link is maintained to preserve external references.

### Original Description
As noted in the “VTPM.md” file in the eve documentation, “VTPM is a server listening on port
8877 in EVE, exposing limited functionality of the TPM to the clients. 
VTPM allows clients to
execute tpm2-tools binaries from a list of hardcoded options”
The communication with this server is done using protobuf, and the data is comprised of 2
parts:

1. Header

2. Data

When a connection is made, the server is waiting for 4 bytes of data, which will be the header,
and these 4 bytes would be parsed as uint32 size of the actual data to come.

Then, in the function “handleRequest” this size is then used in order to allocate a payload on
the stack for the incoming data.

As this payload is allocated on the stack, this will allow overflowing the stack size allocated for
the relevant process with freely controlled data.

* An attacker can crash the system. 
* An attacker can gain control over the system, specifically on the “vtpm_server” process
which has very high privileges.
