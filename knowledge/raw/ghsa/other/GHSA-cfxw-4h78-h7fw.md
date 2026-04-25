# DNSJava DNSSEC Bypass

**GHSA**: GHSA-cfxw-4h78-h7fw | **CVE**: CVE-2024-25638 | **Severity**: high (CVSS 8.9)

**CWE**: CWE-345, CWE-349

**Affected Packages**:
- **dnsjava:dnsjava** (maven): < 3.6.0

## Description

### Summary

Records in DNS replies are not checked for their relevance to the query, allowing an attacker to respond with RRs from different zones.

### Details

DNS Messages are not authenticated. They do not guarantee that

- received RRs are authentic
- not received RRs do not exist
- all or any received records in a response relate to the request

Applications utilizing DNSSEC generally expect these guarantees to be met, however DNSSEC by itself only guarantees the first two.
To meet the third guarantee, resolvers generally follow an (undocumented, as far as RFCs go) algorithm such as: (simplified, e.g. lacks DNSSEC validation!)

1. denote by `QNAME` the name you are querying (e.g. fraunhofer.de.), and initialize a list of aliases
2. if the ANSWER section contains a valid PTR RRSet for `QNAME`, return it (and optionally return the list of aliases as well)
3. if the ANSWER section contains a valid CNAME RRSet for `QNAME`, add it to the list of aliases. Set `QNAME` to the CNAME's target and go to 2.
4. Verify that `QNAME` does not have any PTR, CNAME and DNAME records using valid NSEC or NSEC3 records. Return `null`.

Note that this algorithm relies on NSEC records and thus requires a considerable portion of the DNSSEC specifications to be implemented. For this reason, it cannot be performed by a DNS client (aka application) and is typically performed as part of the resolver logic.

dnsjava does not implement a comparable algorithm, and the provided APIs instead return either

- the received DNS message itself (e.g. when using a ValidatingResolver such as in [this](https://github.com/dnsjava/dnsjava/blob/master/EXAMPLES.md#dnssec-resolver) example), or
- essentially just the contents of its ANSWER section (e.g. when using a LookupSession such as in [this](https://github.com/dnsjava/dnsjava/blob/master/EXAMPLES.md#simple-lookup-with-a-resolver) example)

If applications blindly filter the received results for RRs of the desired record type (as seems to be typical usage for dnsjava), a rogue recursive resolver or (on UDP/TCP connections) a network attacker can

- In addition to the actual DNS response, add RRs irrelevant to the query but of the right datatype, e.g. from another zone, as long as that zone is correctly using DNSSEC, or
- completely exchange the relevant response records

### Impact

DNS(SEC) libraries are usually used as part of a larger security framework.
Therefore, the main misuses of this vulnerability concern application code, which might take the returned records as authentic answers to the request.
Here are three concrete examples of where this might be detrimental:

- [RFC 6186](https://datatracker.ietf.org/doc/html/rfc6186) specifies that to connect to an IMAP server for a user, a mail user agent should retrieve certain SRV records and send the user's credentials to the specified servers. Exchanging the SRV records can be a tool to redirect the credentials.
- When delivering mail via SMTP, MX records determine where to deliver the mails to. Exchanging the MX records might lead to information disclosure. Additionally, an exchange of TLSA records might allow attackers to intercept TLS traffic.
- Some research projects like [LIGHTest](https://www.lightest.eu/) are trying to manage CA trust stores via URI and SMIMEA records in the DNS. Exchanging these allows manipulating the root of trust for dependent applications.

### Mitigations

At this point, the following mitigations are recommended:

- When using a ValidatingResolver, ignore any Server indications of whether or not data was available (e.g. NXDOMAIN, NODATA, ...).
- For APIs returning RRs from DNS responses, filter the RRs using an algorithm such as the one above. This includes e.g. `LookupSession.lookupAsync`.
- Remove APIs dealing with raw DNS messages from the examples section or place a noticable warning above.
