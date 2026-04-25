# Decompressors can crash the JVM and leak memory content in Aircompressor

**GHSA**: GHSA-973x-65j7-xcf4 | **CVE**: CVE-2024-36114 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-125, CWE-787

**Affected Packages**:
- **io.airlift:aircompressor** (maven): < 0.27

## Description

### Summary
All decompressor implementations of Aircompressor (LZ4, LZO, Snappy, Zstandard) can crash the JVM for certain input, and in some cases also leak the content of other memory of the Java process (which could contain sensitive information).

### Details
When decompressing certain data, the decompressors try to access memory outside the bounds of the given byte arrays or byte buffers. Because Aircompressor uses the JDK class `sun.misc.Unsafe` to speed up memory access, no additional bounds checks are performed and this has similar security consequences as out-of-bounds access in C or C++, namely it can lead to non-deterministic behavior or crash the JVM.

Users should update to Aircompressor 0.27 or newer where these issues have been fixed.

### Impact
When decompressing data from untrusted users, this can be exploited for a denial-of-service attack by crashing the JVM, or to leak other sensitive information from the Java process.
