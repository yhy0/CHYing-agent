# Heap-based buffer overflow in ZBar

**GHSA**: GHSA-mhp6-jvpx-2p4m | **CVE**: CVE-2023-40889 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-122, CWE-787

**Affected Packages**:
- **zbar** (pip): <= 0.23.90

## Description

A heap-based buffer overflow exists in the qr_reader_match_centers function of ZBar 0.23.90. Specially crafted QR codes may lead to information disclosure and/or arbitrary code execution. To trigger this vulnerability, an attacker can digitally input the malicious QR code, or prepare it to be physically scanned by the vulnerable scanner.
