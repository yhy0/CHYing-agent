# Pixar OpenUSD Sdf_PathNode Module Use-After-Free Vulnerability Leading to Potential Remote Code Execution

**GHSA**: GHSA-58p5-r2f6-g2cj | **CVE**: N/A | **Severity**: critical (CVSS 9.4)

**CWE**: CWE-416

**Affected Packages**:
- **usd-core** (pip): < 25.8

## Description

### Summary
A Use-After-Free (UAF) vulnerability has been discovered in the Sdf_PathNode module of the Pixar OpenUSD library. This issue occurs during the deletion of the Sdf_PrimPathNode object in multi-threaded environments, where freed memory is accessed. This results in segmentation faults or bus errors, allowing attackers to potentially exploit the vulnerability for remote code execution (RCE). By using a specially crafted .usd file, an attacker could gain control of the affected system. The vulnerability has been confirmed in multiple OpenUSD tools, including sdfdump, usdtree, usdcat, and sdffilter.

### Patches

This is fixed with [commit 0d74f31](https://github.com/PixarAnimationStudios/OpenUSD/commit/0d74f31fe64310791e274e587c9926335e9db9db), with the fix available in OpenUSD 25.08 and onwards.

### Details
The issue is a Use-After-Free vulnerability in the Sdf_PathNode destruction process, specifically in Sdf_PrimPathNode::~Sdf_PrimPathNode(). When multiple threads attempt to destroy or modify the same Sdf_PathNode object, a race condition can occur, causing the object to be accessed after it has been freed. This leads to segmentation faults or bus errors.

The root cause is in the destructor path where the reference count and path node tree are modified without proper synchronization, creating a TOCTOU race condition between the reference count check and the actual memory deallocation.

### PoC
1. Upload proof-of-concept file [poc.usd.zip](https://github.com/user-attachments/files/17690595/poc.usd.zip)
2. A crafted .usd file triggers the vulnerability when loaded into any of the affected tools. Reproduced in both Linux and macOS environments.

```
git clone https://github.com/PixarAnimationStudios/OpenUSD.git
python3 OpenUSD/build_scripts/build_usd.py ./install -j4 --no-python

cd ./install/bin
./sdfdump /path/to/poc.usd
```

Run one of the vulnerable tools (e.g., `sdffilter`) with the crafted `.usd` file:
```
./sdffilter /path/to/crafted_file.usd
```

### Impact
OpenUSD, managed by the Alliance for OpenUSD (AOUSD), is widely adopted by major organizations such as Apple, NVIDIA, Autodesk, and Pixar. It serves as a key standard in industries like film, animation, gaming, AR/VR, and simulation. Exploitation of this vulnerability could lead to severe consequences, including system compromise, unauthorized data access, and disruption of services relying on OpenUSD. Given its critical role in 3D content creation and its widespread use, this vulnerability poses a significant threat to system security and data integrity.

### Credit
- Song Hyun Bae ( @bshyuunn )
