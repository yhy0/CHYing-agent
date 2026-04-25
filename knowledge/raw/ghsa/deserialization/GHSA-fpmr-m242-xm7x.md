# Malciously crafted QPY files can allows Remote Attackers to Cause Denial of Service in Qiskit

**GHSA**: GHSA-fpmr-m242-xm7x | **CVE**: CVE-2025-1403 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-502

**Affected Packages**:
- **qiskit** (pip): >= 0.45.0, < 1.3.0
- **qiskit-terra** (pip): >= 0.45.0, <= 0.46.3

## Description

### Impact

A maliciously crafted QPY file containing a malformed `symengine` serialization stream as part of the larger QPY serialization of a `ParameterExpression` object can cause a segfault within the `symengine` library, allowing an attacker to terminate the hosting process deserializing the QPY payload.

### Patches

This issue is addressed in 1.3.0 when using QPY format version 13. QPY format versions 10, 11, and 12 are all still inherently vulnerable if they are using symengine symbolic encoding and `symengine <= 0.13.0` is installed in the deserializing environment (as of publishing there is no newer compatible release of symengine available). Using QPY 13 is strongly recommended for this reason.

The symengine 0.14.0 release has addressed the segfault issue, but it is backward incompatible and will not work with any Qiskit release; it also prevents loading a payload generated with any other version of symengine. Using QPY 13 is strongly recommended for this reason.

It is also strongly suggested to patch the locally installed version of symengine in the deserializing environment to prevent the specific segfault. The commit [1] can be applied on top of symengine 0.13.0 and used to build a patched python library that will not segfault in the presence of a malformed payload and instead raise a `RuntimeError` which will address the vulnerability.

### Workarounds

As QPY is backwards compatible `qiskit.qpy.load()` function will always attempt to deserialize the `symengine`-serialized payloads in QPY format versions 10, 11, and 12. These are any payloads generated with the `use_symengine` argument on `qiskit.qpy.dump()` set to `True` (which is the default value starting in Qiskit 1.0.0. The only option is to disallow parsing if those QPY formats are being read and the `use_symengine` flag was set in the file's header. You can detect whether a payload is potentially vulnerable by using the following function built using the Python standard library:

```python
import struct
from collections import namedtuple


def check_qpy_payload(path: str) -> bool:
    """Function to check if a QPY payload is potentially vulnerable to a symengine vulnerability.

    Args:
        path: The path to the QPY file

    Returns:
        Whether the specified payload is potentially vulnerable. If ``True`` the conditions for
        being vulnerable exist, however the payload may not be vulnerable it can't be detected
        until trying to deserialize.
    """
    with open(path, "rb") as file_obj:
        version = struct.unpack("!6sB", file_obj.read(7))[1]
        if version < 10 or version >= 13:
            return False
        file_obj.seek(0)
        header_tuple = namedtuple(
            "FILE_HEADER",
            [
                "preface",
                "qpy_version",
                "major_version",
                "minor_version",
                "patch_version",
                "num_programs",
                "symbolic_encoding",
            ],
        )
        header_pack_str = "!6sBBBBQc"
        header_read_size = struct.calcsize(header_pack_str)
        data = struct.unpack(header_pack_str, file_obj.read(header_read_size))
        header = header_tuple(*data)
        return header.symbolic_encoding == b"e"
```

Note, this function does **not** tell you whether the payload is malicious and will cause the segfault, just that conditions for it to be potentially malicious exist. It's not possible to know ahead of time whether `symengine` will segfault until the data is passed to that library.

### References

[1] https://github.com/symengine/symengine/commit/eb3e292bf13b2dfdf0fa1c132944af8df2bc7d51
