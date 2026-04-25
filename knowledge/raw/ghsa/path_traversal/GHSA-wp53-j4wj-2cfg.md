# Python-Multipart has Arbitrary File Write via Non-Default Configuration

**GHSA**: GHSA-wp53-j4wj-2cfg | **CVE**: CVE-2026-24486 | **Severity**: high (CVSS 8.6)

**CWE**: CWE-22

**Affected Packages**:
- **python-multipart** (pip): < 0.0.22

## Description

### Summary

A Path Traversal vulnerability exists when using non-default configuration options `UPLOAD_DIR` and `UPLOAD_KEEP_FILENAME=True`. An attacker can write uploaded files to arbitrary locations on the filesystem by crafting a malicious filename.

### Details

When `UPLOAD_DIR` is set and `UPLOAD_KEEP_FILENAME` is `True`, the library constructs the file path using `os.path.join(file_dir, fname)`. Due to the behavior of `os.path.join()`, if the filename begins with a `/`, all preceding path components are discarded:

```py
os.path.join("/upload/dir", "/etc/malicious") == "/etc/malicious"
```
                        
This allows an attacker to bypass the intended upload directory and write files to arbitrary paths.                                         
                                                                                                                                              
#### Affected Configuration                                                                                                                      
                                                                                                                                              
Projects are only affected if all of the following are true:                                                                                     
- `UPLOAD_DIR` is set
- `UPLOAD_KEEP_FILENAME` is set to True
- The uploaded file exceeds `MAX_MEMORY_FILE_SIZE` (triggering a flush to disk)

The default configuration is not vulnerable.                                                                                                
                                                                                                                                              
#### Impact                                                                                                                                   
                                                                                                                                              
Arbitrary file write to attacker-controlled paths on the filesystem.                                                                        
                                                                                                                                              
#### Mitigation                                                                                                                                  
                                                                                                                                              
Upgrade to version 0.0.22, or avoid using `UPLOAD_KEEP_FILENAME=True` in project configurations.
