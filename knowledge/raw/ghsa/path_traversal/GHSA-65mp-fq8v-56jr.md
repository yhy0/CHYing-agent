# Flask-Reuploaded vulnerable to Remote Code Execution via Server-Side Template Injection

**GHSA**: GHSA-65mp-fq8v-56jr | **CVE**: CVE-2026-27641 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-22, CWE-1336

**Affected Packages**:
- **flask-reuploaded** (pip): < 1.5.0

## Description

### Impact
A critical path traversal and extension bypass vulnerability in Flask-Reuploaded allows remote attackers to achieve arbitrary file write and remote code execution through Server-Side Template Injection (SSTI).

### Patches
Flask-Reuploaded has been patched in version 1.5.0

### Workarounds

1. **Do not pass user input to the `name` parameter**
2. Use auto-generated filenames only
3. Implement strict input validation if `name` must be used

```python
from werkzeug.utils import secure_filename
import os

# Sanitize user input before passing to save()
safe_name = secure_filename(request.form.get('custom_name'))
# Remove path separators
safe_name = os.path.basename(safe_name)
# Validate extension matches policy
if not photos.extension_allowed(photos.get_extension(safe_name)):
    abort(400)
    
filename = photos.save(file, name=safe_name)
```

### Resources
The fix is documented in the pull request, see https://github.com/jugmac00/flask-reuploaded/pull/180.

A proper write-up was created by the reporter of the vulnerability, Jaron Cabral (https://www.linkedin.com/in/jaron-cabral-751994357/), but is not yet available as of time of this publication.
