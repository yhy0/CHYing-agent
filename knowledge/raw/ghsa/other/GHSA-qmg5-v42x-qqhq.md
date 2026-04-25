# 1Panel – CAPTCHA Bypass via Client-Controlled Flag 

**GHSA**: GHSA-qmg5-v42x-qqhq | **CVE**: CVE-2025-66507 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-290, CWE-602, CWE-807

**Affected Packages**:
- **github.com/1Panel-dev/1Panel** (go): < 2.0.14
- **github.com/1Panel-dev/1Panel/core** (go): < 0.0.0-20251128030527-ac43f00273be

## Description

### Summary

A CAPTCHA bypass vulnerability in the 1Panel authentication API allows an unauthenticated attacker to disable CAPTCHA verification by abusing a client-controlled parameter. Because the server previously trusted this value without proper validation, CAPTCHA protections could be bypassed, enabling automated login attempts and significantly increasing the risk of account takeover (ATO).

### Details

The /api/login endpoint accepts a boolean field named ignoreCaptcha directly from the client request body:

`"ignoreCaptcha": true`


The backend implementation uses this value to determine whether CAPTCHA validation should be performed:

```
if !req.IgnoreCaptcha {
    if errMsg := captcha.VerifyCode(req.CaptchaID, req.Captcha); errMsg != "" {
        helper.BadAuth(c, errMsg, nil)
        return
    }
}

```

Because req.IgnoreCaptcha is taken directly from user input—with no server-side validation, no session binding, and no privilege checks—any unauthenticated attacker can force CAPTCHA validation to be skipped.

There are no additional conditions, such as:

no requirement for MFA

no trusted device

no IP reputation checks

no prior valid session

no rate limiting

This results in CAPTCHA being entirely client-controlled, which violates fundamental authentication and anti-automation security assumptions.
