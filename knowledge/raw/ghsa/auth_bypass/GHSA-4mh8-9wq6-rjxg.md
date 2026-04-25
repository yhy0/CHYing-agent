# OpenAM vulnerable to user impersonation using SAMLv1.x SSO process

**GHSA**: GHSA-4mh8-9wq6-rjxg | **CVE**: CVE-2023-37471 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-287

**Affected Packages**:
- **org.openidentityplatform.openam:openam-federation-library** (maven): < 14.7.3

## Description

### Impact
OpenAM up to version 14.7.2 does not properly validate the signature of SAML responses received as part of the SAMLv1.x Single Sign-On process. Attackers can use this fact to impersonate any OpenAM user, including the administrator, by sending a specially crafted SAML response to the SAMLPOSTProfileServlet servlet.

### Patches
This problem has been patched in  OpenAM 14.7.3-SNAPSHOT and later

### Workarounds
One should comment servlet `SAMLPOSTProfileServlet` in web.xml or disable SAML in OpenAM
```xml
<servlet>
    <description>SAMLPOSTProfileServlet</description>
    <servlet-name>SAMLPOSTProfileServlet</servlet-name>
    <servlet-class>com.sun.identity.saml.servlet.SAMLPOSTProfileServlet</servlet-class>
</servlet>
...
<servlet-mapping>
    <servlet-name>SAMLSOAPReceiver</servlet-name>
    <url-pattern>/SAMLSOAPReceiver</url-pattern>
</servlet-mapping>
```

### References
#624

