# Flask-AppBuilder vulnerable to incorrect authentication when using auth type OpenID 

**GHSA**: GHSA-j2pw-vp55-fqqj | **CVE**: CVE-2024-25128 | **Severity**: critical (CVSS 9.1)

**CWE**: N/A

**Affected Packages**:
- **Flask-AppBuilder** (pip): < 4.3.11

## Description

### Impact
When Flask-AppBuilder is set to AUTH_TYPE AUTH_OID, allows an attacker to forge an HTTP request, that could deceive the backend into using any requested OpenID service. This vulnerability could grant an attacker unauthorised privilege access if a custom OpenID service is deployed by the attacker and accessible by the backend. 

This vulnerability is only exploitable when the application is using the old (deprecated 10 years ago) OpenID 2.0 authorization protocol (which is very different from the popular OIDC - Open ID Connect - popular protocol used today). Currently, this protocol is regarded as legacy, with significantly reduced usage and not supported for several years by major authorization providers.

### Patches
Upgrade to Flask-AppBuilder 4.3.11

### Workarounds
If upgrade is not possible add the following to your config:

```
from flask import flash, redirect
from flask_appbuilder import expose
from flask_appbuilder.security.sqla.manager import SecurityManager
from flask_appbuilder.security.views import AuthOIDView
from flask_appbuilder.security.forms import LoginForm_oid

basedir = os.path.abspath(os.path.dirname(__file__))


class FixedOIDView(AuthOIDView):
    @expose("/login/", methods=["GET", "POST"])
    def login(self, flag=True):
        form = LoginForm_oid()
        if form.validate_on_submit():
            identity_url = None
            for provider in self.appbuilder.sm.openid_providers:
                if provider.get("url") == form.openid.data:
                    identity_url = form.openid.data
            if identity_url is None:
                flash(self.invalid_login_message, "warning")
                return redirect(self.appbuilder.get_url_for_login)
        return super().login(flag=flag)

class FixedSecurityManager(SecurityManager):
    authoidview = FixedOIDView


FAB_SECURITY_MANAGER_CLASS = "config.FixedSecurityManager"
```
