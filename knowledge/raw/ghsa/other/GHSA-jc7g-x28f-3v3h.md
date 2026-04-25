# listmonk's Sprig template Injection vulnerability leads to reading of Environment Variable for low privilege user

**GHSA**: GHSA-jc7g-x28f-3v3h | **CVE**: CVE-2025-49136 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-1336

**Affected Packages**:
- **github.com/knadh/listmonk** (go): >= 4.0.0, < 5.0.2

## Description

### Summary
The `env` and `expandenv` template functions which is enabled by default in [Sprig](https://masterminds.github.io/sprig/) enables capturing of env variables on the host. While this may not be a problem on single-user (super admin) installations, on multi-user installations, this allows non-super-admin users with campaign or template permissions to use the `{{ env }}` template expression to capture sensitive environment variables.

**Upgrade to [v5.0.2](https://github.com/knadh/listmonk/releases/tag/v5.0.2)** to mitigate.

---------

# Demonstration

### Description
A critical template injection vulnerability exists in Listmonk's campaign preview functionality that allows authenticated users with minimal privileges (campaigns:get & campaigns:get_all) to extract sensitive system data, including database credentials, SMTP passwords, and admin credentials due to some dangerous function being allowed.

### Proof of Concept

- Create a user and give him `campaigns:get` and `campaigns:get_all` privileges

![image](https://github.com/user-attachments/assets/05333695-14d9-498e-9f73-2137d6eca55b)

- Now login with that user, go to any campaign, go the Content section and here lies the vulnerability, we're able to execute template content which allows us to get environment variables, execute Sprig functions...

- Now in the text field you can input the following and press Preview:
```
{{ env "AWS_KEY" }}
{{ env "LISTMONK_db__user" }}
{{ env "LISTMONK_db__password" }}
````

![image](https://github.com/user-attachments/assets/ac963f54-5982-47d4-99d0-59030917f548)

# Preview:

![image](https://github.com/user-attachments/assets/99558ca4-81c6-4e1a-bd0d-6bc57830f4d0)

I had the AWS_KEY variable set like that to confirm the vulnerability:

![image](https://github.com/user-attachments/assets/16382998-2402-436a-9bb0-db09fb13dd79)

### Impact

- Through these environment variables the attacker can access, they can fully compromise the database, cloud accounts, admin credentials, and more depending on what was setup leading to total system takeover and data breach.

### Suggested Fix

- Blacklist some function for templates like env, expandEnv and fail as they can be used to leak environment variables which leads to a full takeover.
