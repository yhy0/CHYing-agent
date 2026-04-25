# Az - Entra ID (AzureAD) - Privilege Escalation and Defense

## Entra ID Privilege Escalation

## Azure Privilege Escalation

## Defensive Mechanisms

### Privileged Identity Management (PIM)

Privileged Identity Management (PIM) in Azure helps to **prevent excessive privileges** to being assigned to users unnecessarily.

One of the main features provided by PIM is that It allows to not assign roles to principals that are constantly active, but make them **eligible for a period of time (e.g. 6months)**. Then, whenever the user wants to activate that role, he needs to ask for it indicating the time he needs the privilege (e.g. 3 hours). Then an **admin needs to approve** the request.\
Note that the user will also be able to ask to **extend** the time.

Moreover, **PIM send emails** whenever a privileged role is being assigned to someone.

<img src="../../../images/image (354).png" alt=""><figcaption></figcaption>

When PIM is enabled it's possible to configure each role with certain requirements like:

- Maximum duration (hours) of activation
- Require MFA on activation
- Require Conditional Access acuthenticaiton context
- Require justification on activation
- Require ticket information on activation
- Require approval to activate
- Max time to expire the elegible assignments
- A lot more configuration on when and who to send notifications when certain actions happen with that role

### Conditional Access Policies

Check:

### Entra Identity Protection

Entra Identity Protection is a security service that allows to **detect when a user or a sign-in is too risky** to be accepted, allowing to **block** the user or the sig-in attempt.

It allows the admin to configure it to **block** attempts when the risk is "Low and above", "Medium and above" or "High". Although, by default it's completely **disabled**:

<img src="../../../images/image (356).png" alt=""><figcaption></figcaption>

> [!TIP]
> Nowadays it's recommended to add these restrictions via Conditional Access policies where it's possible to configure the same options.

### Entra Password Protection

Entra Password Protection ([https://portal.azure.com/index.html#view/Microsoft_AAD_ConditionalAccess/PasswordProtectionBlade](https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/PasswordProtectionBlade)) is a security feature that **helps prevent the abuse of weak passwords in by locking out accounts when several unsuccessful login attempts happen**.\
It also allows to **ban a custom password list** that you need to provide.

It can be **applied both** at the cloud level and on-premises Active Directory.

The default mode is **Audit**:

<img src="../../../images/image (355).png" alt=""><figcaption></figcaption>

## References

- [https://learn.microsoft.com/en-us/azure/active-directory/roles/administrative-units](https://learn.microsoft.com/en-us/azure/active-directory/roles/administrative-units)
- [SharePointDumper](https://github.com/zh54321/SharePointDumper)
- [EntraTokenAid](https://github.com/zh54321/EntraTokenAid)
