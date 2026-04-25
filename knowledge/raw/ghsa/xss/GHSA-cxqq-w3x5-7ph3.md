# MobSF Stored Cross-Site Scripting (XSS)

**GHSA**: GHSA-cxqq-w3x5-7ph3 | **CVE**: CVE-2025-24803 | **Severity**: high (CVSS 8.1)

**CWE**: CWE-79

**Affected Packages**:
- **mobsf** (pip): <= 4.3.0

## Description

**Product:** MobSF
**Version:** < 4.3.1
**CWE-ID:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
**CVSS vector v.4.0:** 8.5 (AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N)
**CVSS vector v.3.1:** 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)
**Description:** Stored XSS in the iOS Dynamic Analyzer functionality.
**Impact:** Leveraging this vulnerability would enable performing actions as users, including administrative users.
**Vulnerable component:** `dynamic_analysis.html` 
https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/d1d3b7a9aeb1a8c8c7c229a3455b19ade9fa8fe0/mobsf/templates/dynamic_analysis/ios/dynamic_analysis.html#L406
**Exploitation conditions:** A malicious application was uploaded to the Correlium.
**Mitigation:** Use `escapeHtml()` function on the `bundle` variable.
**Researcher: Oleg Surnin (Positive Technologies)**

## Research
Researcher discovered zero-day vulnerability Stored Cross-site Scripting (XSS) in MobSF in iOS Dynamic Analyzer functionality.
According to Apple's documentation for bundle ID's, it must contain only alphanumeric characters (A–Z, a–z, and 0–9), hyphens (-), and periods (.).
(https://developer.apple.com/documentation/bundleresources/information-property-list/cfbundleidentifier)
However, an attacker can manually modify this value in `Info.plist` file and add special characters to the `<key>CFBundleIdentifier</key>` value.
In the `dynamic_analysis.html` file you do not sanitize received bundle value from Corellium 
https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/d1d3b7a9aeb1a8c8c7c229a3455b19ade9fa8fe0/mobsf/templates/dynamic_analysis/ios/dynamic_analysis.html#L406

<img width="1581" alt="image" src="https://github.com/user-attachments/assets/8400f872-46c0-406c-9dd6-97655e499b75" />

*Figure 1. Unsanitized bundle*

As a result, it is possible to break the HTML context and achieve Stored XSS.

## Vulnerability reproduction

To reproduce the vulnerability, follow the steps described below.

•	Unzip the IPA file of any iOS application.
*Listing 1. Unzipping the file*
```
unzip test.ipa
```
•	Modify the value of `<key>CFBundleIdentifier</key>` by adding restricted characters in the `Info.plist` file.

<img width="560" alt="image-1" src="https://github.com/user-attachments/assets/3eedf216-45ab-4d73-9815-6b02827d36d4" />

*Figure 2. Example of the modified Bundle Identifier*

•	Zip the modified IPA file.

*Listing 2. Zipping the file*
```
zip -r xss.ipa Payload/
```
•	Upload the modified IPA file to your virtual device using the Correlium platform.
 
<img width="762" alt="image-2" src="https://github.com/user-attachments/assets/7f3e8b0d-d1f9-4d86-b63b-9b3f9e8f1d0c" />

*Figure 3. Example of the uploaded malicious application*

•	Open the XSS functionality and hover the mouse over the Uninstall button of the malicious app.

<img width="764" alt="image-3" src="https://github.com/user-attachments/assets/fd621574-f2c1-42be-b30a-e8e7445c6b13" />

*Figure 4. Example of the 'Uninstall' button*

 <img width="652" alt="image-4" src="https://github.com/user-attachments/assets/73526f71-6d39-4a94-98bf-8a867aa9acc7" />
 
*Figure 5. Example of the XSS*
 
<img width="460" alt="image-5" src="https://github.com/user-attachments/assets/13e6a1fc-59be-492d-8e42-a5a8010fc4c3" />

*Figure 6. Example of the vulnerable code*

___________________________

### Please, assign all credits to: Oleg Surnin (Positive Technologies)
