# fief-server Server-Side Template Injection vulnerability

**GHSA**: GHSA-hj8m-9fhf-v7jp | **CVE**: N/A | **Severity**: critical (CVSS 10.0)

**CWE**: N/A

**Affected Packages**:
- **fief-server** (pip): >= 0.19.0, < 0.25.3

## Description

# Server-Side Template Injection

## Overview of the Vulnerability

Server-Side Template Injection (SSTI) is a vulnerability within application templating engines where user input is improperly handled and is embedded into the template, possibly leading code being executed.

An attacker can use SSTI to execute code on the underlying system by manipulating values within the embedded template. When code is executed within the underlying system, it can allow an attacker to run permissioned commands under the exploited process, or exploit Cross-Site Scripting (XSS) to run code within the user's browser.

## Business Impact

SSTI can lead to reputational damage for the business due to a loss in confidence and trust by users. If an attacker successfully executes code within the underlying system, it can result in data theft and indirect financial losses.

## Steps to Reproduce

1. [Sign up](https://fief.fief.dev/register) and login to your account
1. Use a browser to navigate to: email-templates {{[URL](https://test.fief.dev/admin/customization/email-templates/)}}
1. put your payload in Edit Base template `{{ cycler.__init__.__globals__.os.popen('id').read() }}` and you will se it will execute.

Payload:
`{{ cycler.__init__.__globals__.os.popen('id').read() }}`

## Proof of Concept (PoC)

The screenshot(s) below demonstrates the SSTI:

![SSTI](https://user-images.githubusercontent.com/42150485/248214990-854c2272-4f34-4c49-9759-d49ce8ce3d12.png)

