# Code injection in Stripe CLI on windows

**GHSA**: GHSA-4cx6-fj7j-pjx9 | **CVE**: CVE-2022-24753 | **Severity**: high (CVSS 7.8)

**CWE**: CWE-78

**Affected Packages**:
- **github.com/stripe/stripe-cli** (go): < 1.7.13

## Description

### Impact
A vulnerability in Stripe CLI exists on Windows when certain commands are run in a directory where an attacker has planted files. The commands are `stripe login`, `stripe config -e`, `stripe community`, and `stripe open`. MacOS and Linux are unaffected.

An attacker who successfully exploits the vulnerability can run arbitrary code in the context of the current user. The update addresses the vulnerability by throwing an error in these situations before the code can run.

There has been no evidence of exploitation of this vulnerability.

### Recommendation
Upgrade to Stripe CLI v1.7.13.

### Acknowledgments
Thanks to [trungpabc](https://hackerone.com/trungpabc) for reporting the issue.

### For more information
Email us at [security@stripe.com](mailto:security@stripe.com).

