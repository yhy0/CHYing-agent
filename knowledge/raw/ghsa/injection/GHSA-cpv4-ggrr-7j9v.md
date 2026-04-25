# Rasa Allows Remote Code Execution via Remote Model Loading

**GHSA**: GHSA-cpv4-ggrr-7j9v | **CVE**: CVE-2024-49375 | **Severity**: critical (CVSS 9.1)

**CWE**: CWE-94, CWE-502

**Affected Packages**:
- **rasa-pro** (pip): >= 3.10.0, < 3.10.12
- **rasa-pro** (pip): >= 3.9.0, < 3.9.16
- **rasa-pro** (pip): < 3.8.18
- **rasa** (pip): < 3.6.21

## Description

## Vulnerability
A vulnerability has been identified in Rasa Pro and Rasa Open Source that enables an attacker who has the ability to load a maliciously crafted model remotely into a Rasa instance to achieve Remote Code Execution.

The prerequisites for this are:
- The HTTP API must be enabled on the Rasa instance eg with `--enable-api`. This is not the default configuration.
- For unauthenticated RCE to be exploitable, the user must not have configured any authentication or other security controls recommended in our documentation.
- For authenticated RCE, the attacker must posses a valid authentication token or JWT to interact with the Rasa API.

## Fix
We encourage you to upgrade to a version of Rasa that includes a fix. These are:

- Rasa Pro 3.8.18, 3.9.16, 3.10.12
- Rasa Open Source 3.6.21

Once you have upgraded your Rasa Pro or Open Source installation, you will need to retrain your model using the fixed version of Rasa Pro or Open Source. If you have a custom component that inherits from one of the components listed below and modified the persist or load method, make sure to update your code. Please contact us in case you encounter any problems.

Affected components:

- `CountVectorFeaturizer`
- `LexicalSyntacticFeaturizer`
- `LogisticRegressionClassifier`
- `SklearnIntentClassifier`
- `DIETClassifier`
- `CRFEntityExtractor`
- `TrackerFeaturizer`
- `TEDPolicy`
- `UnexpectedIntentTEDPolicy`

If you are unable to upgrade immediately, please follow our mitigation advice below.

## Mitigation Advice

- The unauthenticated RCE can be mitigated by ensuring that you enable authentication for the Rasa HTTP API if this is enabled. This means that in addition to passing `--enable-api` to Rasa, you should also pass an authentication configuration as described in our documentation [here](https://rasa.com/docs/rasa-pro/production/rest-api/#enabling-the-rest-api). 

- The authenticated RCE can be mitigated by:
    - Ensuring that you only load models from trusted sources such as your own CI pipelines. You can check file hashes for model archives to confirm that a model has not been tampered with between training and use.
    - Confirming that you have sufficient access controls and utilize the principle of least privilege to control who in your organization has the ability to interact with the Rasa API even with authentication enabled.

## Future Releases
As an additional security step, a future release of Rasa Pro will remove the ability to enable the API without any authentication method enabled.

## Credit
Rasa would like to thank Julian Scheid from Deutsche Telekom Security GmbH for responsible disclosure of this vulnerability.
