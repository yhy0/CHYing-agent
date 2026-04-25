# Hyperledger Aries Cloud Agent Python result of presentation verification not checked for LDP-VC

**GHSA**: GHSA-97x9-59rv-q5pm | **CVE**: CVE-2024-21669 | **Severity**: critical (CVSS 9.9)

**CWE**: CWE-347

**Affected Packages**:
- **aries-cloudagent** (pip): >= 0.7.0, < 0.10.5
- **aries-cloudagent** (pip): >= 0.11.0rc1, < 0.11.0

## Description

### Impact

When verifying W3C Format Verifiable Credentials using JSON-LD with Linked Data Proofs (LDP-VCs), the result of verifying the presentation `document.proof` was not factored into the final `verified` value (`true`/`false`) on the presentation record. Below is an example result from verifying a JSON-LD Presentation where there is an error noted in the processing (mismatched challenge), but the overall result is incorrectly `"verified": true`:

```json
{
  "verified": true,
  "presentation_result": {
    "verified": false,
    "document": {
      "@context": [
        "https://www.w3.org/2018/credentials/v1"
      ],
      "type": [
        "VerifiablePresentation"
      ],
      "verifiableCredential": [
        {
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://w3id.org/citizenship/v1"
          ],
          "type": [
            "VerifiableCredential",
            "PermanentResident"
          ],
          "issuer": "did:sov:EzcfrVw7Tveho5NjrmDWnd",
          "issuanceDate": "2023-11-18",
          "credentialSubject": {
            "type": [
              "PermanentResident"
            ],
            "id": "did:key:z6MkrpbudRMUpTWSdqFcG2ytbYu2QQfgGFUf8GJpShR8Gy7C",
            "givenName": "Bob",
            "familyName": "Builder",
            "gender": "Male",
            "birthCountry": "Bahamas",
            "birthDate": "1958-07-17"
          },
          "proof": {
            "type": "Ed25519Signature2018",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:sov:EzcfrVw7Tveho5NjrmDWnd#key-1",
            "created": "2023-11-18T21:39:56.988853+00:00",
            "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..eKdLMhKJkiVNzTKOEv14KyAFJnk8QX5MqXPmRE5OjQvwRNkeXk1lQRovhDhXKw154OrSqLHgfSNwBd3xfwuDCA"
          }
        }
      ],
      "proof": {
        "type": "Ed25519Signature2018",
        "proofPurpose": "authentication",
        "verificationMethod": "did:key:z6MkrpbudRMUpTWSdqFcG2ytbYu2QQfgGFUf8GJpShR8Gy7C#z6MkrpbudRMUpTWSdqFcG2ytbYu2QQfgGFUf8GJpShR8Gy7C",
        "created": "2023-11-18T21:39:59.188276+00:00",
        "challenge": "ce0956d4-206d-4b69-a087-52bbb9ddaf1d",
        "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..4ciLzT3oF-Ch9nngGVgI_fBNIo_RPPXzRuFXjMx4AdwVNM4ioeB3TNDbHsF7fPXANznkZR0bHceyvMN3-CUSAw"
      }
    },
    "results": [
      {
        "verified": false,
        "proof": {
          "@context": [
            "https://www.w3.org/2018/credentials/v1"
          ],
          "type": "Ed25519Signature2018",
          "proofPurpose": "authentication",
          "verificationMethod": "did:key:z6MkrpbudRMUpTWSdqFcG2ytbYu2QQfgGFUf8GJpShR8Gy7C#z6MkrpbudRMUpTWSdqFcG2ytbYu2QQfgGFUf8GJpShR8Gy7C",
          "created": "2023-11-18T21:39:59.188276+00:00",
          "challenge": "ce0956d4-206d-4b69-a087-52bbb9ddaf1d",
          "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..4ciLzT3oF-Ch9nngGVgI_fBNIo_RPPXzRuFXjMx4AdwVNM4ioeB3TNDbHsF7fPXANznkZR0bHceyvMN3-CUSAw"
        },
        "error": "The challenge is not as expected; challenge=ce0956d4-206d-4b69-a087-52bbb9ddaf1d, expected=328daf6e-f1f5-475a-944e-6446e7b3a969",
        "purpose_result": {
          "valid": false,
          "error": "The challenge is not as expected; challenge=ce0956d4-206d-4b69-a087-52bbb9ddaf1d, expected=328daf6e-f1f5-475a-944e-6446e7b3a969"
        }
      }
    ],
    "errors": [
      "The challenge is not as expected; challenge=ce0956d4-206d-4b69-a087-52bbb9ddaf1d, expected=328daf6e-f1f5-475a-944e-6446e7b3a969"
    ]
  },
  "credential_results": [
    {
      "verified": true,
      "document": {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://w3id.org/citizenship/v1"
        ],
        "type": [
          "VerifiableCredential",
          "PermanentResident"
        ],
        "issuer": "did:sov:EzcfrVw7Tveho5NjrmDWnd",
        "issuanceDate": "2023-11-18",
        "credentialSubject": {
          "type": [
            "PermanentResident"
          ],
          "id": "did:key:z6MkrpbudRMUpTWSdqFcG2ytbYu2QQfgGFUf8GJpShR8Gy7C",
          "givenName": "Bob",
          "familyName": "Builder",
          "gender": "Male",
          "birthCountry": "Bahamas",
          "birthDate": "1958-07-17"
        },
        "proof": {
          "type": "Ed25519Signature2018",
          "proofPurpose": "assertionMethod",
          "verificationMethod": "did:sov:EzcfrVw7Tveho5NjrmDWnd#key-1",
          "created": "2023-11-18T21:39:56.988853+00:00",
          "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..eKdLMhKJkiVNzTKOEv14KyAFJnk8QX5MqXPmRE5OjQvwRNkeXk1lQRovhDhXKw154OrSqLHgfSNwBd3xfwuDCA"
        }
      },
      "results": [
        {
          "verified": true,
          "proof": {
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://w3id.org/citizenship/v1"
            ],
            "type": "Ed25519Signature2018",
            "proofPurpose": "assertionMethod",
            "verificationMethod": "did:sov:EzcfrVw7Tveho5NjrmDWnd#key-1",
            "created": "2023-11-18T21:39:56.988853+00:00",
            "jws": "eyJhbGciOiAiRWREU0EiLCAiYjY0IjogZmFsc2UsICJjcml0IjogWyJiNjQiXX0..eKdLMhKJkiVNzTKOEv14KyAFJnk8QX5MqXPmRE5OjQvwRNkeXk1lQRovhDhXKw154OrSqLHgfSNwBd3xfwuDCA"
          },
          "purpose_result": {
            "valid": true,
            "controller": {
              "@context": "https://w3id.org/security/v2",
              "id": "did:sov:EzcfrVw7Tveho5NjrmDWnd",
              "assertionMethod": [
                "did:sov:EzcfrVw7Tveho5NjrmDWnd#key-1"
              ],
              "authentication": [
                {
                  "id": "did:sov:EzcfrVw7Tveho5NjrmDWnd#key-1",
                  "type": "Ed25519VerificationKey2018",
                  "controller": "did:sov:EzcfrVw7Tveho5NjrmDWnd",
                  "publicKeyBase58": "8dMkWKZxsK7vS8sR4XgS7gWvRawPp5TMYVFvnU2RyXqo"
                }
              ],
              "verificationMethod": "did:sov:EzcfrVw7Tveho5NjrmDWnd#key-1",
              "https://www.w3.org/ns/did#service": {
                "id": "did:sov:EzcfrVw7Tveho5NjrmDWnd#did-communication",
                "type": "did-communication",
                "https://www.w3.org/ns/did#serviceEndpoint": {
                  "id": "http://alice:3000"
                }
              }
            }
          }
        }
      ]
    }
  ],
  "errors": [
    "The challenge is not as expected; challenge=ce0956d4-206d-4b69-a087-52bbb9ddaf1d, expected=328daf6e-f1f5-475a-944e-6446e7b3a969"
  ]
}
```

The flaw enables holders of W3C Format Verifiable Credentials using JSON-LD with Linked Data Proofs (LDPs) to present incorrectly constructed proofs, and allows malicious verifiers to save and replay a presentation from such holders as their own.

This vulnerability has been present since the first implementation of support for JSON-LD W3C Verifiable Credential Data Model presentations, in Aries Cloud Agent Python release in 0.7.0.

All ACA-Py Users depending on W3C Format Verifiable Credentials using JSON-LD with Linked Data Proofs are impacted by this vulnerability.

### Patches

This issue has been patched in version [0.10.5](https://github.com/hyperledger/aries-cloudagent-python/releases/tag/0.10.5) and fixed in [0.11.0](https://github.com/hyperledger/aries-cloudagent-python/releases/tag/0.11.0).

### Workarounds

There is no workaround other upgrading to a patched/fixed version of ACA-Py.
