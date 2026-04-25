# GCP - Secret Manager Persistence

## Secret Manager

Find more information about Secret Manager in:

### Rotation misuse

An attacker could update the secret to:

- **Stop rotations** so the secret won't be modified
- **Make rotations much less often** so the secret won't be modified
- **Publish the rotation message to a different pub/sub**
- **Modify the rotation code being executed.** This happens in a different service, probably in a Cloud Function, so the attacker will need privileged access over the Cloud Function or any other service.
