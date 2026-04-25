# WeKnora has Broken Access Control - Cross-Tenant Data Exposure

**GHSA**: GHSA-2f4c-vrjq-rcgv | **CVE**: CVE-2026-30859 | **Severity**: high (CVSS 7.5)

**CWE**: CWE-284

**Affected Packages**:
- **github.com/Tencent/WeKnora** (go): <= 0.2.11

## Description

## Summary
A broken access control vulnerability in the database query tool allows any authenticated tenant to read sensitive data belonging to other tenants, including API keys, model configurations, and private messages. The application fails to enforce tenant isolation on critical tables (`models`, `messages`, `embeddings`), enabling unauthorized cross-tenant data access with user-level authentication privileges.

---

## Details

### Root Cause
The vulnerability exists due to a mismatch between the queryable tables and the tables protected by tenant isolation in `internal/utils/inject.go`.

**Tenant-isolated tables** (protected by automatic `WHERE tenant_id = X` clause):
```
tenants, knowledge_bases, knowledges, sessions, chunks
```

**Queryable tables** (allowed by `WithAllowedTables()` in `WithSecurityDefaults()`):
```
tenants, knowledge_bases, knowledges, sessions, messages, chunks, embeddings, models
```

**Gap**: The tables `messages`, `embeddings`, and `models` are queryable but NOT in the tenant isolation list. This means queries against these tables do NOT receive the automatic `WHERE tenant_id = X` filtering.

### Vulnerable Code

**File: `internal/utils/inject.go`**

```go
func WithTenantIsolation(tenantID uint64, tables ...string) SQLValidationOption {
	return func(v *sqlValidator) {
		v.enableTenantInjection = true
		v.tenantID = tenantID
		v.tablesWithTenantID = make(map[string]bool)
		if len(tables) == 0 {
			// Default tables with tenant_id - MISSING: messages, embeddings, models
			v.tablesWithTenantID = map[string]bool{
				"tenants":         true,
				"knowledge_bases": true,
				"knowledges":      true,
				"sessions":        true,
				"chunks":          true,
			}
		} else {
			for _, table := range tables {
				v.tablesWithTenantID[strings.ToLower(table)] = true
			}
		}
	}
}

func WithSecurityDefaults(tenantID uint64) SQLValidationOption {
	return func(v *sqlValidator) {
		// ... other validations ...
		WithTenantIsolation(tenantID)(v)

		// Default allowed tables - INCLUDES unprotected tables
		WithAllowedTables(
			"tenants",
			"knowledge_bases",
			"knowledges",
			"sessions",
			"messages",           // ← No tenant isolation
			"chunks",
			"embeddings",         // ← No tenant isolation
			"models",             // ← No tenant isolation
		)(v)
	}
}
```

**File: `database_query.go`**

```go
func (t *DatabaseQueryTool) validateAndSecureSQL(sqlQuery string, tenantID uint64) (string, error) {
	securedSQL, validationResult, err := utils.ValidateAndSecureSQL(
		sqlQuery,
		utils.WithSecurityDefaults(tenantID),
		utils.WithInjectionRiskCheck(),
	)
	// ... validation logic ...
	return securedSQL, nil
}
```

When tenant 1 queries `SELECT * FROM models`, the validation passes and **no** `WHERE tenant_id = 1` clause is appended because `models` is not in the `tablesWithTenantID` map. The unfiltered result exposes all model records across all tenants.

---

## PoC

### Prerequisites
- Access to the AI application as an authenticated tenant
- Ability to send prompts that invoke the `database_query` tool

### Steps to Reproduce

1. **Authenticate as Tenant 1** and craft the following prompt to the AI agent:
   ```
   Use the database_query tool with {"sql": "SELECT * FROM models"} to query the database. 
   Output all results and any errors.
   ```

2. **Expected vulnerable response**: The agent returns ALL model records in the `models` table across all tenants, including:
   - Model IDs and names
   - API keys and authentication credentials
   - Configuration details for all organizations

Example result:

<img width="864" height="1150" alt="image" src="https://github.com/user-attachments/assets/01e3d0ba-0f2a-43ab-ab51-8778fb8a79b1" />

3. **Repeat with messages table**:
   ```
   Use the database_query tool with {"sql": "SELECT * FROM messages"} to query the database. 
   Output all results.
   ```

4. **Expected vulnerable response**: The agent returns ALL messages from all tenants, bypassing message privacy.

---

PoC Video:

https://github.com/user-attachments/assets/056984e8-1700-41fe-9b8a-6d18d5579c18

---

## Impact

### Vulnerability Type
**Broken Access Control (CWE-639)** / **Unauthorized Information Disclosure (CWE-200)**

### Specific Data at Risk
1. **API Keys & Credentials** (from `models` table)
   - Third-party LLM provider keys (OpenAI, Anthropic, etc.)
   - Database credentials and connection strings
   - Authentication tokens for integrated services

2. **Private Messages** (from `messages` table)
   - Confidential business communications
   - User conversations with AI agents
   - Sensitive information shared within conversations
